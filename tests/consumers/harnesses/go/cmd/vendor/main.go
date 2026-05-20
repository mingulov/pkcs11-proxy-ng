// R5 vendor-extension end-to-end harness.
//
// Uses the vendor mechanism CKM_CLOUDHSM_AES_GCM (0x80001087) which
// is aliased to CKM_AES_GCM in the patched SoftHSM2 backend. The
// daemon advertises the mechanism through its mechanism registry
// (mapped to shape "gcm" — same params as standard AES-GCM). The
// shim accepts the mechanism + GCM params and forwards to the
// daemon. The daemon's backend (patched SoftHSM2) accepts 0x80001087
// in C_EncryptInit / C_DecryptInit and performs the GCM op.
//
// Round-trip check: encrypt + decrypt under the vendor mechanism
// produces the same plaintext.

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
)

const CKM_CLOUDHSM_AES_GCM uint = 0x80001087

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func die(msg string, err error) {
	fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
	os.Exit(1)
}

func main() {
	module := env("PKCS11_MODULE_PATH", "/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so")
	token := env("TOKEN_LABEL", "r5-token")
	pin := env("USER_PIN", "1234")

	p := pkcs11.New(module)
	if p == nil {
		fmt.Fprintln(os.Stderr, "FAIL: pkcs11.New nil")
		os.Exit(1)
	}
	if err := p.Initialize(); err != nil {
		die("Initialize", err)
	}
	defer func() { _ = p.Finalize(); p.Destroy() }()

	slots, err := p.GetSlotList(true)
	if err != nil {
		die("GetSlotList", err)
	}
	var slot uint
	found := false
	for _, s := range slots {
		info, err := p.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if info.Label == token {
			slot, found = s, true
			break
		}
	}
	if !found {
		die("findSlot", fmt.Errorf("no token labelled %q", token))
	}

	sess, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		die("OpenSession", err)
	}
	defer p.CloseSession(sess)

	if err := p.Login(sess, pkcs11.CKU_USER, pin); err != nil {
		if pe, ok := err.(pkcs11.Error); !ok || pe != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			die("Login", err)
		}
	}
	defer p.Logout(sess)

	keyLabel := "r5-vendor-aes"
	aesTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	aes, err := p.GenerateKey(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		aesTmpl)
	if err != nil {
		die("GenerateKey", err)
	}
	defer p.DestroyObject(sess, aes)

	// Same GCM params shape as standard CKM_AES_GCM. The shim
	// recognises 0x80001087 → shape "gcm" via the daemon-advertised
	// mechanism registry, and forwards iv+aad+tagBits as
	// CK_GCM_PARAMS to the backend.
	iv := mustHex("0102030405060708090a0b0c")
	aad := []byte("vendor-extension-aad")
	gcmParams := pkcs11.NewGCMParams(iv, aad, 128)
	defer gcmParams.Free()

	plaintext := []byte("vendor-mech-test-data-vendor-1!")

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(CKM_CLOUDHSM_AES_GCM, gcmParams),
	}
	if err := p.EncryptInit(sess, mech, aes); err != nil {
		die("EncryptInit(CKM_CLOUDHSM_AES_GCM)", err)
	}
	ct, err := p.Encrypt(sess, plaintext)
	if err != nil {
		die("Encrypt(CKM_CLOUDHSM_AES_GCM)", err)
	}
	fmt.Printf("  encrypted %d -> %d bytes via CKM_CLOUDHSM_AES_GCM\n",
		len(plaintext), len(ct))

	// Decrypt with the same vendor mechanism. miekg/pkcs11 GCM
	// params must be re-created per init call (the params struct
	// holds C-side state).
	gcmParams2 := pkcs11.NewGCMParams(iv, aad, 128)
	defer gcmParams2.Free()
	if err := p.DecryptInit(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_CLOUDHSM_AES_GCM, gcmParams2)},
		aes); err != nil {
		die("DecryptInit(CKM_CLOUDHSM_AES_GCM)", err)
	}
	pt, err := p.Decrypt(sess, ct)
	if err != nil {
		die("Decrypt(CKM_CLOUDHSM_AES_GCM)", err)
	}
	if string(pt) != string(plaintext) {
		fmt.Fprintf(os.Stderr, "FAIL: roundtrip mismatch: got %q want %q\n", pt, plaintext)
		os.Exit(1)
	}

	fmt.Println("PASS: vendor-mech AES-GCM round-trip ok")
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
