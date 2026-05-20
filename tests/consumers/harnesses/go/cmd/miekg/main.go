// R5 Go consumer harness — miekg/pkcs11 (direct PKCS#11 binding).
//
// Exercises:
//   1. C_Initialize / C_Finalize
//   2. C_GetSlotList → find first slot with token labelled $TOKEN_LABEL
//   3. C_OpenSession + C_Login (USER_PIN)
//   4. C_GenerateKeyPair (RSA-2048)
//   5. C_SignInit + C_Sign (SHA256-RSA-PKCS) — exact-output semantics
//   6. C_VerifyInit + C_Verify
//   7. C_GenerateKey (AES-256) → C_EncryptInit / C_Encrypt (AES-ECB)
//      → C_DecryptInit / C_Decrypt — round-trip
//   8. Cleanup (delete generated objects), C_Logout, C_CloseSession
//
// Reports PASS/FAIL on stdout. Non-zero exit on failure.

package main

import (
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	modulePath = env("PKCS11_MODULE_PATH", "/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so")
	tokenLabel = env("TOKEN_LABEL", "r5-token")
	userPIN    = env("USER_PIN", "1234")
	keyLabel   = env("KEY_LABEL", "r5-key-miekg")
)

func die(msg string, err error) {
	fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
	os.Exit(1)
}

func findSlot(p *pkcs11.Ctx, label string) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("GetSlotList: %w", err)
	}
	for _, s := range slots {
		info, err := p.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if info.Label == label || trimNullsAndSpaces(info.Label) == label {
			return s, nil
		}
	}
	return 0, fmt.Errorf("no slot with token label %q (saw %d slots)", label, len(slots))
}

func trimNullsAndSpaces(s string) string {
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if c != 0x00 && c != ' ' {
			break
		}
		end--
	}
	return s[:end]
}

func main() {
	p := pkcs11.New(modulePath)
	if p == nil {
		fmt.Fprintln(os.Stderr, "FAIL: pkcs11.New returned nil")
		os.Exit(1)
	}
	if err := p.Initialize(); err != nil {
		die("Initialize", err)
	}
	defer func() { _ = p.Finalize(); p.Destroy() }()

	slot, err := findSlot(p, tokenLabel)
	if err != nil {
		die("findSlot", err)
	}
	fmt.Printf("  slot for %q: %d\n", tokenLabel, slot)

	sess, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		die("OpenSession", err)
	}
	defer p.CloseSession(sess)

	if err := p.Login(sess, pkcs11.CKU_USER, userPIN); err != nil {
		// NSS softokn persists login at the token level across
		// processes; if a previous process already logged in, the
		// fresh session inherits that state and Login fails with
		// CKR_USER_ALREADY_LOGGED_IN. Treat that as success.
		if pe, ok := err.(pkcs11.Error); !ok || pe != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			die("Login", err)
		}
		fmt.Println("  Login: already logged in (NSS quirk), continuing")
	}
	defer p.Logout(sess)

	// RSA keygen.
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{0x10}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{0x10}),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	}
	pub, priv, err := p.GenerateKeyPair(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubTmpl, privTmpl)
	if err != nil {
		die("GenerateKeyPair (RSA-2048)", err)
	}
	fmt.Printf("  RSA keypair: pub=%d priv=%d\n", pub, priv)
	defer p.DestroyObject(sess, pub)
	defer p.DestroyObject(sess, priv)

	// Sign / verify.
	data := []byte("miekg-pkcs11-test-data")
	if err := p.SignInit(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)},
		priv); err != nil {
		die("SignInit", err)
	}
	sig, err := p.Sign(sess, data)
	if err != nil {
		die("Sign", err)
	}
	fmt.Printf("  signed %d bytes -> sig=%d bytes\n", len(data), len(sig))

	if err := p.VerifyInit(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)},
		pub); err != nil {
		die("VerifyInit", err)
	}
	if err := p.Verify(sess, data, sig); err != nil {
		die("Verify", err)
	}

	// AES keygen + encrypt/decrypt round-trip.
	aesTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"-aes"),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	aes, err := p.GenerateKey(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		aesTmpl)
	if err != nil {
		die("GenerateKey (AES-256)", err)
	}
	defer p.DestroyObject(sess, aes)
	fmt.Printf("  AES key: %d\n", aes)

	plaintext := []byte("0123456789ABCDEF") // exact AES block size
	if err := p.EncryptInit(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)},
		aes); err != nil {
		die("EncryptInit (AES-ECB)", err)
	}
	ct, err := p.Encrypt(sess, plaintext)
	if err != nil {
		die("Encrypt (AES-ECB)", err)
	}

	if err := p.DecryptInit(sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)},
		aes); err != nil {
		die("DecryptInit", err)
	}
	pt, err := p.Decrypt(sess, ct)
	if err != nil {
		die("Decrypt", err)
	}
	if string(pt) != string(plaintext) {
		fmt.Fprintf(os.Stderr, "FAIL: roundtrip mismatch: got %q\n", pt)
		os.Exit(1)
	}

	fmt.Println("PASS: miekg/pkcs11 round-trip ok")
}
