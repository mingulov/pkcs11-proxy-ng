// R5 Go consumer harness — ThalesGroup/crypto11 (high-level wrapper).
//
// Exercises crypto11's `Context` + `KeyPair` flow:
//   1. Configure({Path, TokenLabel, Pin})
//   2. GenerateRSAKeyPairWithLabel("r5-key-crypto11", 2048)
//   3. crypto.Signer interface — sha256+sign + verify with crypto/rsa
//   4. Close()

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/ThalesGroup/crypto11"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := &crypto11.Config{
		Path:       env("PKCS11_MODULE_PATH", "/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so"),
		TokenLabel: env("TOKEN_LABEL", "r5-token"),
		Pin:        env("USER_PIN", "1234"),
	}
	ctx, err := crypto11.Configure(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Configure: %v\n", err)
		os.Exit(1)
	}
	defer ctx.Close()

	label := []byte(env("KEY_LABEL", "r5-key-crypto11"))
	id := []byte{0x20}

	// Best-effort cleanup of any prior run.
	if prev, _ := ctx.FindKeyPair(id, label); prev != nil {
		_ = prev.Delete()
	}

	kp, err := ctx.GenerateRSAKeyPairWithLabel(id, label, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: GenerateRSAKeyPairWithLabel: %v\n", err)
		os.Exit(1)
	}
	defer kp.Delete()
	fmt.Println("  crypto11 RSA keypair generated")

	signer, ok := kp.(crypto.Signer)
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL: KeyPair does not implement crypto.Signer")
		os.Exit(1)
	}

	msg := []byte("crypto11-test-data")
	digest := sha256.Sum256(msg)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Signer.Sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  signed digest -> sig=%d bytes\n", len(sig))

	pub := signer.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: verify PKCS1v15: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("PASS: crypto11 round-trip ok")
}
