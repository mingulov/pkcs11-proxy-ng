// Java consumer harness — OpenJDK SunPKCS11 provider.
//
// Loads the shim as a PKCS#11 module via a config file at
// /tmp/pkcs11.cfg, opens a KeyStore for the token, generates an
// RSA keypair, signs + verifies SHA256withRSA.
//
// Usage:
//   java -cp /usr/local/lib/harness.jar Harness <module> <tokenLabel> <pin>

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class Harness {
    public static void main(String[] args) throws Exception {
        String module = args.length > 0 ? args[0] : "/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so";
        String tokenLabel = args.length > 1 ? args[1] : "matrix-token";
        String pin = args.length > 2 ? args[2] : "1234";

        Path cfg = Path.of("/tmp/pkcs11.cfg");
        String cfgText =
            "name = r5\n" +
            "library = " + module + "\n" +
            "slotListIndex = 0\n";
        Files.writeString(cfg, cfgText);

        Provider prov = Security.getProvider("SunPKCS11");
        if (prov == null) {
            throw new IllegalStateException("SunPKCS11 provider not available");
        }
        prov = prov.configure(cfg.toString());
        Security.addProvider(prov);
        System.out.println("  provider: " + prov.getName());

        KeyStore ks = KeyStore.getInstance("PKCS11", prov);
        ks.load(null, pin.toCharArray());
        System.out.println("  keystore loaded, " + ks.size() + " entries (token: " + tokenLabel + ")");

        // Prefer reusing an existing key labelled "matrix-key" so backends
        // that don't default CKA_SIGN=true on KeyPairGenerator output
        // (e.g. Kryoptic) still pass — the key was provisioned with
        // explicit sign usage by pkcs11-tool / miekg in an earlier
        // cell of the matrix. Falls back to generating a fresh key
        // when no pre-provisioned key exists (first-time SoftHSM2 /
        // NSS / p11kit runs).
        java.security.PrivateKey priv = null;
        java.security.PublicKey pub = null;
        String existing = null;
        for (java.util.Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
            String alias = e.nextElement();
            if (alias.equals("matrix-key") || alias.startsWith("matrix-key")) {
                existing = alias;
                break;
            }
        }
        if (existing != null) {
            priv = (java.security.PrivateKey) ks.getKey(existing, pin.toCharArray());
            pub = ks.getCertificate(existing) != null
                    ? ks.getCertificate(existing).getPublicKey()
                    : null;
            if (pub == null) {
                // Some tokens won't return a cert for a raw keypair; fall through to generate.
                existing = null;
            } else {
                System.out.println("  reusing existing key: " + existing);
            }
        }
        if (existing == null) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", prov);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            priv = kp.getPrivate();
            pub = kp.getPublic();
            System.out.println("  generated fresh RSA keypair");
        }

        byte[] msg = "java-test-data".getBytes("UTF-8");
        Signature s = Signature.getInstance("SHA256withRSA", prov);
        s.initSign(priv);
        s.update(msg);
        byte[] sig = s.sign();
        System.out.println("  signature: " + sig.length + " bytes");

        // Verify with the default JCE provider (SunRsaSign) instead of
        // the PKCS#11 provider. This sidesteps tokens that don't set
        // CKA_VERIFY=true on pub keys derived from key generation
        // (e.g. Kryoptic). The signature itself was produced by the
        // token; verifying it against the same RSA public key in
        // pure Java is the right end-to-end check.
        Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(pub);
        v.update(msg);
        if (!v.verify(sig)) {
            throw new RuntimeException("FAIL: signature did not verify");
        }

        System.out.println("PASS: Java SunPKCS11 round-trip ok");
    }
}
