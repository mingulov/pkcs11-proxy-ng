#!/usr/bin/env python3
"""
Python PKCS#11 consumer smoke test using PyKCS11.

Usage:
    PKCS11_MODULE=/path/to/libpkcs11_proxy_ng_shim.so \
    PKCS11_PROXY_ENDPOINT=http://127.0.0.1:PORT \
    python3 test-python-consumer.py [PIN]

Exits 0 on success, 1 on failure. Prints structured output for parsing.
"""

import os
import sys

try:
    import PyKCS11
except ImportError:
    print("SKIP: PyKCS11 not installed")
    sys.exit(0)


def main():
    module_path = os.environ.get("PKCS11_MODULE")
    if not module_path:
        print("ERROR: PKCS11_MODULE not set")
        sys.exit(1)

    pin = sys.argv[1] if len(sys.argv) > 1 else "1234"
    results = []

    def record(name, passed, detail=""):
        status = "PASS" if passed else "FAIL"
        results.append((name, passed, detail))
        msg = f"[{status}] {name}"
        if detail:
            msg += f": {detail}"
        print(msg)

    try:
        lib = PyKCS11.PyKCS11Lib()
        lib.load(module_path)
        record("load_module", True)
    except Exception as e:
        record("load_module", False, str(e))
        print(f"\nResults: 0 passed, 1 failed")
        sys.exit(1)

    # Get slot list
    try:
        slots = lib.getSlotList(tokenPresent=True)
        record("get_slot_list", len(slots) > 0, f"found {len(slots)} slot(s)")
        if not slots:
            print(
                f"\nResults: {sum(1 for _, p, _ in results if p)} passed, {sum(1 for _, p, _ in results if not p)} failed"
            )
            sys.exit(1)
    except Exception as e:
        record("get_slot_list", False, str(e))
        print(
            f"\nResults: {sum(1 for _, p, _ in results if p)} passed, {sum(1 for _, p, _ in results if not p)} failed"
        )
        sys.exit(1)

    slot = slots[0]

    # Get token info
    try:
        info = lib.getTokenInfo(slot)
        record("get_token_info", True, f"label='{info.label.strip()}'")
    except Exception as e:
        record("get_token_info", False, str(e))

    # Get mechanism list
    try:
        mechs = lib.getMechanismList(slot)
        record("get_mechanism_list", len(mechs) > 0, f"{len(mechs)} mechanism(s)")
    except Exception as e:
        record("get_mechanism_list", False, str(e))

    # Open session
    try:
        session = lib.openSession(
            slot,
            PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION,
        )
        record("open_session", True)
    except Exception as e:
        record("open_session", False, str(e))
        print(
            f"\nResults: {sum(1 for _, p, _ in results if p)} passed, {sum(1 for _, p, _ in results if not p)} failed"
        )
        sys.exit(1)

    # Login
    try:
        session.login(pin)
        record("login", True)
    except PyKCS11.PyKCS11Error as e:
        if e.value == PyKCS11.CKR_USER_ALREADY_LOGGED_IN:
            record("login", True, "already logged in")
        else:
            record("login", False, str(e))

    # Generate random bytes
    try:
        rnd = session.generateRandom(32)
        record("generate_random", len(rnd) == 32, f"{len(rnd)} bytes")
    except Exception as e:
        record("generate_random", False, str(e))

    # Generate RSA key pair
    pub_handle = None
    priv_handle = None
    try:
        pub_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
            (PyKCS11.CKA_TOKEN, True),
            (PyKCS11.CKA_VERIFY, True),
            (PyKCS11.CKA_ENCRYPT, True),
            (PyKCS11.CKA_MODULUS_BITS, 2048),
            (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (PyKCS11.CKA_LABEL, "py-consumer-pub"),
        ]
        priv_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
            (PyKCS11.CKA_TOKEN, True),
            (PyKCS11.CKA_SIGN, True),
            (PyKCS11.CKA_DECRYPT, True),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (PyKCS11.CKA_LABEL, "py-consumer-priv"),
        ]
        pub_handle, priv_handle = session.generateKeyPair(
            pub_template,
            priv_template,
            mecha=PyKCS11.MechanismRSAGENERATEKEYPAIR,
        )
        record("generate_rsa_keypair", True, f"pub={pub_handle} priv={priv_handle}")
    except Exception as e:
        record("generate_rsa_keypair", False, str(e))

    # Sign and verify
    if priv_handle is not None and pub_handle is not None:
        test_data = b"Python PKCS#11 consumer test payload"
        try:
            signature = session.sign(
                priv_handle, test_data, PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS)
            )
            record("sign_rsa_pkcs", len(signature) > 0, f"{len(signature)} bytes")
        except Exception as e:
            record("sign_rsa_pkcs", False, str(e))
            signature = None

        if signature is not None:
            try:
                verified = session.verify(
                    pub_handle,
                    test_data,
                    signature,
                    PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS),
                )
                record("verify_rsa_pkcs", bool(verified))
            except Exception as e:
                record("verify_rsa_pkcs", False, str(e))

            # Verify with bad signature should fail
            try:
                bad_sig = bytes([0xDE] * len(signature))
                verified = session.verify(
                    pub_handle,
                    test_data,
                    bad_sig,
                    PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS),
                )
                record(
                    "verify_bad_sig_rejected",
                    not bool(verified),
                    "bad signature was accepted" if verified else "",
                )
            except PyKCS11.PyKCS11Error:
                record("verify_bad_sig_rejected", True)
            except Exception as e:
                record("verify_bad_sig_rejected", False, str(e))

    # Find objects
    try:
        objects = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            ]
        )
        record("find_objects", len(objects) > 0, f"found {len(objects)} private key(s)")
    except Exception as e:
        record("find_objects", False, str(e))

    # Get attribute values
    if priv_handle is not None:
        try:
            attrs = session.getAttributeValue(
                priv_handle,
                [
                    PyKCS11.CKA_CLASS,
                    PyKCS11.CKA_KEY_TYPE,
                    PyKCS11.CKA_LABEL,
                ],
            )
            record(
                "get_attribute_value", len(attrs) == 3, f"got {len(attrs)} attribute(s)"
            )
        except Exception as e:
            record("get_attribute_value", False, str(e))

    # Logout and close
    try:
        session.logout()
        record("logout", True)
    except Exception as e:
        record("logout", False, str(e))

    try:
        session.closeSession()
        record("close_session", True)
    except Exception as e:
        record("close_session", False, str(e))

    # Summary
    passed = sum(1 for _, p, _ in results if p)
    failed = sum(1 for _, p, _ in results if not p)
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
