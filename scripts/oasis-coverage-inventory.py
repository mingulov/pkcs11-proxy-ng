#!/usr/bin/env python3
"""Build a source-grounded PKCS#11 coverage inventory.

The vendored OASIS Markdown and published headers under the umbrella workspace
are the primary source of truth. Local Rust tables are implementation evidence,
not a replacement for the spec. This script intentionally reports spec-only
functions and working-spec mechanism names instead of silently dropping them
when the current ABI or published numeric inventory does not expose a slot.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


FUNCTION_RE = re.compile(r"\bC_[A-Za-z0-9_]+\b")
DECLARE_FUNCTION_RE = re.compile(r"CK_DECLARE_FUNCTION\([^,]+,\s*(C_[A-Za-z0-9_]+)\)")
HEADER_FUNCTION_RE = re.compile(r"CK_PKCS11_FUNCTION_INFO\((C_[A-Za-z0-9_]+)\)")
HEADING_FUNCTION_RE = re.compile(r"^#{2,6}\s+(C_[A-Za-z0-9_]+)\b")
MECHANISM_RE = re.compile(r"\bCKM_[A-Z0-9_]+\b")
PARAM_STRUCT_RE = re.compile(r"\bCK_[A-Z0-9_]+(?:PARAMS2?|PARAMS_PTR|PARAMETERS)\b")
CONCRETE_PARAM_STRUCT_RE = re.compile(r"\bCK_[A-Z0-9_]+(?:PARAMS2?|PARAMETERS)\b")
HEADING_RE = re.compile(r"^#{3,6}\s+.*$", re.MULTILINE)
DENOTED_MECHANISM_RE = re.compile(r"denoted\s+(?:\*\*)?(CKM_[A-Z0-9_]+)(?:\*\*)?")
STRUCT_PROVIDES_MECHANISM_PARAMS_RE = re.compile(
    r"\*\*(CK_[A-Z0-9_]+(?:PARAMS2?|PARAMETERS)\b)\*\*"
    r"\s+is a structure(?:\s+that|,\s+which)\s+provides the parameters to\s+"
    r"(.{0,180}?)\s+mechanism",
    re.DOTALL,
)
MECHANISM_HAS_PARAMETER_RE = re.compile(
    r"(?:\*\*)?(CKM_[A-Z0-9_]+)(?:\*\*)?\s+has a parameter,\s+"
    r"(?:a|an)\s+\*\*(CK_[A-Z0-9_]+(?:PARAMS2?|PARAMETERS)\b)\*\*",
    re.DOTALL,
)
SECTION_HAS_PARAMETER_RE = re.compile(
    r"\b(?:It|This mechanism|The mechanisms)\s+(?:has|have)\s+a parameter,\s+"
    r"(?:a|an)\s+\*\*(CK_[A-Z0-9_]+(?:PARAMS2?|PARAMETERS)\b)\*\*",
    re.DOTALL,
)
SECTION_USES_EXISTING_PARAMETER_RE = re.compile(
    r"\b(?:It|This mechanism|The mechanisms|(?:\*\*)?CKM_[A-Z0-9_]+(?:\*\*)?)"
    r".{0,120}?uses the existing\s+\*\*(CK_[A-Z0-9_]+(?:PARAMS2?|PARAMETERS)\b)\*\*"
    r"\s+structure",
    re.DOTALL,
)
RUST_FUNCTION_LIST_RE = re.compile(r"\bC_[A-Za-z0-9_]+\b")
RUST_OFFICIAL_MECH_RE = re.compile(
    r"CkMechanismType\((0x[0-9A-Fa-f]+|\d+)\),\s*//\s*(.+)"
)
RUST_STRUCT_RE = re.compile(r"^pub struct ([A-Z][A-Za-z0-9]+)")
RUST_MECHANISM_PARAM_ENUM_RE = re.compile(r"^pub enum CkMechanismParams\s*\{")
RUST_ENUM_VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9]+)\(([^)]+)\),")
HEADER_MECH_DEFINE_RE = re.compile(r"^\s*#define\s+(CKM_[A-Z0-9_]+)\s+(.+)$")
HEADER_MECH_ANNOTATION_RE = re.compile(r"/\*\s*(Historical|Deprecated)\s*\*/")
BACKEND_TRAIT_METHOD_RE = re.compile(r"^\s*fn\s+([a-z][a-z0-9_]*)\s*\(", re.MULTILINE)
TRAIT_DEFAULT_ERR_RE = re.compile(r"Err\(CkRv::([A-Z0-9_]+)\)")
PROTO_RPC_RE = re.compile(r"^\s*rpc\s+([A-Za-z][A-Za-z0-9_]*)\s*\(")
CLIENT_METHOD_RE = re.compile(r"^\s*pub\s+async\s+fn\s+([a-z][a-z0-9_]*)\s*\(")
SHIM_DISPATCH_RE = re.compile(
    r"pub\s+unsafe\s+extern\s+\"C\"\s+fn\s+(c_[a-z0-9_]+)\s*\("
)
SHIM_ROOT_ENTRYPOINT_RE = re.compile(
    r"pub\s+unsafe\s+extern\s+\"C\"\s+fn\s+(C_[A-Za-z0-9_]+)\s*\("
)
RUST_TEST_RE = re.compile(r"^\s*(?:async\s+)?fn\s+([a-z][a-z0-9_]*)\s*\(")
PROTO_MESSAGE_RE = re.compile(r"^message\s+([A-Za-z][A-Za-z0-9]+)\s*\{")
PROTO_ONEOF_FIELD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]+)\s+([a-z][a-z0-9_]*)\s*=")
CK_MECHANISM_PARAM_VARIANT_RE = re.compile(r"CkMechanismParams::([A-Z][A-Za-z0-9]+)\s*\(")

WORKFLOW_COLUMNS = [
    "encrypt_decrypt",
    "sign_verify",
    "sign_recover_verify_recover",
    "digest",
    "generate_generate_key_pair",
    "wrap_unwrap",
    "derive",
    "encapsulate_decapsulate",
]

WORKFLOW_MECHANISM_INFO_FLAGS = {
    "encrypt_decrypt": ["CKF_ENCRYPT", "CKF_DECRYPT"],
    "sign_verify": ["CKF_SIGN", "CKF_VERIFY"],
    "sign_recover_verify_recover": ["CKF_SIGN_RECOVER", "CKF_VERIFY_RECOVER"],
    "digest": ["CKF_DIGEST"],
    "wrap_unwrap": ["CKF_WRAP", "CKF_UNWRAP"],
    "derive": ["CKF_DERIVE"],
    "encapsulate_decapsulate": ["CKF_ENCAPSULATE", "CKF_DECAPSULATE"],
}

GENERATE_WORKFLOW = "generate_generate_key_pair"

MOCK_MECHANISM_INFO_FLAG_LOCAL_TEST = "mock_mechanism_info_uses_source_grounded_workflow_flags"
MOCK_SOURCE_GROUNDED_WORKFLOW_ENFORCEMENT_TEST = (
    "official_source_grounded_mock_enforces_mechanism_workflow_flags"
)
MOCK_NO_SOURCE_WORKFLOW_REJECTION_TEST = (
    "official_source_grounded_mock_rejects_all_no_source_workflow_mechanisms"
)
MOCK_MECHANISM_INFO_NO_SOURCE_LOCAL_TESTS = [
    "mock_mechanism_info_leaves_flags_empty_without_source_workflow_evidence",
    "grpc_mechanism_info_preserves_zero_flags_without_source_workflow_evidence",
    "loaded_shim_preserves_no_source_mechanism_info_zero_flags",
    MOCK_NO_SOURCE_WORKFLOW_REJECTION_TEST,
]

# Mechanisms whose MockBackend C_GetMechanismInfo flags are covered by a
# source-grounded local test. Most official mechanisms still have workflow
# coverage through generic simulator operations but do not yet have
# mechanism-specific flag evidence; the coverage matrix below makes that gap
# explicit instead of treating workflow smoke tests as semantic flags.
MOCK_MECHANISM_INFO_FLAG_SOURCE_GROUNDED_FLAGS = {
    "CKM_RSA_PKCS_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_RSA_PKCS": [
        "CKF_ENCAPSULATE",
        "CKF_DECAPSULATE",
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
        "CKF_SIGN",
        "CKF_SIGN_RECOVER",
        "CKF_VERIFY",
        "CKF_VERIFY_RECOVER",
        "CKF_WRAP",
        "CKF_UNWRAP",
    ],
    "CKM_RSA_PKCS_OAEP": [
        "CKF_ENCAPSULATE",
        "CKF_DECAPSULATE",
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
        "CKF_WRAP",
        "CKF_UNWRAP",
    ],
    # rsa.md marks these legacy and TPM RSA mechanisms in explicit workflow
    # table columns; CKM_RSA_AES_KEY_WRAP has a separate RSA_AES_KEY_WRAP table.
    "CKM_RSA_X9_31_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_RSA_9796": ["CKF_SIGN", "CKF_VERIFY", "CKF_SIGN_RECOVER", "CKF_VERIFY_RECOVER"],
    "CKM_RSA_X_509": [
        "CKF_ENCAPSULATE",
        "CKF_DECAPSULATE",
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
        "CKF_SIGN",
        "CKF_SIGN_RECOVER",
        "CKF_VERIFY",
        "CKF_VERIFY_RECOVER",
        "CKF_WRAP",
        "CKF_UNWRAP",
    ],
    "CKM_RSA_X9_31": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_RSA_PKCS_TPM_1_1": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_RSA_PKCS_OAEP_TPM_1_1": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_RSA_AES_KEY_WRAP": ["CKF_WRAP", "CKF_UNWRAP"],
    # cms_mechanisms.md marks CMS signatures for sign/verify and
    # sign-recover/verify-recover.
    "CKM_CMS_SIG": ["CKF_SIGN", "CKF_VERIFY", "CKF_SIGN_RECOVER", "CKF_VERIFY_RECOVER"],
    # password-based_encryption.md marks these PKCS #5/PBE mechanisms in GENK.
    "CKM_PBE_SHA1_DES3_EDE_CBC": ["CKF_GENERATE"],
    "CKM_PBE_SHA1_DES2_EDE_CBC": ["CKF_GENERATE"],
    "CKM_PBA_SHA1_WITH_SHA1_HMAC": ["CKF_GENERATE"],
    "CKM_PKCS5_PBKD2": ["CKF_GENERATE"],
    # null_mechanism.md marks every classic workflow except ENCS/DECS.
    "CKM_NULL": [
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
        "CKF_SIGN",
        "CKF_VERIFY",
        "CKF_SIGN_RECOVER",
        "CKF_VERIFY_RECOVER",
        "CKF_DIGEST",
        "CKF_WRAP",
        "CKF_UNWRAP",
        "CKF_DERIVE",
    ],
    "CKM_AES_KEY_GEN": ["CKF_GENERATE"],
    # The working AES mechanism table typo is CKM_AES_EC; the published headers
    # and definitions identify the intended mechanism as CKM_AES_ECB.
    "CKM_AES_ECB": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    # aes.md, aes_with_counter.md, aes_cbc_with_ciphertext_stealing_cts.md,
    # aes_xts.md, aes_key_wrap.md, additional_aes_mechanisms.md, and
    # key_derivation_by_data_encryption_aes-des.md mark the published AES
    # mechanisms in their mechanism/function tables. The AES tables contain
    # historical prose/table tension for some stream-like modes; the inventory
    # records the explicit mechanism/function table flags because those are the
    # direct CK_MECHANISM_INFO workflow source.
    "CKM_AES_CBC": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CTR": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CTS": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_XTS": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_OFB": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CFB64": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CFB8": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CFB128": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CFB1": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_CCM": [
        "CKF_MESSAGE_ENCRYPT",
        "CKF_MESSAGE_DECRYPT",
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
        "CKF_WRAP",
        "CKF_UNWRAP",
    ],
    # The GCM workflow table omits message-operation checkmarks, but the same
    # working spec file defines GCM message encrypt/decrypt flows in prose.
    "CKM_AES_GCM": [
        "CKF_MESSAGE_ENCRYPT",
        "CKF_MESSAGE_DECRYPT",
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
        "CKF_WRAP",
        "CKF_UNWRAP",
    ],
    "CKM_AES_KEY_WRAP": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_KEY_WRAP_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_KEY_WRAP_KWP": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_KEY_WRAP_PKCS7": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_AES_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_AES_MAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_AES_CMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_AES_CMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_AES_XCBC_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_AES_XCBC_MAC_96": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_AES_GMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_AES_XTS_KEY_GEN": ["CKF_GENERATE"],
    "CKM_AES_ECB_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_AES_CBC_ENCRYPT_DATA": ["CKF_DERIVE"],
    # chacha20.md and salsa20.md mark the stream cipher mechanisms for
    # encryption/decryption and wrapping/unwrapping, and their key-generation
    # rows in GENK. chacha20_salsa20_poly1305.md marks the combined AEAD
    # mechanisms for Encrypt/Decrypt and separately defines MessageEncrypt and
    # MessageDecrypt flows in prose.
    "CKM_CHACHA20": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_CHACHA20_KEY_GEN": ["CKF_GENERATE"],
    "CKM_CHACHA20_POLY1305": [
        "CKF_MESSAGE_ENCRYPT",
        "CKF_MESSAGE_DECRYPT",
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
    ],
    "CKM_SALSA20": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_SALSA20_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SALSA20_POLY1305": [
        "CKF_MESSAGE_ENCRYPT",
        "CKF_MESSAGE_DECRYPT",
        "CKF_ENCRYPT",
        "CKF_DECRYPT",
    ],
    "CKM_POLY1305_KEY_GEN": ["CKF_GENERATE"],
    # aria.md, camellia.md, seed.md, and the matching key-derivation-by-data
    # encryption sections have explicit mechanism/function tables for these
    # block-cipher families. CKM_CAMELLIA_CTR is intentionally not included
    # here because the current working spec text defines its params but does
    # not provide a workflow-table row.
    "CKM_ARIA_ECB": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_ARIA_CBC": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_ARIA_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_ARIA_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ARIA_MAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ARIA_KEY_GEN": ["CKF_GENERATE"],
    "CKM_ARIA_ECB_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_ARIA_CBC_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_CAMELLIA_ECB": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_CAMELLIA_CBC": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_CAMELLIA_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_CAMELLIA_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_CAMELLIA_MAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_CAMELLIA_KEY_GEN": ["CKF_GENERATE"],
    "CKM_CAMELLIA_ECB_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_CAMELLIA_CBC_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_SEED_ECB": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_SEED_CBC": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_SEED_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_SEED_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SEED_MAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SEED_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SEED_ECB_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_SEED_CBC_ENCRYPT_DATA": ["CKF_DERIVE"],
    # double_and_triple-length_des.md, double_and_triple-length_des_cmac.md,
    # and key_derivation_by_data_encryption_aes-des.md provide explicit
    # workflow tables for many DES-family mechanisms. The current working
    # function chapters also include examples for CKM_DES_KEY_GEN,
    # CKM_DES_ECB, CKM_DES_CBC_PAD, and CKM_DES_MAC. CKM_DES_CBC and
    # CKM_DES_MAC_GENERAL stay no-source here because the checked working
    # Markdown does not provide enough workflow evidence for their flags.
    "CKM_DES_KEY_GEN": ["CKF_GENERATE"],
    "CKM_DES_ECB": ["CKF_ENCRYPT", "CKF_DECRYPT"],
    "CKM_DES_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT"],
    "CKM_DES_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DES2_KEY_GEN": ["CKF_GENERATE"],
    "CKM_DES3_KEY_GEN": ["CKF_GENERATE"],
    "CKM_DES3_ECB": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_DES3_CBC": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_DES3_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_DES3_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DES3_MAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DES3_CMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DES3_CMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DES_OFB64": ["CKF_ENCRYPT", "CKF_DECRYPT"],
    "CKM_DES_OFB8": ["CKF_ENCRYPT", "CKF_DECRYPT"],
    "CKM_DES_CFB64": ["CKF_ENCRYPT", "CKF_DECRYPT"],
    "CKM_DES_CFB8": ["CKF_ENCRYPT", "CKF_DECRYPT"],
    "CKM_DES_ECB_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_DES_CBC_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_DES3_ECB_ENCRYPT_DATA": ["CKF_DERIVE"],
    "CKM_DES3_CBC_ENCRYPT_DATA": ["CKF_DERIVE"],
    # elliptic_curves.md provides a single explicit mechanism/function table
    # for EC key generation, ECDSA/EdDSA signatures, ECDH derives, and ECDH
    # AES key-wrap variants. CKM_ECDSA_KEY_PAIR_GEN is a deprecated published
    # alias for CKM_EC_KEY_PAIR_GEN and is not promoted here because the working
    # table names CKM_EC_KEY_PAIR_GEN.
    "CKM_EC_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS": ["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"],
    "CKM_EC_EDWARDS_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_EC_MONTGOMERY_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_ECDSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA1": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA512": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA3_224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA3_256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA3_384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDSA_SHA3_512": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_EDDSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_XEDDSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ECDH1_DERIVE": ["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"],
    "CKM_ECDH1_COFACTOR_DERIVE": ["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"],
    "CKM_ECMQV_DERIVE": ["CKF_DERIVE"],
    "CKM_ECDH_AES_KEY_WRAP": ["CKF_WRAP", "CKF_UNWRAP"],
    "CKM_ECDH_COF_AES_KEY_WRAP": ["CKF_WRAP", "CKF_UNWRAP"],
    "CKM_ECDH_X_AES_KEY_WRAP": ["CKF_WRAP", "CKF_UNWRAP"],
    # diffie-hellman.md marks DH/X9.42 key pair generation, domain parameter
    # generation, derivation, and ENCS/DECS encapsulation/decapsulation rows.
    "CKM_DH_PKCS_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_DH_PKCS_PARAMETER_GEN": ["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"],
    "CKM_DH_PKCS_DERIVE": ["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"],
    "CKM_X9_42_DH_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_X9_42_DH_PARAMETER_GEN": ["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"],
    "CKM_X9_42_DH_DERIVE": ["CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"],
    "CKM_X9_42_DH_HYBRID_DERIVE": ["CKF_DERIVE"],
    "CKM_X9_42_MQV_DERIVE": ["CKF_DERIVE"],
    # blowfish.md and twofish.md provide explicit mechanism/function tables for
    # key generation and CBC/CBC-PAD encrypt/decrypt plus wrap/unwrap.
    "CKM_BLOWFISH_KEY_GEN": ["CKF_GENERATE"],
    "CKM_BLOWFISH_CBC": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_BLOWFISH_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_TWOFISH_KEY_GEN": ["CKF_GENERATE"],
    "CKM_TWOFISH_CBC": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_TWOFISH_CBC_PAD": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    # generic_secret_key.md marks generic secret key generation in GENK, and
    # miscellaneous_simple_key_derivation_mechanisms.md marks the simple
    # concatenate/extract/public-from-private/XOR mechanisms in DRV.
    "CKM_GENERIC_SECRET_KEY_GEN": ["CKF_GENERATE"],
    "CKM_CONCATENATE_BASE_AND_KEY": ["CKF_DERIVE"],
    "CKM_CONCATENATE_BASE_AND_DATA": ["CKF_DERIVE"],
    "CKM_CONCATENATE_DATA_AND_BASE": ["CKF_DERIVE"],
    "CKM_XOR_BASE_AND_DATA": ["CKF_DERIVE"],
    "CKM_EXTRACT_KEY_FROM_KEY": ["CKF_DERIVE"],
    "CKM_PUB_KEY_FROM_PRIV_KEY": ["CKF_DERIVE"],
    # hkdf_mechanisms.md marks HKDF derive/data in DRV and HKDF key gen in GENK.
    "CKM_HKDF_DERIVE": ["CKF_DERIVE"],
    "CKM_HKDF_DATA": ["CKF_DERIVE"],
    "CKM_HKDF_KEY_GEN": ["CKF_GENERATE"],
    # ct-kip.md marks KIP derive, wrap, and MAC in DRV, WRP/UWRP, and SIG/VER.
    "CKM_KIP_DERIVE": ["CKF_DERIVE"],
    "CKM_KIP_WRAP": ["CKF_WRAP", "CKF_UNWRAP"],
    "CKM_KIP_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    # ike_mechanisms.md marks all IKE mechanisms in DRV.
    "CKM_IKE2_PRF_PLUS_DERIVE": ["CKF_DERIVE"],
    "CKM_IKE_PRF_DERIVE": ["CKF_DERIVE"],
    "CKM_IKE1_PRF_DERIVE": ["CKF_DERIVE"],
    "CKM_IKE1_EXTENDED_DERIVE": ["CKF_DERIVE"],
    # hash_based_key_derivations.md marks SHAKE key derivation mechanisms in DRV.
    "CKM_SHAKE_128_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHAKE_256_KEY_DERIVATION": ["CKF_DERIVE"],
    # hss.md and xmss_and_xmss-mt.md mark stateful hash signature key-pair
    # generation in GENKP and signing/verification in SIG/VER.
    "CKM_HSS_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_HSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_XMSS_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_XMSSMT_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_XMSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_XMSSMT": ["CKF_SIGN", "CKF_VERIFY"],
    # ssl.md, tls_1.2_mechanisms.md, and wtls.md provide explicit
    # mechanism/function tables for the current SSL/TLS/WTLS KDF and MAC rows.
    # CKM_TLS_PRF is not in the current mechanism/function table, but
    # tls_1.2_mechanisms.md still defines CK_TLS_PRF_PARAMS for CKM_TLS_PRF
    # and explicitly describes CKM_TLS_PRF as deprecated for C_DeriveKey.
    "CKM_SSL3_PRE_MASTER_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SSL3_MASTER_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_SSL3_MASTER_KEY_DERIVE_DH": ["CKF_DERIVE"],
    "CKM_SSL3_KEY_AND_MAC_DERIVE": ["CKF_DERIVE"],
    "CKM_SSL3_MD5_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SSL3_SHA1_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_TLS_PRE_MASTER_KEY_GEN": ["CKF_GENERATE"],
    "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH": ["CKF_DERIVE"],
    "CKM_TLS12_MASTER_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_TLS12_MASTER_KEY_DERIVE_DH": ["CKF_DERIVE"],
    "CKM_TLS12_KEY_AND_MAC_DERIVE": ["CKF_DERIVE"],
    "CKM_TLS12_KEY_SAFE_DERIVE": ["CKF_DERIVE"],
    "CKM_TLS_PRF": ["CKF_DERIVE"],
    "CKM_TLS_KDF": ["CKF_DERIVE"],
    "CKM_TLS12_KDF": ["CKF_DERIVE"],
    "CKM_TLS_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_TLS12_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_WTLS_PRE_MASTER_KEY_GEN": ["CKF_GENERATE"],
    "CKM_WTLS_MASTER_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC": ["CKF_DERIVE"],
    "CKM_WTLS_PRF": ["CKF_DERIVE"],
    "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE": ["CKF_DERIVE"],
    "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE": ["CKF_DERIVE"],
    "CKM_ML_KEM_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_ML_KEM": ["CKF_ENCAPSULATE", "CKF_DECAPSULATE"],
    # otp_mechanisms.md lists CKM_ACTI_KEY_GEN in the GENK column and describes
    # OTP retrieval/verification mechanisms as signing/verifying.
    "CKM_SECURID_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SECURID": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HOTP_KEY_GEN": ["CKF_GENERATE"],
    "CKM_HOTP": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ACTI": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_ACTI_KEY_GEN": ["CKF_GENERATE"],
    # gost_28147-89.md, gost_r_34.10-2001.md, and gost_r_34.11-94.md provide
    # explicit mechanism/function tables for the published GOST mechanisms.
    "CKM_GOST28147_KEY_GEN": ["CKF_GENERATE"],
    "CKM_GOST28147_ECB": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_GOST28147": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_GOST28147_MAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_GOST28147_KEY_WRAP": ["CKF_WRAP", "CKF_UNWRAP"],
    "CKM_GOSTR3410_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_GOSTR3410": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_GOSTR3410_WITH_GOSTR3411": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_GOSTR3410_KEY_WRAP": ["CKF_WRAP", "CKF_UNWRAP"],
    "CKM_GOSTR3410_DERIVE": ["CKF_DERIVE"],
    "CKM_GOSTR3411": ["CKF_DIGEST"],
    "CKM_GOSTR3411_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    # double_ratchet.md and extended_triple_diffie-hellman.md provide explicit
    # mechanism/function tables for their derive and encrypt/wrap workflows.
    "CKM_X3DH_INITIALIZE": ["CKF_DERIVE"],
    "CKM_X3DH_RESPOND": ["CKF_DERIVE"],
    "CKM_X2RATCHET_INITIALIZE": ["CKF_DERIVE"],
    "CKM_X2RATCHET_RESPOND": ["CKF_DERIVE"],
    "CKM_X2RATCHET_ENCRYPT": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    "CKM_X2RATCHET_DECRYPT": ["CKF_ENCRYPT", "CKF_DECRYPT", "CKF_WRAP", "CKF_UNWRAP"],
    # BLAKE2B mechanisms are split across the digest, hash-based MAC,
    # hash-based key-derivation, and MAC key-generation tables.
    "CKM_BLAKE2B_160": ["CKF_DIGEST"],
    "CKM_BLAKE2B_160_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_160_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_160_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_BLAKE2B_160_KEY_GEN": ["CKF_GENERATE"],
    "CKM_BLAKE2B_256": ["CKF_DIGEST"],
    "CKM_BLAKE2B_256_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_256_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_256_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_BLAKE2B_256_KEY_GEN": ["CKF_GENERATE"],
    "CKM_BLAKE2B_384": ["CKF_DIGEST"],
    "CKM_BLAKE2B_384_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_384_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_384_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_BLAKE2B_384_KEY_GEN": ["CKF_GENERATE"],
    "CKM_BLAKE2B_512": ["CKF_DIGEST"],
    "CKM_BLAKE2B_512_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_512_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_BLAKE2B_512_KEY_DERIVE": ["CKF_DERIVE"],
    "CKM_BLAKE2B_512_KEY_GEN": ["CKF_GENERATE"],
    # rsa.md marks RSA-PSS and hash-with-RSA signature mechanisms, including
    # deprecated MD2/MD5/RIPEMD variants, as sign/verify without message
    # recovery.
    "CKM_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_MD2_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_MD5_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_RIPEMD128_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_RIPEMD160_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA1_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA1_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA1_RSA_X9_31": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA224_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA224_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA256_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA256_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA384_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA384_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_224_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_224_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_256_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_256_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_384_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_384_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_512_RSA_PKCS": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_512_RSA_PKCS_PSS": ["CKF_SIGN", "CKF_VERIFY"],
    # dsa.md marks key-pair generation, parameter generation, and DSA
    # signature mechanisms in the mechanism/function table. The misspelled
    # CKM_DSA_PROBABLISTIC_PARAMETER_GEN header alias is left ungrounded.
    "CKM_DSA_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_DSA_PARAMETER_GEN": ["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"],
    "CKM_DSA_PROBABILISTIC_PARAMETER_GEN": ["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"],
    "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN": ["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"],
    "CKM_DSA_FIPS_G_GEN": ["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"],
    "CKM_DSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA1": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA512": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA3_224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA3_256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA3_384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_DSA_SHA3_512": ["CKF_SIGN", "CKF_VERIFY"],
    # ml_dsa.md and slh-dsa.md mark published post-quantum signature
    # mechanisms in the key-pair-generation or sign/verify workflow columns.
    # ExternalMu mechanisms remain spec-only until a published value appears.
    "CKM_ML_DSA_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_ML_DSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA512": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA3_224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA3_256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA3_384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHA3_512": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHAKE128": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_ML_DSA_SHAKE256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SLH_DSA_KEY_PAIR_GEN": ["CKF_GENERATE_KEY_PAIR"],
    "CKM_SLH_DSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA512": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA3_224": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA3_256": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA3_384": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHA3_512": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHAKE128": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HASH_SLH_DSA_SHAKE256": ["CKF_SIGN", "CKF_VERIFY"],
    # Historical MD digest evidence is fragmentary in the current working
    # spec: CKM_MD2 is shown with CKF_DIGEST in C_GetMechanismInfo example
    # prose, and CKM_MD5 is used with C_DigestInit in the digesting-functions
    # example. Do not infer MD HMAC or key-derivation rows from the published
    # header names alone.
    "CKM_MD2": ["CKF_DIGEST"],
    "CKM_MD5": ["CKF_DIGEST"],
    # SHA-1/SHA-2 mechanisms are split across the digest, hash-based MAC,
    # hash-based key-derivation, and MAC key-generation tables.
    "CKM_SHA_1": ["CKF_DIGEST"],
    "CKM_SHA_1_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA_1_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA_1_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA1_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA224": ["CKF_DIGEST"],
    "CKM_SHA224_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA224_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA224_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA224_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA256": ["CKF_DIGEST"],
    "CKM_SHA256_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA256_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA256_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA256_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA384": ["CKF_DIGEST"],
    "CKM_SHA384_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA384_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA384_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA384_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA512": ["CKF_DIGEST"],
    "CKM_SHA512_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA512_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA512_224": ["CKF_DIGEST"],
    "CKM_SHA512_224_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_224_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_224_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA512_224_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA512_256": ["CKF_DIGEST"],
    "CKM_SHA512_256_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_256_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_256_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA512_256_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA512_T": ["CKF_DIGEST"],
    "CKM_SHA512_T_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_T_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA512_T_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA512_T_KEY_GEN": ["CKF_GENERATE"],
    # SHA3 mechanisms are split across the digest, hash-based MAC,
    # hash-based key-derivation, and MAC key-generation tables. The
    # *_KEY_DERIVE aliases remain separate rows when no workflow-table evidence
    # is available for that spelling.
    "CKM_SHA3_224": ["CKF_DIGEST"],
    "CKM_SHA3_224_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_224_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_224_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA3_224_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA3_256": ["CKF_DIGEST"],
    "CKM_SHA3_256_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_256_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_256_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA3_256_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA3_384": ["CKF_DIGEST"],
    "CKM_SHA3_384_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_384_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_384_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA3_384_KEY_GEN": ["CKF_GENERATE"],
    "CKM_SHA3_512": ["CKF_DIGEST"],
    "CKM_SHA3_512_HMAC": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_512_HMAC_GENERAL": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_SHA3_512_KEY_DERIVATION": ["CKF_DERIVE"],
    "CKM_SHA3_512_KEY_GEN": ["CKF_GENERATE"],
    # sp800-108_key_derivation.md marks all three SP800-108 KDF mechanisms as
    # derive workflows and describes deriving one or more symmetric keys.
    "CKM_SP800_108_COUNTER_KDF": ["CKF_DERIVE"],
    "CKM_SP800_108_FEEDBACK_KDF": ["CKF_DERIVE"],
    "CKM_SP800_108_DOUBLE_PIPELINE_KDF": ["CKF_DERIVE"],
}

MOCK_MECHANISM_INFO_FLAG_SOURCE_DISCREPANCY_REPLACEMENT_FLAGS = {
    # poly1305.md has an inconsistent mechanism/function summary table that
    # marks CKM_POLY1305 in ENC/WRP, but the same section identifies Poly1305
    # as a MAC, its sample key template sets CKA_SIGN, and its mechanism table
    # lists C_Sign/C_Verify. Use the mechanism prose/function table for
    # CK_MECHANISM_INFO flags rather than the conflicting summary row.
    "CKM_POLY1305": ["CKF_SIGN", "CKF_VERIFY"],
    # password-based_encryption.md uses the combined GENK/GENKP table column,
    # but the section prose describes generating keys and IVs for PBE. These
    # mechanisms are generated with C_GenerateKey, not C_GenerateKeyPair.
    "CKM_PBE_SHA1_DES3_EDE_CBC": ["CKF_GENERATE"],
    "CKM_PBE_SHA1_DES2_EDE_CBC": ["CKF_GENERATE"],
    "CKM_PBA_SHA1_WITH_SHA1_HMAC": ["CKF_GENERATE"],
    "CKM_PKCS5_PBKD2": ["CKF_GENERATE"],
}

MECHANISM_SOURCE_DISCREPANCY_REASONS = {
    "CKM_POLY1305": "working_poly1305_mechanism_table_conflicts_with_mac_prose",
    "CKM_PBE_SHA1_DES3_EDE_CBC": "working_pbe_table_uses_combined_genk_genkp_column_but_prose_defines_key_iv_generation",
    "CKM_PBE_SHA1_DES2_EDE_CBC": "working_pbe_table_uses_combined_genk_genkp_column_but_prose_defines_key_iv_generation",
    "CKM_PBA_SHA1_WITH_SHA1_HMAC": "working_pbe_table_uses_combined_genk_genkp_column_but_prose_defines_key_iv_generation",
    "CKM_PKCS5_PBKD2": "working_pbe_table_uses_combined_genk_genkp_column_but_prose_defines_key_iv_generation",
}

MOCK_BACKEND_CORE_WORKFLOWS = [
    "sign",
    "sign_recover",
    "sign_update_final",
    "verify",
    "verify_recover",
    "verify_signature",
    "verify_update_final",
    "digest",
    "digest_update_final",
    "encrypt",
    "encrypt_update_final",
    "decrypt",
    "decrypt_update_final",
    "derive",
    "generate_key",
    "generate_key_pair",
    "wrap",
    "unwrap",
    "authenticated_wrap_unwrap",
    "async_complete",
    "kem_encapsulate_decapsulate",
    "message_encrypt_decrypt",
    "message_sign_verify",
]

MOCK_BACKEND_EXACT_OUTPUT_WORKFLOWS = [
    "sign_exact",
    "sign_final_exact",
    "sign_recover_exact",
    "verify_recover_exact",
    "digest_exact",
    "digest_final_exact",
    "encrypt_exact",
    "encrypt_update_exact",
    "encrypt_final_exact",
    "decrypt_exact",
    "decrypt_update_exact",
    "decrypt_final_exact",
    "combined_update_exact",
    "wrap_key_exact",
    "get_operation_state_exact",
    "encapsulate_key_exact",
    "parameter_output_exact",
    "parameter_output_next_exact",
    "authenticated_wrap_exact",
]

DIGEST_XOF_FUNCTIONS = {
    "C_DigestXof",
    "C_DigestXofExtract",
    "C_DigestXofFinal",
    "C_DigestXofInit",
    "C_DigestXofKeyValue",
    "C_DigestXofUpdate",
}

DIGEST_XOF_ABI_DECISION_LOCAL_TESTS = [
    "loaded_shim_does_not_export_digest_xof_out_of_band_symbols",
    "oasis_inventory_tracks_digest_xof_as_explicit_abi_decision",
]

SHIM_LOCAL_INTERFACE_FUNCTIONS = {
    "C_GetFunctionList": {
        "reason": "shim_local_function_catalog_entrypoint",
        "local_tests": [
            "get_function_list_null_returns_bad_args",
            "get_function_list_returns_nonnull_pointer",
            "get_function_list_version_is_2_40",
        ],
    },
    "C_GetInterfaceList": {
        "reason": "shim_local_function_catalog_entrypoint",
        "local_tests": [
            "get_interface_list_count_only_mode",
            "get_interface_list_fills_entries",
            "interface_catalog_has_three_entries",
        ],
    },
    "C_GetInterface": {
        "reason": "shim_local_function_catalog_entrypoint",
        "local_tests": [
            "get_interface_default_returns_3_2",
            "get_interface_pkcs11_version_2_40",
            "get_interface_3_2_by_version",
        ],
    },
}

FUNCTION_PROXY_LAYER_TESTS = [
    "backend_methods_have_proto_rpcs",
    "grpc_handlers_have_proto_rpcs",
    "proto_rpcs_have_grpc_handlers",
    "catch_panics_source_coverage",
]

FUNCTION_LIST_TESTS_BY_VERSION = {
    "2.40": ["all_function_list_pointers_are_non_null"],
    "3.0": ["all_3_0_out_of_scope_slots_are_nonnull"],
    "3.2": ["all_3_2_out_of_scope_slots_are_nonnull"],
}

FUNCTION_SEMANTIC_LOCAL_TESTS = {
    "C_AsyncComplete": ["async_complete_returns_result"],
    "C_AsyncGetID": ["async_get_id_returns_state_unsaveable"],
    "C_AsyncJoin": ["async_join_returns_saved_state_invalid"],
    "C_EncapsulateKey": ["encapsulate_key_returns_synthetic_result_through_full_stack"],
    "C_DecapsulateKey": ["decapsulate_key_returns_synthetic_handle_through_full_stack"],
    "C_WrapKeyAuthenticated": ["wrap_unwrap_key_authenticated_round_trip"],
    "C_UnwrapKeyAuthenticated": ["wrap_unwrap_key_authenticated_round_trip"],
    "C_MessageEncryptInit": ["message_encrypt_decrypt_round_trip"],
    "C_EncryptMessage": ["message_encrypt_decrypt_round_trip"],
    "C_EncryptMessageBegin": [
        "message_encrypt_decrypt_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_EncryptMessageNext": [
        "message_encrypt_decrypt_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_MessageEncryptFinal": ["message_encrypt_decrypt_round_trip"],
    "C_MessageDecryptInit": ["message_encrypt_decrypt_round_trip"],
    "C_DecryptMessage": ["message_encrypt_decrypt_round_trip"],
    "C_DecryptMessageBegin": [
        "message_encrypt_decrypt_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_DecryptMessageNext": [
        "message_encrypt_decrypt_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_MessageDecryptFinal": ["message_encrypt_decrypt_round_trip"],
    "C_MessageSignInit": ["message_sign_verify_round_trip"],
    "C_SignMessage": ["message_sign_verify_round_trip"],
    "C_SignMessageBegin": [
        "message_sign_verify_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_SignMessageNext": [
        "message_sign_verify_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_MessageSignFinal": ["message_sign_verify_round_trip"],
    "C_MessageVerifyInit": ["message_sign_verify_round_trip"],
    "C_VerifyMessage": ["message_sign_verify_round_trip"],
    "C_VerifyMessageBegin": [
        "message_sign_verify_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_VerifyMessageNext": [
        "message_sign_verify_begin_next_round_trip",
        "loaded_shim_message_begin_next_round_trips_c_stack_params",
    ],
    "C_MessageVerifyFinal": ["message_sign_verify_round_trip"],
    "C_Finalize": ["finalize_p_reserved_nonnull_returns_bad_args"],
    "C_FindObjectsInit": ["find_objects_tracks_active_search_operation"],
    "C_FindObjects": ["find_objects_tracks_active_search_operation"],
    "C_FindObjectsFinal": ["find_objects_tracks_active_search_operation"],
    "C_WaitForSlotEvent": [
        "wait_for_slot_event_blocks_until_event_when_flag_zero",
        "wait_for_slot_event_blocking_returns_not_initialized_after_finalize",
        "wait_for_slot_event_before_initialize_returns_cryptoki_not_initialized",
        "finalize_clears_pending_slot_events",
        "initialize_clears_pending_slot_events",
        "loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive",
        "c_wait_for_slot_event_nonnull_reserved_returns_bad_args",
    ],
}

MOCK_BACKEND_DEFAULT_DECISION_REASONS = {
    "FUNCTION_NOT_PARALLEL": "legacy_parallel_operation_status_api",
}

MOCK_BACKEND_DEFAULT_DECISION_LOCAL_TESTS = {
    "FUNCTION_NOT_PARALLEL": [
        "mock_legacy_parallel_functions_return_function_not_parallel",
    ],
}

PUBLISHED_HEADER_VERSIONS = [
    ("2.40", "2-40-errata-1"),
    ("3.0", "3-00"),
    ("3.1", "3-01"),
    ("3.2", "3-02"),
]

INTERFACE_SPEC_SOURCES = [
    "general_data_types.md",
    "general_purpose_functions.md",
]

STANDARD_INTERFACE_ENTRIES = [
    {
        "interface_name": "PKCS 11",
        "version": "2.40",
        "function_list_type": "CK_FUNCTION_LIST",
        "function_list_getter": "get_function_list",
        "default_interface": False,
        "local_tests": [
            "interface_catalog_has_three_entries",
            "get_interface_list_first_entry_is_2_40",
            "get_interface_pkcs11_version_2_40",
        ],
    },
    {
        "interface_name": "PKCS 11",
        "version": "3.0",
        "function_list_type": "CK_FUNCTION_LIST_3_0",
        "function_list_getter": "get_function_list_3_0",
        "default_interface": False,
        "local_tests": [
            "interface_catalog_has_three_entries",
            "get_interface_list_second_entry_is_3_0",
            "get_interface_pkcs11_version_3_0",
        ],
    },
    {
        "interface_name": "PKCS 11",
        "version": "3.2",
        "function_list_type": "CK_FUNCTION_LIST_3_2",
        "function_list_getter": "get_function_list_3_2",
        "default_interface": True,
        "local_tests": [
            "interface_catalog_has_three_entries",
            "get_interface_list_third_entry_is_3_2",
            "get_interface_3_2_by_version",
            "get_interface_default_returns_3_2",
            "get_interface_pkcs11_no_version_returns_3_2",
        ],
    },
]

MOCK_BACKEND_INTERFACE_CAPABILITY_TEST = (
    "mock_backend_reports_3x_interface_capabilities_by_default"
)

BACKEND_FFI_UNSUPPORTED_PARAMETER_VARIANTS = {
    "AesCmacKeyDerivation",
    "Dilithium",
    "Ecies",
    "HdKeyDerive",
    "Kyber",
    "Raw",
    "VendorObjectExtract",
    "VendorObjectInsert",
}

PARAMETER_SHAPE_OUTPUT_BEHAVIOR = {
    "Gcm": ["CK_GCM_PARAMS.pIv"],
    "Pbe": ["CK_PBE_PARAMS.pInitVector"],
    "Ssl3KeyMat": [
        "CK_SSL3_KEY_MAT_OUT.hClientMacSecret",
        "CK_SSL3_KEY_MAT_OUT.hServerMacSecret",
        "CK_SSL3_KEY_MAT_OUT.hClientKey",
        "CK_SSL3_KEY_MAT_OUT.hServerKey",
        "CK_SSL3_KEY_MAT_OUT.pIVClient",
        "CK_SSL3_KEY_MAT_OUT.pIVServer",
    ],
    "Sp800108FeedbackKdf": ["CK_DERIVED_KEY.phKey"],
    "Sp800108Kdf": ["CK_DERIVED_KEY.phKey"],
    "Tls12MasterKeyDerive": ["CK_TLS12_MASTER_KEY_DERIVE_PARAMS.pVersion"],
    "WtlsKeyMat": [
        "CK_WTLS_KEY_MAT_OUT.hMacSecret",
        "CK_WTLS_KEY_MAT_OUT.hKey",
        "CK_WTLS_KEY_MAT_OUT.pIV",
    ],
    "WtlsMasterKeyDerive": ["CK_WTLS_MASTER_KEY_DERIVE_PARAMS.pVersion"],
}

SP800_108_ERROR_OUTPUT_BEHAVIOR = {
    "source_behavior": (
        "CK_DERIVED_KEY.phKey set to CK_INVALID_HANDLE on template-caused "
        "multi-key derive failure"
    ),
    "source_evidence": [
        "doc/oasis-tcs-pkcs11/working/doc/spec/sp800-108_key_derivation.md",
    ],
    "current_support": "supported",
    "reason": "derive mechanism_out is preserved through non-CKR_OK proxy paths",
    "implementation_gap_paths": [],
    "local_tests": [
        "derive_key_with_sp800_108_template_failure_reports_invalid_additional_handle",
        "derive_key_mechanism_out_surfaces_sp800_108_template_failure_handle",
        "loaded_shim_writes_mechanism_out_to_caller_stack_after_encrypt_wrap_and_derive",
    ],
}

PARAMETER_SHAPE_ERROR_OUTPUT_BEHAVIOR = {
    "Sp800108FeedbackKdf": SP800_108_ERROR_OUTPUT_BEHAVIOR,
    "Sp800108Kdf": SP800_108_ERROR_OUTPUT_BEHAVIOR,
}

PARAMETER_SHAPE_NESTED_INPUT_HANDLES = {
    "Sp800108FeedbackKdf": ["CK_PRF_DATA_PARAM.CK_SP800_108_KEY_HANDLE"],
    "Sp800108Kdf": ["CK_PRF_DATA_PARAM.CK_SP800_108_KEY_HANDLE"],
}

PARAMETER_SHAPE_LOCAL_TESTS = {
    "AesCmacKeyDerivation": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "Dilithium": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "Ecies": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "HdKeyDerive": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "Kyber": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "Raw": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "VendorObjectExtract": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "VendorObjectInsert": ["unsupported_mechanism_params_are_rejected_by_backend_ffi"],
    "Iv": [
        "aes_cbc_iv_round_trip",
        "des3_cbc_iv_round_trip",
        "cbc_iv_params_reconstruct_raw_iv_buffer",
        "reads_common_mechanism_parameter_structs",
    ],
    "RsaPkcsPss": ["mechanism_pss_round_trip", "reads_common_mechanism_parameter_structs"],
    "RsaPkcsOaep": [
        "mechanism_oaep_round_trip",
        "mechanism_oaep_empty_source_data_round_trip",
        "reads_common_mechanism_parameter_structs",
    ],
    "Extract": [
        "extract_params_round_trip",
        "extract_params_reconstruct_ck_ulong_bit_position",
        "extract_params_reads_ck_ulong_bit_position",
    ],
    "ObjectHandle": [
        "object_handle_param_round_trip",
        "object_handle_param_reconstructs_ck_object_handle",
        "derive_key_validates_concatenate_base_and_key_parameter_handle",
        "reads_handle_string_and_sign_context_parameter_structs",
    ],
    "KeyDerivationString": [
        "key_derivation_string_data_round_trip",
        "key_derivation_string_data_empty_round_trip",
        "key_derivation_string_data_reconstructs_c_struct",
        "reads_handle_string_and_sign_context_parameter_structs",
    ],
    "SignAdditionalContext": [
        "sign_additional_context_round_trip",
        "sign_additional_context_reconstructs_c_struct",
        "reads_handle_string_and_sign_context_parameter_structs",
    ],
    "Gcm": [
        "gcm_generated_iv_buffer_is_preserved_and_written_back",
        "gcm_delayed_iv_round_trips_after_encrypt_data_query",
        "simple_encrypt_returns_late_gcm_output_params_through_grpc",
        "multipart_encrypt_returns_cached_gcm_output_params_through_grpc",
        "multipart_encrypt_returns_late_gcm_output_params_through_grpc",
    ],
    "Ccm": ["ccm_params_round_trip", "reads_aead_and_chacha_parameter_structs"],
    "ChaCha20": ["chacha20_params_round_trip", "reads_aead_and_chacha_parameter_structs"],
    "AesCtr": ["aes_ctr_params_round_trip", "reads_counter_and_encrypt_data_parameter_structs"],
    "CamelliaCtr": [
        "camellia_ctr_params_round_trip",
        "reads_counter_and_encrypt_data_parameter_structs",
    ],
    "AesCbcEncryptData": [
        "aes_cbc_encrypt_data_params_round_trip",
        "reads_counter_and_encrypt_data_parameter_structs",
    ],
    "DesCbcEncryptData": [
        "des_cbc_encrypt_data_params_round_trip",
        "reads_counter_and_encrypt_data_parameter_structs",
    ],
    "AriaCbcEncryptData": [
        "aria_cbc_encrypt_data_params_round_trip",
        "reads_counter_and_encrypt_data_parameter_structs",
    ],
    "CamelliaCbcEncryptData": [
        "camellia_cbc_encrypt_data_params_round_trip",
        "reads_counter_and_encrypt_data_parameter_structs",
    ],
    "SeedCbcEncryptData": [
        "seed_cbc_encrypt_data_params_round_trip",
        "reads_counter_and_encrypt_data_parameter_structs",
    ],
    "GcmWrap": ["gcm_wrap_params_round_trip", "reads_authenticated_wrap_parameter_structs"],
    "CcmWrap": ["ccm_wrap_params_round_trip", "reads_authenticated_wrap_parameter_structs"],
    "RsaAesKeyWrap": ["rsa_aes_key_wrap_round_trip", "reads_rsa_wrap_parameter_structs"],
    "KeyWrapSetOaep": ["key_wrap_set_oaep_round_trip", "reads_rsa_wrap_parameter_structs"],
    "Kmac": [
        "kmac_params_round_trip",
        "kmac_params_reconstruct_c_struct_and_customization_string",
        "kmac_params_reads_key_length_and_customization_string",
    ],
    "Kip": [
        "kip_params_round_trip",
        "kip_derive_and_mac_validate_hkey_but_wrap_does_not_use_it",
        "reads_kip_parameter_struct_with_nested_mechanism",
    ],
    "MuGen": [
        "mu_gen_params_round_trip",
        "mu_gen_params_reconstruct_c_struct_tr_and_context",
        "mu_gen_params_reads_key_tr_and_context",
    ],
    "Otp": [
        "otp_params_round_trip",
        "reads_otp_and_skipjack_parameter_structs",
    ],
    "Pbe": [
        "derive_key_with_output_returns_configured_pbe_iv_output_params",
        "derive_key_mechanism_out_surfaces_pbe_iv_through_mock_grpc_stack",
    ],
    "Rc5": [
        "rc5_params_round_trip",
        "reads_legacy_rc2_rc5_and_salsa20_parameter_structs",
    ],
    "Rc2Cbc": [
        "rc2_cbc_params_round_trip",
        "reads_legacy_rc2_rc5_and_salsa20_parameter_structs",
    ],
    "Rc2MacGeneral": [
        "rc2_mac_general_params_round_trip",
        "reads_legacy_rc2_rc5_and_salsa20_parameter_structs",
    ],
    "Rc5Cbc": [
        "rc5_cbc_params_round_trip",
        "reads_legacy_rc2_rc5_and_salsa20_parameter_structs",
    ],
    "Rc5MacGeneral": [
        "rc5_mac_general_params_round_trip",
        "reads_legacy_rc2_rc5_and_salsa20_parameter_structs",
    ],
    "Salsa20": [
        "salsa20_params_round_trip",
        "reads_legacy_rc2_rc5_and_salsa20_parameter_structs",
    ],
    "Salsa20ChaCha20Poly1305": [
        "salsa20_chacha20_poly1305_params_round_trip",
        "salsa20_chacha20_poly1305_empty_aad_round_trip",
        "reads_aead_and_chacha_parameter_structs",
    ],
    "MacGeneral": [
        "mac_general_params_round_trip",
        "mac_general_params_zero_round_trip",
        "reads_legacy_rc2_rc5_and_salsa20_parameter_structs",
    ],
    "SkipjackPrivateWrap": [
        "skipjack_private_wrap_round_trip",
        "reads_otp_and_skipjack_parameter_structs",
    ],
    "SkipjackRelayx": [
        "skipjack_relayx_round_trip",
        "reads_otp_and_skipjack_parameter_structs",
    ],
    "TlsMac": ["tls_mac_params_round_trip", "reads_tls_ssl_parameter_structs"],
    "TlsPrf": ["tls_prf_params_round_trip", "reads_tls_ssl_parameter_structs"],
    "TlsKdf": [
        "tls_kdf_params_round_trip",
        "tls_kdf_params_preserve_present_empty_random_info",
        "reads_tls_ssl_parameter_structs",
    ],
    "Ssl3MasterKeyDerive": [
        "ssl3_master_key_derive_round_trip",
        "reads_tls_ssl_parameter_structs",
    ],
    "Tls12ExtendedMasterKeyDerive": [
        "tls12_extended_master_key_derive_round_trip",
        "reads_tls_ssl_parameter_structs",
    ],
    "Hkdf": [
        "hkdf_round_trip",
        "hkdf_extract_only_round_trip",
        "reads_kdf_and_legacy_agreement_parameter_structs",
    ],
    "Gostr3410Derive": [
        "gostr3410_derive_round_trip",
        "reads_kdf_and_legacy_agreement_parameter_structs",
    ],
    "Gostr3410KeyWrap": [
        "gostr3410_key_wrap_round_trip",
        "reads_kdf_and_legacy_agreement_parameter_structs",
    ],
    "KeaDerive": [
        "kea_derive_round_trip",
        "reads_kdf_and_legacy_agreement_parameter_structs",
    ],
    "Pkcs5Pbkd2": [
        "pkcs5_pbkd2_round_trip",
        "reads_kdf_and_legacy_agreement_parameter_structs",
    ],
    "Ecdh1Derive": [
        "mechanism_ecdh1_derive_round_trip",
        "reads_ecdh_and_x942_parameter_structs",
    ],
    "Ecdh2Derive": [
        "ecdh2_derive_round_trip",
        "reads_ecdh_and_x942_parameter_structs",
        "derive_key_validates_dual_ec_and_x942_parameter_handles",
    ],
    "EcmqvDerive": [
        "ecmqv_derive_round_trip",
        "reads_ecdh_and_x942_parameter_structs",
        "derive_key_validates_dual_ec_and_x942_parameter_handles",
    ],
    "EcdhAesKeyWrap": [
        "ecdh_aes_key_wrap_round_trip",
        "reads_ecdh_and_x942_parameter_structs",
    ],
    "X942Dh1Derive": [
        "x942_dh1_derive_round_trip",
        "reads_ecdh_and_x942_parameter_structs",
    ],
    "X942Dh2Derive": [
        "x942_dh2_derive_round_trip",
        "reads_ecdh_and_x942_parameter_structs",
        "derive_key_validates_dual_ec_and_x942_parameter_handles",
    ],
    "IkePrfDerive": [
        "ike_prf_derive_round_trip",
        "reads_ike_parameter_structs",
    ],
    "Ike1PrfDerive": [
        "ike1_prf_derive_round_trip",
        "reads_ike_parameter_structs",
    ],
    "Ike1ExtendedDerive": [
        "ike1_extended_derive_round_trip",
        "reads_ike_parameter_structs",
    ],
    "Ike2PrfPlusDerive": [
        "ike2_prf_plus_derive_round_trip",
        "reads_ike_parameter_structs",
    ],
    "Eddsa": [
        "eddsa_round_trip",
        "eddsa_no_context_round_trip",
        "reads_signature_parameter_structs",
    ],
    "Xeddsa": [
        "xeddsa_params_round_trip",
        "reads_signature_parameter_structs",
    ],
    "CmsSig": [
        "cms_sig_params_round_trip",
        "cms_sig_params_reject_missing_digest_mechanism",
        "cms_sig_workflows_validate_optional_certificate_handle",
        "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
    ],
    "X3dhInitiate": [
        "x3dh_initiate_round_trip",
        "derive_key_validates_source_grounded_signal_parameter_handles",
        "derive_key_leaves_lengthless_signal_byte_fields_unvalidated",
        "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
    ],
    "X3dhRespond": [
        "x3dh_respond_round_trip",
        "derive_key_validates_source_grounded_signal_parameter_handles",
        "derive_key_leaves_lengthless_signal_byte_fields_unvalidated",
        "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
    ],
    "X2RatchetInitialize": [
        "x2_ratchet_initialize_round_trip",
        "derive_key_validates_source_grounded_signal_parameter_handles",
        "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
    ],
    "X2RatchetRespond": [
        "x2_ratchet_respond_round_trip",
        "derive_key_validates_source_grounded_signal_parameter_handles",
        "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
    ],
    "Ssl3KeyMat": [
        "derive_key_mechanism_out_surfaces_tls_key_material_through_mock_grpc_stack",
        "ssl3_key_mat_output_params_surface_mutated_handles_and_ivs",
        "tls12_key_mat_output_params_surface_mutated_handles_and_ivs",
        "ssl3_key_mat_reads_caller_stack_params_and_writes_outputs_back",
    ],
    "Sp800108FeedbackKdf": [
        "derive_key_with_sp800_108_additional_keys_allocates_output_handles",
        "derive_key_with_sp800_108_additional_keys_does_not_partially_allocate_on_quota_failure",
        "derive_key_with_sp800_108_additional_key_handles_preserves_templates",
        "derive_key_with_sp800_108_enforces_mode_data_param_rules",
        "derive_key_with_sp800_108_rejects_unsupported_prf_type",
        "derive_key_with_sp800_108_template_failure_reports_invalid_additional_handle",
        "derive_key_with_sp800_108_validates_data_param_payload_shapes_and_singletons",
        "derive_key_mechanism_out_surfaces_sp800_108_template_failure_handle",
        "derive_key_mechanism_out_virtualizes_sp800_108_feedback_additional_key_handles",
        "derive_key_with_sp800_108_key_handle_data_param_accepts_live_input_key",
        "derive_key_with_sp800_108_key_handle_data_param_requires_live_input_key",
        "resolves_sp800_108_key_handle_data_param_to_backend_handle_bytes",
        "sp800_108_feedback_reads_additional_keys_and_writes_handles_back",
        "sp800_108_feedback_null_iv_with_nonzero_len_stays_raw",
    ],
    "Sp800108Kdf": [
        "derive_key_with_sp800_108_additional_keys_allocates_output_handles",
        "derive_key_with_sp800_108_additional_keys_does_not_partially_allocate_on_quota_failure",
        "derive_key_with_sp800_108_additional_key_handles_preserves_templates",
        "derive_key_with_sp800_108_enforces_mode_data_param_rules",
        "derive_key_with_sp800_108_rejects_unsupported_prf_type",
        "derive_key_with_sp800_108_template_failure_reports_invalid_additional_handle",
        "derive_key_with_sp800_108_validates_data_param_payload_shapes_and_singletons",
        "derive_key_mechanism_out_surfaces_sp800_108_template_failure_handle",
        "derive_key_mechanism_out_virtualizes_sp800_108_additional_key_handles",
        "derive_key_mechanism_out_virtualizes_sp800_108_double_pipeline_additional_key_handles",
        "derive_key_rejects_invalid_sp800_108_key_handle_data_param",
        "derive_key_with_sp800_108_key_handle_data_param_accepts_live_input_key",
        "derive_key_with_sp800_108_key_handle_data_param_requires_live_input_key",
        "rejects_malformed_sp800_108_key_handle_data_param_width",
        "sp800_108_feedback_reads_additional_keys_and_writes_handles_back",
        "sp800_108_kdf_null_additional_keys_with_nonzero_count_stays_raw",
        "sp800_108_kdf_null_data_params_with_nonzero_count_stays_raw",
        "sp800_108_kdf_null_data_value_with_nonzero_len_stays_raw",
        "sp800_108_kdf_null_output_handle_stays_raw",
        "sp800_108_kdf_null_template_with_nonzero_attr_count_stays_raw",
    ],
    "Tls12MasterKeyDerive": [
        "derive_key_with_output_returns_configured_tls_output_params",
        "write_mechanism_output_params_writes_tls12_pversion",
    ],
    "WtlsMasterKeyDerive": [
        "derive_key_mechanism_out_surfaces_wtls_version_through_mock_grpc_stack",
        "wtls_master_key_derive_output_params_surface_mutated_version_byte",
        "wtls_master_key_derive_reads_version_byte_and_writes_it_back",
    ],
    "WtlsKeyMat": [
        "derive_key_mechanism_out_surfaces_wtls_key_material_through_mock_grpc_stack",
        "wtls_key_mat_output_params_surface_mutated_handles_and_iv",
        "wtls_key_mat_reads_caller_stack_params_and_writes_outputs_back",
    ],
    "WtlsPrf": [
        "wtls_prf_params_round_trip",
        "reads_wtls_prf_and_x942_mqv_parameter_structs",
    ],
    "X942MqvDerive": [
        "x942_mqv_derive_round_trip",
        "reads_wtls_prf_and_x942_mqv_parameter_structs",
        "derive_key_validates_dual_ec_and_x942_parameter_handles",
    ],
}

PARAMETER_SHAPE_UNSUPPORTED_REASONS = {
    "Raw": "opaque_raw_params_not_safe_for_backend_ffi",
    "AesCmacKeyDerivation": "vendor_specific_param_not_safe_for_backend_ffi",
    "Dilithium": "vendor_specific_param_not_safe_for_backend_ffi",
    "Ecies": "vendor_specific_param_not_safe_for_backend_ffi",
    "HdKeyDerive": "vendor_specific_param_not_safe_for_backend_ffi",
    "Kyber": "vendor_specific_param_not_safe_for_backend_ffi",
    "VendorObjectExtract": "vendor_specific_param_not_safe_for_backend_ffi",
    "VendorObjectInsert": "vendor_specific_param_not_safe_for_backend_ffi",
}

PARAMETER_SHAPE_SHIM_READ_UNSUPPORTED_REASONS = {
    "CmsSig": "null_terminated_content_type_without_bounded_length",
    "X2RatchetInitialize": "lengthless_shared_secret_pointer",
    "X2RatchetRespond": "lengthless_shared_secret_pointer",
    "X3dhInitiate": "lengthless_x3dh_byte_pointer_fields",
    "X3dhRespond": "lengthless_x3dh_byte_pointer_fields",
}

PARAMETER_SHAPE_SHIM_READ_DECISION_LOCAL_TESTS = [
    "unsafe_official_lengthless_parameter_shapes_are_rejected_before_shim_read",
    "loaded_shim_rejects_unsafe_official_lengthless_parameter_shapes",
    "oasis_inventory_classifies_unsafe_shim_parameter_read_gaps",
]

PARAMETER_STRUCT_ALIASES = {
    # The working chacha20_salsa20_poly1305.md prose names
    # CK_CHACHA20POLY1305_PARAMS, but its C block and the published OASIS
    # headers define CK_SALSA20_CHACHA20_POLY1305_PARAMS for the same
    # CKM_CHACHA20_POLY1305/CKM_SALSA20_POLY1305 mechanism params.
    "CK_CHACHA20POLY1305_PARAMS": {
        "modeled_as": "CK_SALSA20_CHACHA20_POLY1305_PARAMS",
        "reason": "working_spec_prose_alias_not_published_header_struct",
    },
}

PARAMETER_STRUCT_PLACEHOLDERS = {
    # The authenticated wrap/unwrap prose uses CK_XXX_MESSAGE_PARAMS as a
    # placeholder for mechanism-specific message parameter structs such as
    # CK_GCM_MESSAGE_PARAMS and CK_CCM_MESSAGE_PARAMS. It is not a concrete C
    # struct that can be modeled in the ABI matrix.
    "CK_XXX_MESSAGE_PARAMS": {
        "reason": "prose_placeholder_for_mechanism_specific_message_params",
    },
}

PROSE_MECHANISM_PARAMETER_STRUCT_OVERRIDES = {
    # additional_aes_mechanisms.md describes AES-GMAC as a special case of GCM
    # and defines its tag and IV lengths in terms of CK_GCM_PARAMS fields, but
    # does not use the usual "has a parameter" sentence form.
    "CKM_AES_GMAC": {"CK_GCM_PARAMS"},
}

MESSAGE_PARAMETER_SHAPE_OUTPUT_BEHAVIOR = {
    "CcmMessage": ["CK_CCM_MESSAGE_PARAMS.pNonce", "CK_CCM_MESSAGE_PARAMS.pMAC"],
    "GcmMessage": ["CK_GCM_MESSAGE_PARAMS.pIv", "CK_GCM_MESSAGE_PARAMS.pTag"],
    "SalaChacha": [
        "CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS.pNonce",
        "CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS.pTag",
    ],
}

MESSAGE_PARAMETER_SHAPE_LOCAL_TESTS = {
    "CcmMessage": [
        "ccm_message_params_round_trip",
        "message_parameter_ccm_round_trip",
        "typed_message_exact_paths_return_structured_mock_outputs",
    ],
    "GcmMessage": [
        "gcm_message_params_round_trip",
        "message_parameter_gcm_round_trip",
        "typed_message_exact_paths_return_structured_mock_outputs",
    ],
    "SalaChacha": [
        "salsa20_chacha20_poly1305_message_params_round_trip",
        "message_parameter_salsa_chacha_round_trip",
        "typed_message_exact_paths_return_structured_mock_outputs",
    ],
}

MESSAGE_PARAMETER_READ_WRITE_HELPERS = {
    "CcmMessage": ("read_ccm_message_params", "write_ccm_message_params_back"),
    "GcmMessage": ("read_gcm_message_params", "write_gcm_message_params_back"),
    "SalaChacha": (
        "read_salsa_chacha_message_params",
        "write_salsa_chacha_message_params_back",
    ),
}

SPEC_MECHANISM_FALSE_POSITIVES = {
    # Typo in the working AES mechanism table; the mechanism list and headers
    # use CKM_AES_ECB.
    "CKM_AES_EC",
    # Generic prose/example tokens, not published CKM_* mechanism constants.
    "CKM_ECDH",
    "CKM_PBE",
    # Typo in a C_DigestXof keyed-KMAC example; the working KMAC section uses
    # CKM_KMAC256.
    "CKM_KMAC_256",
}


@dataclass
class FunctionEntry:
    name: str
    sources: set[str] = field(default_factory=set)


@dataclass
class MechanismEntry:
    name: str
    sources: set[str] = field(default_factory=set)
    workflows: set[str] = field(default_factory=set)
    parameter_structs: set[str] = field(default_factory=set)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def oasis_root(root: Path) -> Path:
    if env_root := os.environ.get("PKCS11_PROXY_NG_OASIS_ROOT"):
        return Path(env_root).resolve()
    return (root / "../doc/oasis-tcs-pkcs11").resolve()


def spec_root(root: Path) -> Path:
    return oasis_root(root) / "working/doc/spec"


def official_mechanism_rust(root: Path) -> Path:
    return root / "crates/types/src/mechanism_official.rs"


def mechanism_types_source(root: Path) -> Path:
    return root / "crates/types/src/mechanism.rs"


def official_mechanism_headers(root: Path) -> list[tuple[str, Path]]:
    published = oasis_root(root) / "published"
    return [
        (version, published / dirname / "pkcs11t.h")
        for version, dirname in PUBLISHED_HEADER_VERSIONS
    ]


def official_function_headers(root: Path) -> list[tuple[str, Path]]:
    published = oasis_root(root) / "published"
    return [
        (version, published / dirname / "pkcs11f.h")
        for version, dirname in PUBLISHED_HEADER_VERSIONS
    ]


def function_field_tables(root: Path) -> Path:
    return root / "crates/backend/src/ffi/function_field_tables.rs"


def service_proto(root: Path) -> Path:
    return root / "proto/pkcs11-proxy-ng/v1/service.proto"


def mechanism_params_proto(root: Path) -> Path:
    return root / "proto/pkcs11-proxy-ng/v1/mechanism_params.proto"


def message_params_source(root: Path) -> Path:
    return root / "crates/proto/src/convert/message_params.rs"


def types_proto(root: Path) -> Path:
    return root / "proto/pkcs11-proxy-ng/v1/types.proto"


def backend_traits(root: Path) -> Path:
    return root / "crates/backend/src/traits.rs"


def mock_backend_source(root: Path) -> Path:
    return root / "crates/backend/src/mock.rs"


def backend_ffi_conversion(root: Path) -> Path:
    return root / "crates/backend/src/ffi/ffi_conversion.rs"


def backend_ffi_message_ops(root: Path) -> Path:
    return root / "crates/backend/src/ffi/message_ops.rs"


def client_source_root(root: Path) -> Path:
    return root / "crates/client/src/client"


def shim_dispatch_root(root: Path) -> Path:
    return root / "crates/shim/src/dispatch/general"


def shim_lib(root: Path) -> Path:
    return root / "crates/shim/src/lib.rs"


def shim_interface_probe(root: Path) -> Path:
    return root / "crates/shim/src/interface_probe.rs"


def shim_interface_tests(root: Path) -> Path:
    return root / "crates/shim/src/tests/interface.rs"


def shim_helpers(root: Path) -> Path:
    return root / "crates/shim/src/dispatch/general/helpers.rs"


def provider_artifacts_root(root: Path) -> Path:
    if env_root := os.environ.get("PKCS11_PROXY_NG_PROVIDER_ARTIFACTS_ROOT"):
        return Path(env_root).resolve()
    return (root / "../../pkcs11-check/artifacts").resolve()


def sorted_names(values: set[str] | dict[str, Any]) -> list[str]:
    return sorted(values.keys() if isinstance(values, dict) else values)


def is_official_mechanism_name(name: str) -> bool:
    if name == "CKM_VENDOR_DEFINED" or name.startswith("CKM_VENDOR_DEFINED_"):
        return False
    if name in SPEC_MECHANISM_FALSE_POSITIVES:
        return False
    # The Markdown uses template names such as CKM_DSA_<hash>. The token regex
    # sees those as CKM_DSA_; keep them out of the official mechanism matrix.
    return not name.endswith("_")


def spec_sections(text: str) -> list[str]:
    matches = list(HEADING_RE.finditer(text))
    if not matches:
        return [text]
    sections = [text[: matches[0].start()]]
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections.append(text[match.start() : end])
    return sections


def official_mechanisms_in_text(text: str) -> set[str]:
    return {
        mechanism
        for mechanism in MECHANISM_RE.findall(text)
        if is_official_mechanism_name(mechanism)
    }


def extract_mechanism_parameter_structs(text: str) -> dict[str, set[str]]:
    """Return source-local mechanism-to-parameter-struct associations.

    A spec file can define several mechanisms and several parameter structs.
    File-wide association is too broad: for example rsa.md defines OAEP, PSS,
    and RSA-AES parameter structs, while many RSA mechanisms have no parameter.
    Keep associations tied to nearby mechanism prose instead.
    """

    associations: dict[str, set[str]] = {}

    def add(mechanism: str, struct_name: str) -> None:
        if is_official_mechanism_name(mechanism):
            associations.setdefault(mechanism, set()).add(struct_name)

    for match in STRUCT_PROVIDES_MECHANISM_PARAMS_RE.finditer(text):
        for mechanism in official_mechanisms_in_text(match.group(2)):
            add(mechanism, match.group(1))
    for match in MECHANISM_HAS_PARAMETER_RE.finditer(text):
        add(match.group(1), match.group(2))

    for section in spec_sections(text):
        section_structs: set[str] = set()
        for pattern in [SECTION_HAS_PARAMETER_RE, SECTION_USES_EXISTING_PARAMETER_RE]:
            section_structs.update(match.group(1) for match in pattern.finditer(section))
        if not section_structs:
            continue
        mechanisms = official_mechanisms_in_text(section)
        if not mechanisms:
            continue
        primary_mechanisms = {
            mechanism
            for mechanism in DENOTED_MECHANISM_RE.findall(section)
            if is_official_mechanism_name(mechanism)
        }
        targets = primary_mechanisms or mechanisms
        for mechanism in targets:
            for struct_name in section_structs:
                add(mechanism, struct_name)

    for mechanism, structs in PROSE_MECHANISM_PARAMETER_STRUCT_OVERRIDES.items():
        if mechanism in official_mechanisms_in_text(text):
            for struct_name in structs:
                add(mechanism, struct_name)

    return associations


def parse_spec_functions_and_mechanisms(spec_dir: Path) -> tuple[
    dict[str, FunctionEntry], dict[str, MechanismEntry], dict[str, set[str]]
]:
    functions: dict[str, FunctionEntry] = {}
    mechanisms: dict[str, MechanismEntry] = {}
    parameter_struct_sources: dict[str, set[str]] = {}

    for path in sorted(spec_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        relative = path.name

        for match in HEADING_FUNCTION_RE.finditer(text):
            functions.setdefault(match.group(1), FunctionEntry(match.group(1))).sources.add(
                relative
            )
        for match in DECLARE_FUNCTION_RE.finditer(text):
            functions.setdefault(match.group(1), FunctionEntry(match.group(1))).sources.add(
                relative
            )

        file_parameter_structs = {
            item for item in PARAM_STRUCT_RE.findall(text) if item != "CK_MECHANISM_PTR"
        }
        for struct_name in file_parameter_structs:
            parameter_struct_sources.setdefault(struct_name, set()).add(relative)
        mechanism_parameter_structs = extract_mechanism_parameter_structs(text)

        for mechanism_name in MECHANISM_RE.findall(text):
            if not is_official_mechanism_name(mechanism_name):
                continue
            mechanisms.setdefault(mechanism_name, MechanismEntry(mechanism_name)).sources.add(
                relative
            )

        for line in text.splitlines():
            if not line.startswith("| CKM_"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if not cells:
                continue
            mechanism_name = cells[0]
            if not MECHANISM_RE.fullmatch(mechanism_name):
                continue
            if not is_official_mechanism_name(mechanism_name):
                continue
            entry = mechanisms.setdefault(mechanism_name, MechanismEntry(mechanism_name))
            entry.sources.add(relative)
            for index, cell in enumerate(cells[1 : 1 + len(WORKFLOW_COLUMNS)]):
                if "✓" in cell or "x" == cell.lower():
                    entry.workflows.add(WORKFLOW_COLUMNS[index])
            entry.parameter_structs.update(mechanism_parameter_structs.get(mechanism_name, set()))

        for mechanism_name, structs in mechanism_parameter_structs.items():
            if not is_official_mechanism_name(mechanism_name):
                continue
            entry = mechanisms.setdefault(mechanism_name, MechanismEntry(mechanism_name))
            entry.sources.add(relative)
            entry.parameter_structs.update(structs)

    return functions, mechanisms, parameter_struct_sources


def parse_function_list_fields(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    fields: dict[str, str] = {}
    section = "unknown"
    for line in text.splitlines():
        if "FUNCTION_LIST_3_2_EXTRA_FIELDS" in line:
            section = "3.2"
        elif "FUNCTION_LIST_3_0_EXTRA_FIELDS" in line:
            section = "3.0"
        elif "FUNCTION_LIST_FIELDS" in line:
            section = "2.40"
        for name in RUST_FUNCTION_LIST_RE.findall(line):
            fields.setdefault(name, section)
    return fields


def pascal_to_snake(name: str) -> str:
    result: list[str] = []
    chars = list(name)
    for index, char in enumerate(chars):
        if char.isupper() and index > 0:
            prev_upper = chars[index - 1].isupper()
            next_lower = index + 1 < len(chars) and chars[index + 1].islower()
            if not prev_upper or next_lower:
                result.append("_")
        result.append(char.lower())
    return "".join(result)


def c_function_to_pascal(name: str) -> str:
    return name[2:] if name.startswith("C_") else name


def c_function_to_snake(name: str) -> str:
    return pascal_to_snake(c_function_to_pascal(name))


def parse_proto_rpcs(path: Path) -> set[str]:
    return {
        match.group(1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if (match := PROTO_RPC_RE.match(line))
    }


def parse_backend_trait_methods(path: Path) -> set[str]:
    return {
        match.group(1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if (match := BACKEND_TRAIT_METHOD_RE.match(line))
    }


def find_braced_block(text: str, opening_brace: int) -> tuple[str, int]:
    depth = 0
    for index in range(opening_brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[opening_brace + 1 : index], index
    raise ValueError("unterminated Rust block")


def parse_backend_trait_default_error_methods(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    methods: dict[str, str] = {}
    offset = 0
    while match := BACKEND_TRAIT_METHOD_RE.search(text, offset):
        method = match.group(1)
        after_signature_start = match.end()
        semicolon = text.find(";", after_signature_start)
        opening_brace = text.find("{", after_signature_start)
        if opening_brace == -1:
            break
        if semicolon != -1 and semicolon < opening_brace:
            offset = semicolon + 1
            continue

        body, block_end = find_braced_block(text, opening_brace)
        if error := TRAIT_DEFAULT_ERR_RE.search(body):
            methods[method] = error.group(1)
        offset = block_end + 1
    return methods


def parse_mock_backend_impl_methods(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    marker = "impl Pkcs11Backend for MockBackend"
    marker_start = text.find(marker)
    if marker_start == -1:
        raise SystemExit(f"MockBackend Pkcs11Backend implementation not found: {path}")
    opening_brace = text.find("{", marker_start)
    block, _block_end = find_braced_block(text, opening_brace)
    return {
        match.group(1)
        for line in block.splitlines()
        if (match := BACKEND_TRAIT_METHOD_RE.match(line))
    }


def parse_client_methods(path: Path) -> set[str]:
    methods: set[str] = set()
    for source in sorted(path.rglob("*.rs")):
        for line in source.read_text(encoding="utf-8").splitlines():
            if match := CLIENT_METHOD_RE.match(line):
                methods.add(match.group(1))
    return methods


def parse_shim_dispatch_functions(path: Path) -> set[str]:
    functions: set[str] = set()
    for source in sorted(path.rglob("*.rs")):
        for match in SHIM_DISPATCH_RE.finditer(source.read_text(encoding="utf-8")):
            name = match.group(1)
            if not name.startswith("c_not_supported"):
                functions.add(name)
    return functions


def parse_shim_root_entrypoints(path: Path) -> set[str]:
    return set(SHIM_ROOT_ENTRYPOINT_RE.findall(path.read_text(encoding="utf-8")))


def match_proto_rpc(function_name: str, rpcs: set[str]) -> str | None:
    pascal = c_function_to_pascal(function_name)
    for rpc in sorted(rpcs):
        if rpc.lower() == pascal.lower():
            return rpc
    return None


def unsupported_function_reason(name: str, spec_present: bool, function_list_field: bool) -> str | None:
    if spec_present and not function_list_field and name in DIGEST_XOF_FUNCTIONS:
        return "cryptoki_sys_missing_function_list_field"
    return None


def spec_only_function_abi_decision(
    name: str,
    spec_present: bool,
    function_list_field: bool,
    published_headers_checked: list[str],
    function_field_table: str,
) -> dict[str, Any] | None:
    if not (spec_present and not function_list_field and name in DIGEST_XOF_FUNCTIONS):
        return None
    return {
        "policy": "do_not_add_out_of_band_exports_or_custom_function_list_layout",
        "reason": "working_spec_declares_function_but_standard_function_lists_do_not",
        "compatibility_risk": "custom_ck_function_list_layout_would_break_standard_pkcs11_abi",
        "unsupported_reason": "cryptoki_sys_missing_function_list_field",
        "evidence": [
            "working/doc/spec/message_digesting_functions.md",
            *published_headers_checked,
            function_field_table,
        ],
        "local_tests": DIGEST_XOF_ABI_DECISION_LOCAL_TESTS,
    }


def parse_oasis_header_function_inventory(root: Path) -> tuple[
    list[dict[str, Any]], list[str]
]:
    by_name: dict[str, dict[str, Any]] = {}
    source_headers: list[str] = []
    version_order = {version: index for index, (version, _) in enumerate(PUBLISHED_HEADER_VERSIONS)}

    for version, path in official_function_headers(root):
        if not path.exists():
            raise SystemExit(f"vendored OASIS function header not found: {path}")
        relative_display = (
            Path("../doc/oasis-tcs-pkcs11/published") / path.parent.name / path.name
        )
        source_headers.append(relative_display.as_posix())
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in sorted(set(HEADER_FUNCTION_RE.findall(text))):
            entry = by_name.setdefault(
                name,
                {
                    "name": name,
                    "source_versions": set(),
                    "source_headers": set(),
                },
            )
            entry["source_versions"].add(version)
            entry["source_headers"].add(relative_display.as_posix())

    entries: list[dict[str, Any]] = []
    for name, raw_entry in sorted(by_name.items()):
        source_versions = sorted(
            raw_entry["source_versions"], key=lambda item: version_order.get(item, 999)
        )
        entries.append(
            {
                "name": name,
                "version_introduced": source_versions[0] if source_versions else None,
                "source_versions": source_versions,
                "source_headers": sorted(raw_entry["source_headers"]),
            }
        )

    return entries, source_headers


def compare_function_fields(
    published_functions: list[dict[str, Any]], function_fields: dict[str, str]
) -> dict[str, Any]:
    published_names = {entry["name"] for entry in published_functions}
    local_names = set(function_fields)
    oasis_3_2_functions_missing_from_local_fields = sorted(published_names - local_names)
    local_fields_missing_from_oasis_3_2_headers = sorted(local_names - published_names)

    return {
        "matches": not (
            oasis_3_2_functions_missing_from_local_fields
            or local_fields_missing_from_oasis_3_2_headers
        ),
        "oasis_3_2_functions_missing_from_local_fields": (
            oasis_3_2_functions_missing_from_local_fields
        ),
        "local_fields_missing_from_oasis_3_2_headers": (
            local_fields_missing_from_oasis_3_2_headers
        ),
    }


def unsupported_mechanism_reason(
    name: str, spec_present: bool, official_inventory_present: bool
) -> str | None:
    if spec_present and not official_inventory_present:
        return "oasis_working_spec_lacks_published_numeric_value"
    return None


WORKING_SPEC_MECHANISM_NUMERIC_DECISION_LOCAL_TESTS = [
    "oasis_inventory_marks_working_spec_mechanisms_without_published_values",
]


def mechanism_numeric_decision(
    name: str,
    spec_present: bool,
    official_inventory_present: bool,
    spec_sources: list[str],
    official_headers_checked: list[str],
    rust_test_names: set[str],
) -> dict[str, Any] | None:
    if unsupported_mechanism_reason(name, spec_present, official_inventory_present) is None:
        return None
    local_tests = WORKING_SPEC_MECHANISM_NUMERIC_DECISION_LOCAL_TESTS
    return {
        "policy": "do_not_assign_project_local_ckm_values_for_working_spec_names",
        "reason": "working_spec_mechanism_name_lacks_published_ck_mechanism_type",
        "compatibility_risk": "locally_assigned_ckm_values_could_collide_with_future_oasis_or_vendor_values",
        "unsupported_reason": "oasis_working_spec_lacks_published_numeric_value",
        "evidence": sorted({*spec_sources, *official_headers_checked}),
        "local_tests": local_tests,
        "local_tests_missing": [
            test_name for test_name in local_tests if test_name not in rust_test_names
        ],
    }


def mechanism_source_discrepancy_reason(
    name: str, spec_present: bool, official_inventory_present: bool
) -> str | None:
    if name in MECHANISM_SOURCE_DISCREPANCY_REASONS:
        return MECHANISM_SOURCE_DISCREPANCY_REASONS[name]
    if official_inventory_present and not spec_present:
        return "oasis_published_header_not_in_working_markdown"
    return None


def mock_backend_internal_coverage(
    official_inventory_present: bool,
    mechanism_info_flags: dict[str, Any],
    rust_test_names: set[str],
) -> dict[str, Any]:
    if not official_inventory_present:
        return {
            "advertised_by_official_constructor": False,
            "advertisement_test": None,
            "catalog_smoke_constructor": None,
            "catalog_smoke_workflow_test": None,
            "catalog_smoke_workflows": [],
            "core_workflow_test": None,
            "core_workflows": [],
            "exact_output_workflow_test": None,
            "exact_output_workflows": [],
            "semantic_constructor": None,
            "source_grounded_workflow_enforcement_test": None,
            "source_grounded_workflows": [],
            "workflow_semantics_status": "no_published_ck_mechanism_type_value",
            "semantic_limitation": "no_published_ck_mechanism_type_value",
            "local_tests": [],
            "local_tests_missing": [],
            "limitation": "no_published_ck_mechanism_type_value",
        }

    catalog_tests = [
        "official_mechanism_mock_advertises_provider_gap_mechanisms",
        "official_mechanism_mock_accepts_every_official_mechanism_across_core_workflows",
        "official_mechanism_mock_accepts_every_official_mechanism_across_exact_output_workflows",
        "mechanism_bearing_workflows_reject_unadvertised_mechanisms",
        MOCK_SOURCE_GROUNDED_WORKFLOW_ENFORCEMENT_TEST,
    ]
    local_tests = sorted(
        {*catalog_tests, *mechanism_info_flags.get("local_tests", [])}
    )
    workflow_semantics_status = mechanism_info_flags["status"]
    semantic_limitation = mechanism_info_flags["unsupported_reason"]
    source_grounded_workflows = (
        source_grounded_workflow_names(mechanism_info_flags["expected_flag_names"])
        if workflow_semantics_status == "source_grounded"
        else []
    )
    return {
        "advertised_by_official_constructor": True,
        "advertisement_test": catalog_tests[0],
        "catalog_smoke_constructor": "MockBackend::with_official_mechanism_catalog_smoke",
        "catalog_smoke_workflow_test": catalog_tests[1],
        "catalog_smoke_workflows": MOCK_BACKEND_CORE_WORKFLOWS,
        "core_workflow_test": catalog_tests[1],
        "core_workflows": MOCK_BACKEND_CORE_WORKFLOWS,
        "exact_output_workflow_test": catalog_tests[2],
        "exact_output_workflows": MOCK_BACKEND_EXACT_OUTPUT_WORKFLOWS,
        "semantic_constructor": "MockBackend::with_official_mechanisms",
        "source_grounded_workflow_enforcement_test": MOCK_SOURCE_GROUNDED_WORKFLOW_ENFORCEMENT_TEST,
        "source_grounded_workflows": source_grounded_workflows,
        "workflow_semantics_status": workflow_semantics_status,
        "semantic_limitation": semantic_limitation,
        "local_tests": local_tests,
        "local_tests_missing": [
            test_name for test_name in local_tests if test_name not in rust_test_names
        ],
        "limitation": None,
    }


def expected_mechanism_info_flag_names(name: str, workflows: list[str]) -> list[str]:
    if name in MOCK_MECHANISM_INFO_FLAG_SOURCE_DISCREPANCY_REPLACEMENT_FLAGS:
        return sorted(MOCK_MECHANISM_INFO_FLAG_SOURCE_DISCREPANCY_REPLACEMENT_FLAGS[name])

    expected: set[str] = set()
    for workflow in workflows:
        if workflow == GENERATE_WORKFLOW:
            if name.endswith("_KEY_PAIR_GEN"):
                expected.add("CKF_GENERATE_KEY_PAIR")
            elif name.endswith("_KEY_GEN"):
                expected.add("CKF_GENERATE")
            else:
                expected.update(["CKF_GENERATE", "CKF_GENERATE_KEY_PAIR"])
            continue
        expected.update(WORKFLOW_MECHANISM_INFO_FLAGS.get(workflow, []))

    expected.update(MOCK_MECHANISM_INFO_FLAG_SOURCE_GROUNDED_FLAGS.get(name, []))
    return sorted(expected)


def source_grounded_workflow_names(expected_flag_names: list[str]) -> list[str]:
    flags = set(expected_flag_names)
    workflow_rules = [
        ("encrypt_decrypt", {"CKF_ENCRYPT", "CKF_DECRYPT"}),
        ("sign_verify", {"CKF_SIGN", "CKF_VERIFY"}),
        ("sign_recover_verify_recover", {"CKF_SIGN_RECOVER", "CKF_VERIFY_RECOVER"}),
        ("digest", {"CKF_DIGEST"}),
        ("wrap_unwrap", {"CKF_WRAP", "CKF_UNWRAP"}),
        ("derive", {"CKF_DERIVE"}),
        ("generate", {"CKF_GENERATE"}),
        ("generate_key_pair", {"CKF_GENERATE_KEY_PAIR"}),
        ("encapsulate_decapsulate", {"CKF_ENCAPSULATE", "CKF_DECAPSULATE"}),
        ("message_encrypt_decrypt", {"CKF_MESSAGE_ENCRYPT", "CKF_MESSAGE_DECRYPT"}),
        ("message_sign_verify", {"CKF_MESSAGE_SIGN", "CKF_MESSAGE_VERIFY"}),
    ]
    return [workflow for workflow, workflow_flags in workflow_rules if flags & workflow_flags]


def mechanism_info_source_gap_decision(
    spec_present: bool,
    spec_sources: list[str],
    official_source_headers: list[str],
    workflows: list[str],
) -> tuple[str | None, dict[str, Any] | None]:
    if spec_present and not workflows:
        kind = "working_markdown_mentions_mechanism_without_workflow_flags"
        reason = "working_markdown_mentions_mechanism_but_no_source_workflow_flags"
    elif not spec_present:
        kind = "published_header_only_no_working_markdown_workflow_source"
        reason = "published_header_mechanism_absent_from_working_markdown"
    else:
        kind = "source_workflows_have_no_mapped_ckf_flags"
        reason = "source_workflow_columns_do_not_map_to_ck_mechanism_info_flags"

    return (
        kind,
        {
            "policy": "do_not_infer_ckf_flags_from_mechanism_name_or_header_presence",
            "reason": reason,
            "compatibility_risk": "invented_ckf_flags_can_misroute_clients_to_unsupported_workflows",
            "evidence": sorted({*spec_sources, *official_source_headers}),
        },
    )


def mechanism_info_flag_coverage(
    name: str,
    official_inventory_present: bool,
    workflows: list[str],
    spec_present: bool,
    spec_sources: list[str],
    official_source_headers: list[str],
    rust_test_names: set[str],
) -> dict[str, Any]:
    if not official_inventory_present:
        return {
            "name": name,
            "source_workflows": workflows,
            "source_gap_kind": None,
            "source_gap_decision": None,
            "expected_flag_names": [],
            "status": "no_published_ck_mechanism_type_value",
            "unsupported_reason": "oasis_working_spec_lacks_published_numeric_value",
            "local_tests": [],
            "local_tests_missing": [],
        }

    expected_flags = expected_mechanism_info_flag_names(name, workflows)
    if not expected_flags:
        local_tests = MOCK_MECHANISM_INFO_NO_SOURCE_LOCAL_TESTS
        source_gap_kind, source_gap_decision = mechanism_info_source_gap_decision(
            spec_present, spec_sources, official_source_headers, workflows
        )
        return {
            "name": name,
            "source_workflows": workflows,
            "source_gap_kind": source_gap_kind,
            "source_gap_decision": source_gap_decision,
            "expected_flag_names": [],
            "status": "no_source_workflow_evidence",
            "unsupported_reason": "no_source_workflow_flags_available",
            "local_tests": local_tests,
            "local_tests_missing": [
                test_name for test_name in local_tests if test_name not in rust_test_names
            ],
        }

    local_tests = (
        [MOCK_MECHANISM_INFO_FLAG_LOCAL_TEST]
        if name in MOCK_MECHANISM_INFO_FLAG_SOURCE_GROUNDED_FLAGS
        or name in MOCK_MECHANISM_INFO_FLAG_SOURCE_DISCREPANCY_REPLACEMENT_FLAGS
        else []
    )
    status = "source_grounded" if local_tests else "not_yet_source_grounded"
    unsupported_reason = None if local_tests else "mock_mechanism_info_flags_not_yet_source_grounded"

    return {
        "name": name,
        "source_workflows": workflows,
        "source_gap_kind": None,
        "source_gap_decision": None,
        "expected_flag_names": expected_flags,
        "status": status,
        "unsupported_reason": unsupported_reason,
        "local_tests": local_tests,
        "local_tests_missing": [
            test_name for test_name in local_tests if test_name not in rust_test_names
        ],
    }


def mechanism_info_flag_coverage_summary(matrix: list[dict[str, Any]]) -> dict[str, Any]:
    source_gap_counts: dict[str, int] = {}
    for entry in matrix:
        kind = entry.get("source_gap_kind")
        if kind is not None:
            source_gap_counts[kind] = source_gap_counts.get(kind, 0) + 1

    return {
        "entry_count": len(matrix),
        "represented_expected_flag_count": sum(
            1
            for entry in matrix
            if entry["status"] in {"source_grounded", "not_yet_source_grounded"}
        ),
        "source_grounded_count": sum(
            1 for entry in matrix if entry["status"] == "source_grounded"
        ),
        "not_yet_source_grounded_count": sum(
            1 for entry in matrix if entry["status"] == "not_yet_source_grounded"
        ),
        "no_source_workflow_evidence_count": sum(
            1 for entry in matrix if entry["status"] == "no_source_workflow_evidence"
        ),
        "no_published_ck_mechanism_type_value_count": sum(
            1
            for entry in matrix
            if entry["status"] == "no_published_ck_mechanism_type_value"
        ),
        "no_source_gap_counts_by_kind": dict(sorted(source_gap_counts.items())),
    }


def canonical_parameter_struct(name: str) -> str:
    return name.removesuffix("_PTR")


def parse_oasis_header_parameter_struct_sources(root: Path) -> dict[str, set[str]]:
    parameter_struct_sources: dict[str, set[str]] = {}

    for _version, path in official_mechanism_headers(root):
        if not path.exists():
            raise SystemExit(f"vendored OASIS mechanism header not found: {path}")
        relative_display = (
            Path("../doc/oasis-tcs-pkcs11/published") / path.parent.name / path.name
        ).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for struct_name in PARAM_STRUCT_RE.findall(text):
            if struct_name == "CK_MECHANISM_PTR":
                continue
            parameter_struct_sources.setdefault(
                canonical_parameter_struct(struct_name), set()
            ).add(relative_display)

    return parameter_struct_sources


def parse_rust_mechanism_parameter_shapes(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    struct_to_pkcs11: dict[str, set[str]] = {}
    pending_doc_lines: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("///"):
            pending_doc_lines.append(stripped)
            continue
        if match := RUST_STRUCT_RE.match(stripped):
            rust_struct = match.group(1)
            pkcs11_structs = {
                canonical_parameter_struct(name)
                for doc_line in pending_doc_lines
                for name in PARAM_STRUCT_RE.findall(doc_line)
            }
            if pkcs11_structs:
                struct_to_pkcs11[rust_struct] = pkcs11_structs
            pending_doc_lines = []
            continue
        if stripped and not stripped.startswith("#["):
            pending_doc_lines = []

    variants: list[dict[str, Any]] = []
    in_enum = False
    for line in text.splitlines():
        stripped = line.strip()
        if RUST_MECHANISM_PARAM_ENUM_RE.match(stripped):
            in_enum = True
            continue
        if in_enum and stripped == "}":
            break
        if not in_enum:
            continue
        if match := RUST_ENUM_VARIANT_RE.match(stripped):
            rust_variant, rust_struct = match.groups()
            variants.append(
                {
                    "rust_variant": rust_variant,
                    "rust_struct": rust_struct,
                    "pkcs11_structs": sorted(struct_to_pkcs11.get(rust_struct, set())),
                }
            )

    return variants


def parse_proto_messages(paths: list[Path]) -> set[str]:
    messages: set[str] = set()
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if match := PROTO_MESSAGE_RE.match(line):
                messages.add(match.group(1))
    return messages


def parse_mechanism_proto_oneof(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    fields: dict[str, str] = {}
    in_mechanism = False
    in_oneof = False
    brace_depth = 0

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("message Mechanism"):
            in_mechanism = True
            brace_depth = stripped.count("{") - stripped.count("}")
            continue
        if not in_mechanism:
            continue

        brace_depth += stripped.count("{") - stripped.count("}")
        if stripped.startswith("oneof params"):
            in_oneof = True
            continue
        if in_oneof and stripped == "}":
            in_oneof = False
            continue
        if brace_depth <= 0:
            break
        if in_oneof and (match := PROTO_ONEOF_FIELD_RE.match(stripped)):
            message_name, field_name = match.groups()
            fields[message_name] = field_name

    return fields


def parse_message_parameter_proto_oneof(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    fields: dict[str, str] = {}
    in_message = False
    in_oneof = False
    brace_depth = 0

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("message MessageParameter"):
            in_message = True
            brace_depth = stripped.count("{") - stripped.count("}")
            continue
        if not in_message:
            continue

        brace_depth += stripped.count("{") - stripped.count("}")
        if stripped.startswith("oneof params"):
            in_oneof = True
            continue
        if in_oneof and stripped == "}":
            in_oneof = False
            continue
        if brace_depth <= 0:
            break
        if in_oneof and (match := PROTO_ONEOF_FIELD_RE.match(stripped)):
            message_name, field_name = match.groups()
            fields[message_name] = field_name

    return fields


def parse_ck_mechanism_param_variants(path: Path) -> set[str]:
    return set(CK_MECHANISM_PARAM_VARIANT_RE.findall(path.read_text(encoding="utf-8")))


def parse_writeback_variants(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    start = text.find("pub(crate) unsafe fn write_mechanism_output_params")
    if start == -1:
        return set()
    end = text.find("fn gcm_iv_write_capacity", start)
    if end == -1:
        end = len(text)
    return set(CK_MECHANISM_PARAM_VARIANT_RE.findall(text[start:end]))


def shim_read_decision(
    rust_variant: str,
    spec_sources: list[str],
    published_header_sources: list[str],
    shim_helper_source: str,
) -> dict[str, Any] | None:
    reason = PARAMETER_SHAPE_SHIM_READ_UNSUPPORTED_REASONS.get(rust_variant)
    if reason is None:
        return None
    evidence = sorted({*spec_sources, *published_header_sources, shim_helper_source})
    return {
        "policy": "do_not_parse_unbounded_caller_pointers_in_shim",
        "fallback": "preserve_raw_mechanism_params_for_proxying",
        "caller_visible_outcome": (
            "direct_shim_parameterized_calls_return_CKR_MECHANISM_PARAM_INVALID"
        ),
        "compatibility_risk": "typed_shim_read_would_require_guessing_pointer_lengths",
        "unsupported_reason": reason,
        "evidence": evidence,
        "local_tests": PARAMETER_SHAPE_SHIM_READ_DECISION_LOCAL_TESTS,
    }


def build_parameter_shape_matrix(
    root: Path,
    parameter_struct_sources: dict[str, set[str]],
    message_parameter_structs: set[str],
    published_parameter_struct_sources: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    spec_structs = {
        canonical_parameter_struct(name)
        for name in parameter_struct_sources
        if name.startswith("CK_")
    }
    source_map: dict[str, set[str]] = {}
    for name, sources in parameter_struct_sources.items():
        source_map.setdefault(canonical_parameter_struct(name), set()).update(sources)
    published_structs = set(published_parameter_struct_sources)

    rust_shapes = parse_rust_mechanism_parameter_shapes(mechanism_types_source(root))
    proto_messages = parse_proto_messages([mechanism_params_proto(root), types_proto(root)])
    proto_oneof_fields = parse_mechanism_proto_oneof(types_proto(root))
    backend_variants = parse_ck_mechanism_param_variants(backend_ffi_conversion(root))
    shim_variants = parse_ck_mechanism_param_variants(shim_helpers(root))
    writeback_variants = parse_writeback_variants(shim_helpers(root))
    shim_helper_source = shim_helpers(root).relative_to(root).as_posix()

    matrix: list[dict[str, Any]] = []
    modeled_spec_structs: set[str] = set()
    modeled_struct_variants: dict[str, str] = {}
    for shape in rust_shapes:
        rust_variant = shape["rust_variant"]
        rust_struct = shape["rust_struct"]
        pkcs11_structs = shape["pkcs11_structs"]
        modeled_spec_structs.update(pkcs11_structs)
        for pkcs11_struct in pkcs11_structs:
            modeled_struct_variants.setdefault(pkcs11_struct, rust_variant)
        spec_sources = sorted(
            {
                source
                for pkcs11_struct in pkcs11_structs
                for source in source_map.get(pkcs11_struct, set())
            }
        )
        published_header_sources = sorted(
            {
                source
                for pkcs11_struct in pkcs11_structs
                for source in published_parameter_struct_sources.get(pkcs11_struct, set())
            }
        )
        has_backend_ffi_conversion = (
            rust_variant in backend_variants
            and rust_variant not in BACKEND_FFI_UNSUPPORTED_PARAMETER_VARIANTS
        )
        local_shim_read_decision = shim_read_decision(
            rust_variant, spec_sources, published_header_sources, shim_helper_source
        )
        matrix.append(
            {
                "rust_variant": rust_variant,
                "rust_struct": rust_struct,
                "pkcs11_structs": pkcs11_structs,
                "spec_present": bool(set(pkcs11_structs) & spec_structs),
                "spec_sources": spec_sources,
                "published_header_present": bool(set(pkcs11_structs) & published_structs),
                "published_header_sources": published_header_sources,
                "proto_message": rust_struct if rust_struct in proto_messages else None,
                "proto_oneof_field": proto_oneof_fields.get(rust_struct),
                "backend_ffi_conversion": has_backend_ffi_conversion,
                "shim_read_support": rust_variant in shim_variants,
                "shim_read_unsupported_reason": (
                    PARAMETER_SHAPE_SHIM_READ_UNSUPPORTED_REASONS.get(rust_variant)
                ),
                "shim_read_decision": local_shim_read_decision,
                "shim_writeback_support": rust_variant in writeback_variants,
                "mutable_output_behavior": PARAMETER_SHAPE_OUTPUT_BEHAVIOR.get(
                    rust_variant, []
                ),
                "error_output_behavior": PARAMETER_SHAPE_ERROR_OUTPUT_BEHAVIOR.get(
                    rust_variant
                ),
                "nested_input_handles": PARAMETER_SHAPE_NESTED_INPUT_HANDLES.get(
                    rust_variant, []
                ),
                "nested_output_handles": rust_variant
                in {"Sp800108FeedbackKdf", "Sp800108Kdf"},
                "local_tests": PARAMETER_SHAPE_LOCAL_TESTS.get(rust_variant, []),
                "unsupported_reason": PARAMETER_SHAPE_UNSUPPORTED_REASONS.get(
                    rust_variant
                ),
            }
        )

    alias_rows = []
    for spec_struct, alias in sorted(PARAMETER_STRUCT_ALIASES.items()):
        modeled_as = alias["modeled_as"]
        if spec_struct in spec_structs and modeled_as in modeled_spec_structs:
            alias_rows.append(
                {
                    "spec_struct": spec_struct,
                    "modeled_as": modeled_as,
                    "rust_variant": modeled_struct_variants.get(modeled_as),
                    "reason": alias["reason"],
                }
            )
    aliased_spec_structs = {entry["spec_struct"] for entry in alias_rows}
    placeholder_rows = []
    for spec_struct, placeholder in sorted(PARAMETER_STRUCT_PLACEHOLDERS.items()):
        if spec_struct in spec_structs:
            placeholder_rows.append(
                {
                    "spec_struct": spec_struct,
                    "reason": placeholder["reason"],
                    "sources": sorted(source_map.get(spec_struct, set())),
                }
            )
    placeholder_spec_structs = {entry["spec_struct"] for entry in placeholder_rows}

    comparison = {
        "spec_parameter_struct_base_count": len(spec_structs),
        "modeled_parameter_shape_count": len(matrix),
        "spec_parameter_structs_missing_modeled_shape": sorted(
            spec_structs
            - modeled_spec_structs
            - message_parameter_structs
            - aliased_spec_structs
            - placeholder_spec_structs
        ),
        "spec_parameter_structs_modeled_as_message_parameters": sorted(
            spec_structs & message_parameter_structs
        ),
        "spec_parameter_structs_modeled_as_aliases": alias_rows,
        "spec_parameter_structs_excluded_placeholders": placeholder_rows,
        "modeled_pkcs11_structs_not_in_spec_parameter_structs": sorted(
            modeled_spec_structs - spec_structs
        ),
    }
    return matrix, comparison


def parse_message_parameter_shapes(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    struct_to_pkcs11: dict[str, str] = {}
    pending_doc_lines: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("///"):
            pending_doc_lines.append(stripped)
            continue
        if match := RUST_STRUCT_RE.match(stripped):
            rust_struct = match.group(1)
            pkcs11_structs = [
                canonical_parameter_struct(name)
                for doc_line in pending_doc_lines
                for name in PARAM_STRUCT_RE.findall(doc_line)
            ]
            if pkcs11_structs:
                struct_to_pkcs11[rust_struct] = pkcs11_structs[0]
            pending_doc_lines = []
            continue
        if stripped and not stripped.startswith("#["):
            pending_doc_lines = []

    variants: list[dict[str, Any]] = []
    in_enum = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("pub enum MessageParameter"):
            in_enum = True
            continue
        if in_enum and stripped == "}":
            break
        if not in_enum:
            continue
        if match := RUST_ENUM_VARIANT_RE.match(stripped):
            rust_variant, rust_struct = match.groups()
            if rust_variant == "Raw":
                continue
            variants.append(
                {
                    "rust_variant": rust_variant,
                    "rust_struct": rust_struct,
                    "pkcs11_struct": struct_to_pkcs11.get(rust_struct),
                }
            )

    return variants


def build_message_parameter_shape_matrix(
    root: Path, parameter_struct_sources: dict[str, set[str]]
) -> list[dict[str, Any]]:
    source_map: dict[str, set[str]] = {}
    for name, sources in parameter_struct_sources.items():
        source_map.setdefault(canonical_parameter_struct(name), set()).update(sources)

    rust_shapes = parse_message_parameter_shapes(message_params_source(root))
    proto_messages = parse_proto_messages([mechanism_params_proto(root), types_proto(root)])
    proto_oneof_fields = parse_message_parameter_proto_oneof(types_proto(root))
    message_ops_text = backend_ffi_message_ops(root).read_text(encoding="utf-8")
    shim_text = shim_helpers(root).read_text(encoding="utf-8")

    rows: list[dict[str, Any]] = []
    for shape in rust_shapes:
        rust_variant = shape["rust_variant"]
        rust_struct = shape["rust_struct"]
        pkcs11_struct = shape["pkcs11_struct"]
        read_helper, write_helper = MESSAGE_PARAMETER_READ_WRITE_HELPERS.get(
            rust_variant, ("", "")
        )
        rows.append(
            {
                "rust_variant": rust_variant,
                "rust_struct": rust_struct,
                "pkcs11_struct": pkcs11_struct,
                "spec_present": pkcs11_struct in source_map,
                "spec_sources": sorted(source_map.get(pkcs11_struct, set())),
                "proto_message": rust_struct if rust_struct in proto_messages else None,
                "proto_oneof_field": proto_oneof_fields.get(rust_struct),
                "backend_ffi_message_conversion": (
                    pkcs11_struct in message_ops_text
                    and f"MessageParameter::{rust_variant}" in message_ops_text
                ),
                "shim_read_support": read_helper in shim_text,
                "shim_writeback_support": write_helper in shim_text,
                "mutable_output_behavior": MESSAGE_PARAMETER_SHAPE_OUTPUT_BEHAVIOR.get(
                    rust_variant, []
                ),
                "local_tests": MESSAGE_PARAMETER_SHAPE_LOCAL_TESTS.get(rust_variant, []),
            }
        )

    return rows


def parse_rust_test_names(path: Path) -> set[str]:
    return {
        match.group(1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if (match := RUST_TEST_RE.match(line))
    }


def parse_all_rust_test_names(root: Path) -> set[str]:
    names: set[str] = set()
    for path in (root / "crates").rglob("*.rs"):
        names.update(parse_rust_test_names(path))
    return names


def add_local_tests_missing(rows: list[dict[str, Any]], rust_test_names: set[str]) -> None:
    for entry in rows:
        local_tests = entry.get("local_tests", [])
        entry["local_tests_missing"] = [
            test_name for test_name in local_tests if test_name not in rust_test_names
        ]


def build_interface_matrix(root: Path, rust_test_names: set[str]) -> list[dict[str, Any]]:
    probe = shim_interface_probe(root)
    tests = shim_interface_tests(root)
    probe_text = probe.read_text(encoding="utf-8")
    shim_test_names = parse_rust_test_names(tests)
    reserved_name_present = "IFACE_NAME_PKCS11" in probe_text and 'b"PKCS 11\\0"' in probe_text
    mock_backend_default_capability = (
        MOCK_BACKEND_INTERFACE_CAPABILITY_TEST in rust_test_names
    )

    rows: list[dict[str, Any]] = []
    for entry in STANDARD_INTERFACE_ENTRIES:
        shim_local_tests = entry["local_tests"]
        local_tests = [
            *shim_local_tests,
            MOCK_BACKEND_INTERFACE_CAPABILITY_TEST,
        ]
        rows.append(
            {
                "interface_name": entry["interface_name"],
                "version": entry["version"],
                "function_list_type": entry["function_list_type"],
                "default_interface": entry["default_interface"],
                "reserved_standard_name": True,
                "flags": [],
                "spec_sources": INTERFACE_SPEC_SOURCES,
                "shim_catalog_present": (
                    reserved_name_present
                    and entry["function_list_getter"] in probe_text
                    and all(test_name in shim_test_names for test_name in shim_local_tests)
                ),
                "mock_backend_default_capability": mock_backend_default_capability,
                "shim_sources": [
                    "crates/shim/src/interface_probe.rs",
                    "crates/shim/src/tests/interface.rs",
                ],
                "local_tests": local_tests,
            }
        )
    return rows


def function_local_tests(
    name: str, local_interface: dict[str, Any] | None, function_list_version: str | None
) -> list[str]:
    if local_interface is not None:
        return local_interface["local_tests"]

    tests: list[str] = []
    tests.extend(FUNCTION_PROXY_LAYER_TESTS)
    tests.extend(FUNCTION_LIST_TESTS_BY_VERSION.get(function_list_version, []))
    tests.extend(FUNCTION_SEMANTIC_LOCAL_TESTS.get(name, []))
    return sorted(dict.fromkeys(tests))


def build_mock_backend_default_trait_decisions(
    function_matrix: list[dict[str, Any]],
    trait_default_errors: dict[str, str],
    mock_impl_methods: set[str],
    rust_test_names: set[str],
) -> list[dict[str, Any]]:
    function_by_backend_method = {
        entry["backend_trait_method"]: entry
        for entry in function_matrix
        if entry["backend_trait_method"] is not None
    }
    rows: list[dict[str, Any]] = []

    for method, error in sorted(trait_default_errors.items()):
        if method in mock_impl_methods:
            continue
        function_entry = function_by_backend_method.get(method)
        if function_entry is None:
            continue

        local_tests = MOCK_BACKEND_DEFAULT_DECISION_LOCAL_TESTS.get(error, [])
        rows.append(
            {
                "backend_trait_method": method,
                "c_function": function_entry["name"],
                "spec_present": function_entry["spec_present"],
                "function_list_field": function_entry["function_list_field"],
                "returned_rv": f"CKR_{error}",
                "reason": MOCK_BACKEND_DEFAULT_DECISION_REASONS.get(
                    error, "unclassified_trait_default"
                ),
                "local_tests": local_tests,
                "local_tests_missing": [
                    test_name for test_name in local_tests if test_name not in rust_test_names
                ],
            }
        )

    return rows


def parse_official_mechanism_inventory(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = RUST_OFFICIAL_MECH_RE.search(line)
        if not match:
            continue
        raw_value, raw_names = match.groups()
        value = int(raw_value, 0)
        names = [
            name.strip()
            for name in raw_names.split("/")
            if MECHANISM_RE.fullmatch(name.strip())
            and is_official_mechanism_name(name.strip())
        ]
        entries.append(
            {
                "value": f"0x{value:08X}",
                "names": names,
            }
        )
    return entries


def parse_header_mechanism_values(path: Path) -> dict[str, int]:
    raw_defines: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = HEADER_MECH_DEFINE_RE.match(line)
        if not match:
            continue
        name, expression = match.groups()
        if not is_official_mechanism_name(name):
            continue
        raw_defines[name] = expression.strip()

    resolved: dict[str, int] = {}

    def resolve(name: str, seen: tuple[str, ...] = ()) -> int | None:
        if name in resolved:
            return resolved[name]
        expression = raw_defines.get(name)
        if expression is None:
            return None

        literal = re.match(r"^(0x[0-9A-Fa-f]+|[0-9]+)U?L?\b", expression)
        if literal:
            value = int(literal.group(1), 0)
            resolved[name] = value
            return value

        alias = re.match(r"^(CKM_[A-Z0-9_]+)\b", expression)
        if alias and alias.group(1) not in seen:
            value = resolve(alias.group(1), (*seen, name))
            if value is not None:
                resolved[name] = value
                return value

        return None

    for name in raw_defines:
        resolve(name)

    return resolved


def parse_header_mechanism_annotations(path: Path) -> dict[str, set[str]]:
    annotations: dict[str, set[str]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = HEADER_MECH_DEFINE_RE.match(line)
        if not match:
            continue
        name, _expression = match.groups()
        if not is_official_mechanism_name(name):
            continue
        line_annotations = set(HEADER_MECH_ANNOTATION_RE.findall(line))
        if line_annotations:
            annotations.setdefault(name, set()).update(line_annotations)
    return annotations


def parse_oasis_header_mechanism_inventory(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    by_value: dict[int, dict[str, Any]] = {}
    source_headers: list[str] = []

    for version, path in official_mechanism_headers(root):
        if not path.exists():
            raise SystemExit(f"vendored OASIS mechanism header not found: {path}")
        relative_display = (
            Path("../doc/oasis-tcs-pkcs11/published") / path.parent.name / path.name
        )
        source_headers.append(relative_display.as_posix())

        annotations = parse_header_mechanism_annotations(path)
        for name, value in parse_header_mechanism_values(path).items():
            entry = by_value.setdefault(
                value,
                {
                    "value": f"0x{value:08X}",
                    "names": set(),
                    "name_versions": {},
                    "name_header_annotations": {},
                    "source_versions": set(),
                    "source_headers": set(),
                },
            )
            entry["names"].add(name)
            entry["name_versions"].setdefault(name, version)
            if name in annotations:
                entry["name_header_annotations"].setdefault(name, set()).update(annotations[name])
            entry["source_versions"].add(version)
            entry["source_headers"].add(relative_display.as_posix())

    entries: list[dict[str, Any]] = []
    version_order = {version: index for index, (version, _) in enumerate(PUBLISHED_HEADER_VERSIONS)}
    for value, raw_entry in sorted(by_value.items()):
        source_versions = sorted(
            raw_entry["source_versions"], key=lambda item: version_order.get(item, 999)
        )
        entries.append(
            {
                "value": f"0x{value:08X}",
                "names": sorted(raw_entry["names"]),
                "name_versions": dict(sorted(raw_entry["name_versions"].items())),
                "name_header_annotations": {
                    name: sorted(annotations)
                    for name, annotations in sorted(
                        raw_entry["name_header_annotations"].items()
                    )
                },
                "header_annotations": sorted(
                    {
                        annotation
                        for annotations in raw_entry["name_header_annotations"].values()
                        for annotation in annotations
                    }
                ),
                "version_introduced": source_versions[0] if source_versions else None,
                "source_versions": source_versions,
                "source_headers": sorted(raw_entry["source_headers"]),
            }
        )

    return entries, source_headers


def compare_mechanism_inventories(
    oasis_inventory: list[dict[str, Any]], rust_inventory: list[dict[str, Any]]
) -> dict[str, Any]:
    oasis_values = {entry["value"] for entry in oasis_inventory}
    rust_values = {entry["value"] for entry in rust_inventory}
    oasis_names = {
        name for entry in oasis_inventory for name in entry["names"] if name.startswith("CKM_")
    }
    rust_names = {
        name for entry in rust_inventory for name in entry["names"] if name.startswith("CKM_")
    }

    oasis_values_missing_from_rust = sorted(oasis_values - rust_values)
    rust_values_missing_from_oasis_headers = sorted(rust_values - oasis_values)
    oasis_names_missing_from_rust = sorted(oasis_names - rust_names)
    rust_names_missing_from_oasis_headers = sorted(rust_names - oasis_names)

    return {
        "matches": not (
            oasis_values_missing_from_rust
            or rust_values_missing_from_oasis_headers
            or oasis_names_missing_from_rust
            or rust_names_missing_from_oasis_headers
        ),
        "oasis_values_missing_from_rust": oasis_values_missing_from_rust,
        "rust_values_missing_from_oasis_headers": rust_values_missing_from_oasis_headers,
        "oasis_names_missing_from_rust": oasis_names_missing_from_rust,
        "rust_names_missing_from_oasis_headers": rust_names_missing_from_oasis_headers,
    }


def parse_provider_coverage(root: Path) -> dict[str, Any]:
    artifacts = provider_artifacts_root(root)
    coverage_files = sorted(artifacts.glob("*/coverage.json")) if artifacts.exists() else []
    advertised_mechanisms: set[str] = set()
    providers: list[str] = []

    for path in coverage_files:
        providers.append(path.parent.name)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        stack: list[Any] = [data]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, str) and MECHANISM_RE.fullmatch(value):
                advertised_mechanisms.add(value)

    return {
        "artifacts_dir": str(artifacts),
        "coverage_file_count": len(coverage_files),
        "providers": providers,
        "advertised_mechanism_names": sorted(advertised_mechanisms),
    }


def provider_mechanism_summary(
    mechanism_matrix: list[dict[str, Any]], official_mechanism_value_count: int
) -> dict[str, Any]:
    official_entries = [
        entry for entry in mechanism_matrix if entry["official_inventory_present"]
    ]
    provider_present = [
        entry for entry in official_entries if entry["provider_artifact_present"]
    ]
    provider_gaps = [entry for entry in official_entries if entry["provider_gap"]]

    return {
        "official_mechanism_value_count": official_mechanism_value_count,
        "official_mechanism_name_count": len(official_entries),
        "provider_artifact_present_count": len(provider_present),
        "provider_gap_count": len(provider_gaps),
        "provider_artifact_present_names": sorted(
            entry["name"] for entry in provider_present
        ),
        "provider_gap_names": sorted(entry["name"] for entry in provider_gaps),
    }


def completion_gap_summary(
    function_matrix: list[dict[str, Any]],
    parameter_shape_matrix: list[dict[str, Any]],
    message_parameter_shape_matrix: list[dict[str, Any]],
    mechanism_info_flag_coverage_matrix: list[dict[str, Any]],
    mechanism_matrix: list[dict[str, Any]],
    parameter_shape_comparison: dict[str, Any],
    provider_summary: dict[str, Any],
    flag_summary: dict[str, Any],
) -> dict[str, Any]:
    def missing_local_test_count(rows: list[dict[str, Any]]) -> int:
        return sum(1 for entry in rows if entry.get("local_tests_missing"))

    def row_name(entry: dict[str, Any]) -> str:
        return (
            entry.get("name")
            or entry.get("rust_variant")
            or entry.get("pkcs11_struct")
            or "/".join(entry.get("pkcs11_structs", []))
            or "<unnamed>"
        )

    def missing_local_test_names(rows: list[dict[str, Any]]) -> list[str]:
        return sorted(row_name(entry) for entry in rows if entry.get("local_tests_missing"))

    mock_missing_count = sum(
        1
        for entry in mechanism_matrix
        if entry["mock_backend_internal_coverage"].get("local_tests_missing")
    )
    mock_missing_names = sorted(
        entry["name"]
        for entry in mechanism_matrix
        if entry["mock_backend_internal_coverage"].get("local_tests_missing")
    )
    semantic_status_counts: dict[str, int] = {}
    for entry in mechanism_matrix:
        status = entry["mock_backend_internal_coverage"]["workflow_semantics_status"]
        semantic_status_counts[status] = semantic_status_counts.get(status, 0) + 1

    missing_local_test_citation_counts = {
        "function_matrix": missing_local_test_count(function_matrix),
        "mechanism_parameter_shape_matrix": missing_local_test_count(
            parameter_shape_matrix
        ),
        "message_parameter_shape_matrix": missing_local_test_count(
            message_parameter_shape_matrix
        ),
        "mechanism_info_flag_coverage_matrix": missing_local_test_count(
            mechanism_info_flag_coverage_matrix
        ),
        "mock_backend_internal_coverage": mock_missing_count,
    }
    spec_only_function_list_gap_names = sorted(
        entry["name"] for entry in function_matrix if entry["status"] == "spec_only"
    )
    working_spec_mechanisms_without_published_values = sorted(
        entry["name"]
        for entry in mechanism_matrix
        if entry["unsupported_reason"] == "oasis_working_spec_lacks_published_numeric_value"
    )
    no_source_workflow_rejection_names = sorted(
        entry["name"]
        for entry in mechanism_matrix
        if entry["mock_backend_internal_coverage"]["workflow_semantics_status"]
        == "no_source_workflow_evidence"
    )
    actionable_mockbackend_semantic_gap_names = sorted(
        entry["name"]
        for entry in mechanism_matrix
        if entry["mock_backend_internal_coverage"]["workflow_semantics_status"]
        == "not_yet_source_grounded"
    )
    not_yet_source_grounded_mechanism_info_flag_names = sorted(
        entry["name"]
        for entry in mechanism_info_flag_coverage_matrix
        if entry["status"] == "not_yet_source_grounded"
    )
    missing_local_test_citation_names = {
        "function_matrix": missing_local_test_names(function_matrix),
        "mechanism_parameter_shape_matrix": missing_local_test_names(
            parameter_shape_matrix
        ),
        "message_parameter_shape_matrix": missing_local_test_names(
            message_parameter_shape_matrix
        ),
        "mechanism_info_flag_coverage_matrix": missing_local_test_names(
            mechanism_info_flag_coverage_matrix
        ),
        "mock_backend_internal_coverage": mock_missing_names,
    }
    strict_completion_open_item_counts = {
        "provider_artifact_gaps": provider_summary["provider_gap_count"],
        "spec_parameter_structs_missing_modeled_shape": len(
            parameter_shape_comparison["spec_parameter_structs_missing_modeled_shape"]
        ),
        "missing_local_test_citations": sum(missing_local_test_citation_counts.values()),
        "actionable_mockbackend_semantic_gaps": semantic_status_counts.get(
            "not_yet_source_grounded", 0
        ),
        "not_yet_source_grounded_mechanism_info_flags": flag_summary[
            "not_yet_source_grounded_count"
        ],
    }
    internal_completion_open_item_count = sum(
        count
        for name, count in strict_completion_open_item_counts.items()
        if name != "provider_artifact_gaps"
    )

    return {
        "missing_local_test_citation_counts": missing_local_test_citation_counts,
        "intentional_unsupported_function_list_gap_names": spec_only_function_list_gap_names,
        "intentional_unsupported_function_list_gap_count": len(
            spec_only_function_list_gap_names
        ),
        "intentional_unsupported_numeric_value_gap_names": (
            working_spec_mechanisms_without_published_values
        ),
        "intentional_unsupported_numeric_value_gap_count": len(
            working_spec_mechanisms_without_published_values
        ),
        "intentional_no_source_workflow_rejection_names": (
            no_source_workflow_rejection_names
        ),
        "intentional_unsupported_workflow_gap_names": no_source_workflow_rejection_names,
        "intentional_unsupported_workflow_gap_count": len(
            no_source_workflow_rejection_names
        ),
        "strict_completion_open_items": {
            "provider_artifact_gaps": provider_summary["provider_gap_names"],
            "spec_parameter_structs_missing_modeled_shape": parameter_shape_comparison[
                "spec_parameter_structs_missing_modeled_shape"
            ],
            "missing_local_test_citations": missing_local_test_citation_names,
            "actionable_mockbackend_semantic_gaps": (
                actionable_mockbackend_semantic_gap_names
            ),
            "not_yet_source_grounded_mechanism_info_flags": (
                not_yet_source_grounded_mechanism_info_flag_names
            ),
        },
        "strict_completion_open_item_counts": strict_completion_open_item_counts,
        "internal_completion_open_item_count": internal_completion_open_item_count,
        "strict_completion_open_item_count": internal_completion_open_item_count
        + strict_completion_open_item_counts["provider_artifact_gaps"],
        "spec_only_function_list_gap_names": spec_only_function_list_gap_names,
        "working_spec_mechanisms_without_published_values": (
            working_spec_mechanisms_without_published_values
        ),
        "no_source_workflow_evidence_count": flag_summary[
            "no_source_workflow_evidence_count"
        ],
        "no_source_workflow_gap_counts_by_kind": flag_summary[
            "no_source_gap_counts_by_kind"
        ],
        "source_grounded_mockbackend_semantic_covered_count": semantic_status_counts.get(
            "source_grounded", 0
        ),
        "actionable_mockbackend_semantic_gap_count": semantic_status_counts.get(
            "not_yet_source_grounded", 0
        ),
        "intentional_no_source_workflow_rejection_count": semantic_status_counts.get(
            "no_source_workflow_evidence", 0
        ),
        "no_published_value_mechanism_count": semantic_status_counts.get(
            "no_published_ck_mechanism_type_value", 0
        ),
        "not_yet_source_grounded_mechanism_info_flag_count": flag_summary[
            "not_yet_source_grounded_count"
        ],
        "provider_gap_count": provider_summary["provider_gap_count"],
        "spec_parameter_structs_missing_modeled_shape": parameter_shape_comparison[
            "spec_parameter_structs_missing_modeled_shape"
        ],
        "spec_parameter_structs_missing_modeled_shape_count": len(
            parameter_shape_comparison["spec_parameter_structs_missing_modeled_shape"]
        ),
    }


def build_inventory() -> dict[str, Any]:
    root = repo_root()
    spec_dir = spec_root(root)
    if not spec_dir.exists():
        raise SystemExit(f"vendored OASIS spec directory not found: {spec_dir}")

    spec_functions, spec_mechanisms, parameter_struct_sources = parse_spec_functions_and_mechanisms(
        spec_dir
    )
    published_parameter_struct_sources = parse_oasis_header_parameter_struct_sources(root)
    function_fields = parse_function_list_fields(function_field_tables(root))
    published_functions, official_function_headers_source = parse_oasis_header_function_inventory(
        root
    )
    function_field_comparison = compare_function_fields(published_functions, function_fields)
    published_functions_by_name = {entry["name"]: entry for entry in published_functions}
    proto_rpcs = parse_proto_rpcs(service_proto(root))
    backend_methods = parse_backend_trait_methods(backend_traits(root))
    trait_default_errors = parse_backend_trait_default_error_methods(backend_traits(root))
    mock_impl_methods = parse_mock_backend_impl_methods(mock_backend_source(root))
    client_methods = parse_client_methods(client_source_root(root))
    shim_dispatch = parse_shim_dispatch_functions(shim_dispatch_root(root))
    shim_root_entrypoints = parse_shim_root_entrypoints(shim_lib(root))
    rust_test_names = parse_all_rust_test_names(root)
    official_inventory, official_headers = parse_oasis_header_mechanism_inventory(root)
    rust_official_inventory = parse_official_mechanism_inventory(official_mechanism_rust(root))
    official_inventory_comparison = compare_mechanism_inventories(
        official_inventory, rust_official_inventory
    )
    interface_matrix = build_interface_matrix(root, rust_test_names)
    message_parameter_shape_matrix = build_message_parameter_shape_matrix(
        root, parameter_struct_sources
    )
    parameter_shape_matrix, parameter_shape_comparison = build_parameter_shape_matrix(
        root,
        parameter_struct_sources,
        {
            entry["pkcs11_struct"]
            for entry in message_parameter_shape_matrix
            if entry["pkcs11_struct"] is not None
        },
        published_parameter_struct_sources,
    )
    add_local_tests_missing(message_parameter_shape_matrix, rust_test_names)
    add_local_tests_missing(parameter_shape_matrix, rust_test_names)
    official_names = {
        name for entry in official_inventory for name in entry["names"] if name.startswith("CKM_")
    }
    official_by_name = {
        name: entry
        for entry in official_inventory
        for name in entry["names"]
        if name.startswith("CKM_")
    }
    provider = parse_provider_coverage(root)
    provider_names = set(provider["advertised_mechanism_names"])

    spec_function_names = set(spec_functions)
    function_field_names = set(function_fields)
    spec_mechanism_names = set(spec_mechanisms)

    function_matrix = []
    function_field_table_source = function_field_tables(root).relative_to(root).as_posix()
    for name in sorted(spec_function_names | function_field_names):
        snake = c_function_to_snake(name)
        shim_fn = f"c_{snake}"
        local_interface = SHIM_LOCAL_INTERFACE_FUNCTIONS.get(name)
        spec_present = name in spec_function_names
        function_list_field = name in function_field_names
        published_function_entry = published_functions_by_name.get(name)
        local_abi_decision = spec_only_function_abi_decision(
            name,
            spec_present,
            function_list_field,
            official_function_headers_source,
            function_field_table_source,
        )
        local_tests = (
            function_local_tests(name, local_interface, function_fields.get(name))
            if spec_present and function_list_field
            else local_abi_decision["local_tests"]
            if local_abi_decision is not None
            else []
        )
        function_matrix.append(
            {
                "name": name,
                "spec_present": spec_present,
                "spec_sources": sorted(spec_functions.get(name, FunctionEntry(name)).sources),
                "published_function_list_present": published_function_entry is not None,
                "published_function_version_introduced": (
                    published_function_entry["version_introduced"]
                    if published_function_entry
                    else None
                ),
                "published_function_source_versions": (
                    published_function_entry["source_versions"]
                    if published_function_entry
                    else []
                ),
                "function_list_field": function_list_field,
                "function_list_version": function_fields.get(name),
                "proto_rpc": match_proto_rpc(name, proto_rpcs),
                "backend_trait_method": snake if snake in backend_methods else None,
                "client_method": snake if snake in client_methods else None,
                "shim_dispatch_function": shim_fn if shim_fn in shim_dispatch else None,
                "shim_entrypoint_function": (
                    name
                    if local_interface is not None and name in shim_root_entrypoints
                    else None
                ),
                "local_abi_reason": (
                    local_interface["reason"] if local_interface is not None else None
                ),
                "local_abi_decision": local_abi_decision,
                "local_tests": local_tests,
                "local_tests_missing": [
                    test_name for test_name in local_tests if test_name not in rust_test_names
                ],
                "unsupported_reason": unsupported_function_reason(
                    name, spec_present, function_list_field
                ),
                "status": (
                    "represented"
                    if spec_present and function_list_field
                    else "spec_only"
                    if spec_present
                    else "implementation_only"
                ),
            }
        )

    mock_backend_default_trait_decisions = build_mock_backend_default_trait_decisions(
        function_matrix,
        trait_default_errors,
        mock_impl_methods,
        rust_test_names,
    )

    mechanism_matrix = []
    mechanism_info_flag_coverage_matrix = []
    for name in sorted(spec_mechanism_names | official_names):
        entry = spec_mechanisms.get(name, MechanismEntry(name))
        official_entry = official_by_name.get(name)
        official_inventory_present = name in official_names
        spec_sources = sorted(entry.sources)
        workflows = sorted(entry.workflows)
        mechanism_info_flags = mechanism_info_flag_coverage(
            name,
            official_inventory_present,
            workflows,
            name in spec_mechanism_names,
            spec_sources,
            official_entry["source_headers"] if official_entry else [],
            rust_test_names,
        )
        mechanism_info_flag_coverage_matrix.append(mechanism_info_flags)
        mechanism_matrix.append(
            {
                "name": name,
                "spec_present": name in spec_mechanism_names,
                "spec_sources": spec_sources,
                "workflows": workflows,
                "parameter_structs": sorted(entry.parameter_structs),
                "official_inventory_present": official_inventory_present,
                "value": official_entry["value"] if official_entry else None,
                "aliases": official_entry["names"] if official_entry else [],
                "version_introduced": (
                    official_entry["version_introduced"] if official_entry else None
                ),
                "name_version_introduced": (
                    official_entry["name_versions"].get(name) if official_entry else None
                ),
                "header_annotations": (
                    official_entry["name_header_annotations"].get(name, [])
                    if official_entry
                    else []
                ),
                "official_source_versions": (
                    official_entry["source_versions"] if official_entry else []
                ),
                "provider_artifact_present": name in provider_names,
                "provider_gap": official_inventory_present and name not in provider_names,
                "mock_backend_internal_coverage": mock_backend_internal_coverage(
                    official_inventory_present, mechanism_info_flags, rust_test_names
                ),
                "unsupported_reason": unsupported_mechanism_reason(
                    name, name in spec_mechanism_names, official_inventory_present
                ),
                "source_discrepancy_reason": mechanism_source_discrepancy_reason(
                    name, name in spec_mechanism_names, official_inventory_present
                ),
                "local_numeric_decision": mechanism_numeric_decision(
                    name,
                    name in spec_mechanism_names,
                    official_inventory_present,
                    spec_sources,
                    official_headers,
                    rust_test_names,
                ),
                "status": (
                    "represented"
                    if official_inventory_present
                    else "spec_only"
                    if name in spec_mechanism_names
                    else "implementation_only"
                ),
            }
        )

    flag_summary = mechanism_info_flag_coverage_summary(mechanism_info_flag_coverage_matrix)
    provider_summary = provider_mechanism_summary(mechanism_matrix, len(official_inventory))

    return {
        "source": {
            "repo_root": str(root),
            "spec_dir": str(spec_dir),
            "spec_markdown_file_count": len(list(spec_dir.glob("*.md"))),
            "official_function_headers": official_function_headers_source,
            "function_field_tables": str(function_field_tables(root)),
            "official_mechanism_headers": official_headers,
            "rust_official_mechanism_inventory": str(official_mechanism_rust(root)),
            "mock_backend_source": str(mock_backend_source(root)),
            "interface_spec_sources": INTERFACE_SPEC_SOURCES,
            "interface_shim_sources": [
                "crates/shim/src/lib.rs",
                "crates/shim/src/interface_probe.rs",
                "crates/shim/src/tests/interface.rs",
            ],
            "mechanism_types_source": str(mechanism_types_source(root)),
            "mechanism_params_proto": str(mechanism_params_proto(root)),
            "message_params_source": str(message_params_source(root)),
            "types_proto": str(types_proto(root)),
            "backend_ffi_conversion": str(backend_ffi_conversion(root)),
            "backend_ffi_message_ops": str(backend_ffi_message_ops(root)),
            "shim_helpers": str(shim_helpers(root)),
        },
        "implementation_layer_counts": {
            "proto_rpcs": len(proto_rpcs),
            "backend_trait_methods": len(backend_methods),
            "client_methods": len(client_methods),
            "shim_dispatch_functions": len(shim_dispatch),
            "shim_root_entrypoints": len(shim_root_entrypoints),
        },
        "interface_catalog_entry_count": len(interface_matrix),
        "interface_matrix": interface_matrix,
        "mechanism_parameter_shape_count": len(parameter_shape_matrix),
        "spec_parameter_struct_base_count": parameter_shape_comparison[
            "spec_parameter_struct_base_count"
        ],
        "mechanism_parameter_shape_matrix": parameter_shape_matrix,
        "mechanism_parameter_struct_comparison": parameter_shape_comparison,
        "message_parameter_shape_count": len(message_parameter_shape_matrix),
        "message_parameter_shape_matrix": message_parameter_shape_matrix,
        "spec_function_count": len(spec_function_names),
        "spec_functions": sorted_names(spec_functions),
        "function_list_field_count": len(function_field_names),
        "function_list_fields": sorted_names(function_fields),
        "published_function_inventory_count": len(published_functions),
        "published_function_inventory_entries": published_functions,
        "function_list_field_comparison": function_field_comparison,
        "spec_functions_missing_from_function_lists": sorted(
            spec_function_names - function_field_names
        ),
        "function_list_fields_not_in_spec_functions": sorted(
            function_field_names - spec_function_names
        ),
        "mock_backend_default_trait_decisions": mock_backend_default_trait_decisions,
        "spec_mechanism_count": len(spec_mechanism_names),
        "spec_mechanisms": sorted_names(spec_mechanisms),
        "official_mechanism_inventory_count": len(official_inventory),
        "official_mechanism_inventory_entries": official_inventory,
        "rust_official_mechanism_inventory_count": len(rust_official_inventory),
        "rust_official_mechanism_inventory_entries": rust_official_inventory,
        "rust_official_mechanism_inventory_comparison": official_inventory_comparison,
        "spec_mechanisms_missing_from_official_inventory_by_name": sorted(
            spec_mechanism_names - official_names
        ),
        "official_mechanisms_missing_from_spec_markdown_by_name": sorted(
            official_names - spec_mechanism_names
        ),
        "parameter_structs": [
            {"name": name, "sources": sorted(sources)}
            for name, sources in sorted(parameter_struct_sources.items())
        ],
        "mechanism_info_flag_coverage_summary": flag_summary,
        "mechanism_info_flag_coverage_matrix": mechanism_info_flag_coverage_matrix,
        "function_matrix": function_matrix,
        "mechanism_matrix": mechanism_matrix,
        "provider_mechanism_summary": provider_summary,
        "completion_gap_summary": completion_gap_summary(
            function_matrix,
            parameter_shape_matrix,
            message_parameter_shape_matrix,
            mechanism_info_flag_coverage_matrix,
            mechanism_matrix,
            parameter_shape_comparison,
            provider_summary,
            flag_summary,
        ),
        "provider_artifact_evidence": provider,
    }


def print_markdown(inventory: dict[str, Any]) -> None:
    def display(value: Any) -> str:
        if value is None or value == []:
            return "-"
        if isinstance(value, list):
            return ", ".join(f"`{item}`" for item in value) if value else "-"
        if isinstance(value, bool):
            return "yes" if value else "no"
        return str(value)

    print("# OASIS PKCS#11 Coverage Inventory")
    print()
    print(f"- Spec Markdown files: {inventory['source']['spec_markdown_file_count']}")
    print(f"- Spec functions: {inventory['spec_function_count']}")
    print(f"- Function-list fields: {inventory['function_list_field_count']}")
    print(f"- Standard interface catalog entries: {inventory['interface_catalog_entry_count']}")
    print(
        "- Modeled mechanism parameter shapes: "
        f"{inventory['mechanism_parameter_shape_count']}"
    )
    print(
        "- Spec mechanism parameter structs: "
        f"{inventory['spec_parameter_struct_base_count']}"
    )
    print(f"- Message parameter shapes: {inventory['message_parameter_shape_count']}")
    print(
        "- Official mechanism inventory entries: "
        f"{inventory['official_mechanism_inventory_count']}"
    )
    provider = inventory["provider_artifact_evidence"]
    print(f"- pkcs11-check coverage files: {provider['coverage_file_count']}")
    provider_summary = inventory["provider_mechanism_summary"]
    print(
        "- Official mechanism values from published headers: "
        f"{provider_summary['official_mechanism_value_count']}"
    )
    print(
        "- Official mechanism names/aliases in matrix: "
        f"{provider_summary['official_mechanism_name_count']}"
    )
    print(
        "- Official mechanism names/aliases with provider artifact coverage: "
        f"{provider_summary['provider_artifact_present_count']}"
    )
    print(
        "- Official mechanism names/aliases absent from provider artifacts: "
        f"{provider_summary['provider_gap_count']}"
    )
    completion_summary = inventory["completion_gap_summary"]
    missing_tests = completion_summary["missing_local_test_citation_counts"]
    print()
    print("## Completion Gap Summary")
    print()
    print(
        "- Spec-only function-list gap functions: "
        f"{len(completion_summary['spec_only_function_list_gap_names'])}"
    )
    print(
        "- Working-spec mechanisms without published CK_MECHANISM_TYPE values: "
        f"{len(completion_summary['working_spec_mechanisms_without_published_values'])}"
    )
    print(
        "- Spec parameter structs missing modeled shape: "
        f"{completion_summary['spec_parameter_structs_missing_modeled_shape_count']}"
    )
    print(
        "- Source-grounded MockBackend semantic rows covered: "
        f"{completion_summary['source_grounded_mockbackend_semantic_covered_count']}"
    )
    print(
        "- Actionable MockBackend semantic gaps: "
        f"{completion_summary['actionable_mockbackend_semantic_gap_count']}"
    )
    print(
        "- Intentional no-source workflow rejections: "
        f"{completion_summary['intentional_no_source_workflow_rejection_count']}"
    )
    print(
        "- Intentional unsupported workflow gaps: "
        f"{completion_summary['intentional_unsupported_workflow_gap_count']}"
    )
    print(
        "- No-published-value mechanism rows: "
        f"{completion_summary['no_published_value_mechanism_count']}"
    )
    print(
        "- Intentional unsupported function-list gaps: "
        f"{completion_summary['intentional_unsupported_function_list_gap_count']}"
    )
    print(
        "- Intentional unsupported numeric-value gaps: "
        f"{completion_summary['intentional_unsupported_numeric_value_gap_count']}"
    )
    print(
        "- Internal completion open items: "
        f"{completion_summary['internal_completion_open_item_count']}"
    )
    print(
        "- Strict completion open items including provider gaps: "
        f"{completion_summary['strict_completion_open_item_count']}"
    )
    open_counts = completion_summary["strict_completion_open_item_counts"]
    print(
        "- Strict open item classes: "
        f"provider_artifact_gaps:{open_counts['provider_artifact_gaps']}, "
        "spec_parameter_structs_missing_modeled_shape:"
        f"{open_counts['spec_parameter_structs_missing_modeled_shape']}, "
        f"missing_local_test_citations:{open_counts['missing_local_test_citations']}, "
        "actionable_mockbackend_semantic_gaps:"
        f"{open_counts['actionable_mockbackend_semantic_gaps']}, "
        "not_yet_source_grounded_mechanism_info_flags:"
        f"{open_counts['not_yet_source_grounded_mechanism_info_flags']}"
    )
    print(
        "- Local-test citation gaps: "
        f"function_matrix={missing_tests['function_matrix']}, "
        f"mechanism_parameter_shape_matrix={missing_tests['mechanism_parameter_shape_matrix']}, "
        f"message_parameter_shape_matrix={missing_tests['message_parameter_shape_matrix']}, "
        "mechanism_info_flag_coverage_matrix="
        f"{missing_tests['mechanism_info_flag_coverage_matrix']}, "
        f"mock_backend_internal_coverage={missing_tests['mock_backend_internal_coverage']}"
    )
    print()
    print("## Spec Functions Missing From Function Lists")
    missing = inventory["spec_functions_missing_from_function_lists"]
    if missing:
        for name in missing:
            print(f"- `{name}`")
    else:
        print("- none")
    print()
    print("## Function List Fields Not Found As Spec Headings")
    extra = inventory["function_list_fields_not_in_spec_functions"]
    if extra:
        for name in extra:
            print(f"- `{name}`")
    else:
        print("- none")
    print()
    print("## Spec-Only Function ABI Decisions")
    print()
    decisions = [
        entry
        for entry in inventory["function_matrix"]
        if entry["status"] == "spec_only" and entry["unsupported_reason"] is not None
    ]
    if decisions:
        print("| Function | Reason | Policy | Evidence |")
        print("| --- | --- | --- | --- |")
        for entry in decisions:
            decision = entry["local_abi_decision"] or {}
            print(
                f"| {entry['name']} | {entry['unsupported_reason']} | "
                f"{display(decision.get('policy'))} | "
                f"{display(decision.get('evidence'))} |"
            )
    else:
        print("- none")
    print()
    print("## MockBackend Inherited Trait Defaults")
    print()
    decisions = inventory["mock_backend_default_trait_decisions"]
    if decisions:
        print("| Function | Backend Method | Return | Reason | Local Tests |")
        print("| --- | --- | --- | --- | --- |")
        for entry in decisions:
            print(
                f"| {entry['c_function']} | {entry['backend_trait_method']} | "
                f"{entry['returned_rv']} | {entry['reason']} | "
                f"{display(entry['local_tests'])} |"
            )
    else:
        print("- none")
    print()
    print("## Function Matrix")
    print()
    print(
        "| Function | Status | Function List | Published Header | Introduced | "
        "Proto | Backend | Client | Shim Dispatch | Shim Entrypoint | Local ABI | Local Tests |"
    )
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for entry in inventory["function_matrix"]:
        function_list = (
            f"yes ({entry['function_list_version']})"
            if entry["function_list_field"]
            else "no"
        )
        print(
            f"| {entry['name']} | {entry['status']} | {function_list} | "
            f"{display(entry['published_function_list_present'])} | "
            f"{display(entry['published_function_version_introduced'])} | "
            f"{display(entry['proto_rpc'])} | {display(entry['backend_trait_method'])} | "
            f"{display(entry['client_method'])} | {display(entry['shim_dispatch_function'])} |"
            f" {display(entry['shim_entrypoint_function'])} | "
            f"{display(entry['local_abi_reason'])} | {display(entry['local_tests'])} |"
        )
    print()
    print("## Interface Matrix")
    print()
    print(
        "| Interface | Version | Function List Type | Default | Shim Catalog | "
        "MockBackend Default | Tests |"
    )
    print("| --- | --- | --- | --- | --- | --- | --- |")
    for entry in inventory["interface_matrix"]:
        print(
            f"| {entry['interface_name']} | {entry['version']} | "
            f"{entry['function_list_type']} | {display(entry['default_interface'])} | "
            f"{display(entry['shim_catalog_present'])} | "
            f"{display(entry['mock_backend_default_capability'])} | "
            f"{display(entry['local_tests'])} |"
        )
    print()
    print("## Mechanism Parameter Shape Matrix")
    print()
    print(
        "| Rust Variant | Rust Struct | PKCS#11 Structs | Spec | Published Header | Proto | Oneof | "
        "Backend FFI | Shim Read | Shim Read Unsupported Reason | Shim Read Decision | "
        "Shim Writeback | Mutable Output | Error Output | Unsupported Reason |"
    )
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for entry in inventory["mechanism_parameter_shape_matrix"]:
        decision = entry["shim_read_decision"] or {}
        error_output = entry["error_output_behavior"] or {}
        error_output_summary = (
            f"{error_output.get('current_support')}: {error_output.get('reason')}"
            if error_output
            else None
        )
        print(
            f"| {entry['rust_variant']} | {entry['rust_struct']} | "
            f"{display(entry['pkcs11_structs'])} | {display(entry['spec_present'])} | "
            f"{display(entry['published_header_present'])} | "
            f"{display(entry['proto_message'])} | {display(entry['proto_oneof_field'])} | "
            f"{display(entry['backend_ffi_conversion'])} | "
            f"{display(entry['shim_read_support'])} | "
            f"{display(entry['shim_read_unsupported_reason'])} | "
            f"{display(decision.get('policy'))} | "
            f"{display(entry['shim_writeback_support'])} | "
            f"{display(entry['mutable_output_behavior'])} | "
            f"{display(error_output_summary)} | "
            f"{display(entry['unsupported_reason'])} |"
        )
    print()
    print("## Parameter Struct Placeholders Excluded From ABI Matrix")
    print()
    placeholders = inventory["mechanism_parameter_struct_comparison"][
        "spec_parameter_structs_excluded_placeholders"
    ]
    if placeholders:
        print("| Placeholder | Reason | Sources |")
        print("| --- | --- | --- |")
        for entry in placeholders:
            print(
                f"| {entry['spec_struct']} | {entry['reason']} | "
                f"{display(entry['sources'])} |"
            )
    else:
        print("- none")
    print()
    print("## Message Parameter Shape Matrix")
    print()
    print(
        "| Rust Variant | Rust Struct | PKCS#11 Struct | Spec | Proto | Oneof | "
        "Backend FFI | Shim Read | Shim Writeback | Mutable Output | Local Tests |"
    )
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for entry in inventory["message_parameter_shape_matrix"]:
        print(
            f"| {entry['rust_variant']} | {entry['rust_struct']} | "
            f"{display(entry['pkcs11_struct'])} | {display(entry['spec_present'])} | "
            f"{display(entry['proto_message'])} | {display(entry['proto_oneof_field'])} | "
            f"{display(entry['backend_ffi_message_conversion'])} | "
            f"{display(entry['shim_read_support'])} | "
            f"{display(entry['shim_writeback_support'])} | "
            f"{display(entry['mutable_output_behavior'])} | "
            f"{display(entry['local_tests'])} |"
        )
    print()
    print("## Mechanism Info Flag Coverage Matrix")
    print()
    flag_summary = inventory["mechanism_info_flag_coverage_summary"]
    print(
        "- Represented mechanisms with expected flags: "
        f"{flag_summary['represented_expected_flag_count']}"
    )
    print(f"- Source-grounded mechanism-info flags: {flag_summary['source_grounded_count']}")
    print(
        "- Not-yet source-grounded mechanism-info flags: "
        f"{flag_summary['not_yet_source_grounded_count']}"
    )
    print(
        "- No-source workflow evidence mechanisms: "
        f"{flag_summary['no_source_workflow_evidence_count']}"
    )
    print(
        "- No published CK_MECHANISM_TYPE value mechanisms: "
        f"{flag_summary['no_published_ck_mechanism_type_value_count']}"
    )
    if flag_summary["no_source_gap_counts_by_kind"]:
        gap_counts = ", ".join(
            f"{kind}: {count}"
            for kind, count in flag_summary["no_source_gap_counts_by_kind"].items()
        )
        print(f"- No-source workflow gap classes: {gap_counts}")
    print()
    print(
        "| Mechanism | Status | Source Workflows | Source Gap Kind | Expected Flags | "
        "Unsupported Reason | Local Tests |"
    )
    print("| --- | --- | --- | --- | --- | --- | --- |")
    for entry in inventory["mechanism_info_flag_coverage_matrix"]:
        print(
            f"| {entry['name']} | {entry['status']} | "
            f"{display(entry['source_workflows'])} | "
            f"{display(entry['source_gap_kind'])} | "
            f"{display(entry['expected_flag_names'])} | "
            f"{display(entry['unsupported_reason'])} | "
            f"{display(entry['local_tests'])} |"
        )
    print()
    print("## Mechanism Matrix")
    print()
    print(
        "| Mechanism | Status | Official Inventory | Value | Version | Header Annotations | Workflows | "
        "Parameter Structs | MockBackend Catalog Smoke | MockBackend Source-Grounded | "
        "MockBackend Semantics Status | MockBackend Semantic Constructor | "
        "MockBackend Workflow Enforcement | MockBackend Semantic Limitation | "
        "MockBackend Exact Output | "
        "Provider Artifact | Provider Gap | Local Numeric Decision | "
        "Unsupported Reason | Source Discrepancy |"
    )
    print(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    )
    for entry in inventory["mechanism_matrix"]:
        mock_coverage = entry["mock_backend_internal_coverage"]
        numeric_decision = entry["local_numeric_decision"] or {}
        print(
            f"| {entry['name']} | {entry['status']} | "
            f"{display(entry['official_inventory_present'])} | "
            f"{display(entry['value'])} | {display(entry['version_introduced'])} | "
            f"{display(entry['header_annotations'])} | "
            f"{display(entry['workflows'])} | {display(entry['parameter_structs'])} | "
            f"{display(mock_coverage['catalog_smoke_workflows'])} | "
            f"{display(mock_coverage['source_grounded_workflows'])} | "
            f"{display(mock_coverage['workflow_semantics_status'])} | "
            f"{display(mock_coverage['semantic_constructor'])} | "
            f"{display(mock_coverage['source_grounded_workflow_enforcement_test'])} | "
            f"{display(mock_coverage['semantic_limitation'])} | "
            f"{display(mock_coverage['exact_output_workflows'])} | "
            f"{display(entry['provider_artifact_present'])} | {display(entry['provider_gap'])} | "
            f"{display(numeric_decision.get('policy'))} | "
            f"{display(entry['unsupported_reason'])} | "
            f"{display(entry['source_discrepancy_reason'])} |"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    inventory = build_inventory()
    if args.format == "json":
        print(json.dumps(inventory, indent=2, sort_keys=True))
    else:
        print_markdown(inventory)


if __name__ == "__main__":
    main()
