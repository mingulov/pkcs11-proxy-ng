//! R13 handler-wiring tests (S2 §6 order at every `parse_mechanism` site).
//!
//! Each of the 21 handler `parse_mechanism(` call sites (plus the shared
//! `prepare_wrap` admission) is driven with a uniform 5-vector battery:
//! Flat-accept, Flat-reject, Null, legacy-Raw-reject, version-newer-FNS.
//! RED pre-wire: Flat-reject / legacy-Raw sail through the unvalidated
//! path to the mock backend (OK instead of `PARAM_INVALID`); an excluded
//! mechanism is forwarded instead of rejected with `MECHANISM_INVALID`.
//! GREEN post-wire: the S2 §6 order (exclusion → auth → transport
//! validation → remap → backend) holds at every site.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::MockBackend;
use pkcs11_proxy_ng_types::shape_descriptors::{
    Operation, OperationContext, ParamAbi, ShapeResolver,
};
use pkcs11_proxy_ng_types::{
    CkMechanismType, CkObjectHandle, CkRv, CkSessionFlags, CkSlotId,
    MECHANISM_PARAMETER_TRANSPORT_VERSION,
};
use tonic::Request;

use super::HandlerContext;
use super::service_utils::register_session_object_handle;
use crate::consistency_checks::{find_keyword, read_ident, skip_ws, strip_rust_code};
use crate::mechanism_registry_source::MechanismRegistrySource;
use crate::server::context_manager::{ClientContextId, ContextManager};
use crate::server::handle_map::{BackendHandle, VirtualHandle};
use crate::server::slot_map::BackendSlotId;

const AES_CBC: u64 = 0x0000_1082;
const AES_CBC_PAD: u64 = 0x0000_1085;
const RSA_PSS: u64 = 0x000D;
const LP64: ParamAbi = ParamAbi::Lp64NativeLe;

/// This test daemon's native v1 ABI (LP64 on 64-bit unix, ILP32 on i686,
/// LLP64-pack1 on Windows): struct-prefix Flats require source == daemon
/// ABI (S2 §5 width rule — only parameterless and byte-buffer grants
/// cross ABIs; the daemon validates under `daemon_validation_abis`,
/// whose local half is the compiled native ABI), so the struct-prefix
/// accept vector must be fingerprinted and labeled under the ABI the
/// tests actually execute with. The LP64 helpers below stay as-is: their
/// byte-buffer accept vectors cross ABIs and their reject vectors reject
/// everywhere.
fn native_abi() -> ParamAbi {
    ParamAbi::native().expect("v1 ABI exists on little-endian CI targets")
}

/// Wire encoding of a domain ABI, mirroring production's
/// `domain_abi_to_wire` (proto convert): matched explicitly so a future
/// ABI addition fails to compile here rather than mislabel.
fn source_abi_wire(abi: ParamAbi) -> i32 {
    match abi {
        ParamAbi::Lp64NativeLe => pkcs11_proxy_ng_proto::MechanismParamAbi::Lp64NativeLe as i32,
        ParamAbi::Ilp32NativeLe => pkcs11_proxy_ng_proto::MechanismParamAbi::Ilp32NativeLe as i32,
        ParamAbi::Llp64Packed1Le => pkcs11_proxy_ng_proto::MechanismParamAbi::Llp64Packed1Le as i32,
        ParamAbi::Ilp32Packed1Le => pkcs11_proxy_ng_proto::MechanismParamAbi::Ilp32Packed1Le as i32,
    }
}

fn expected_fingerprint(mech: u64, operation: Operation, len: u64) -> u64 {
    expected_fingerprint_for_shape("iv", mech, operation, len)
}

fn expected_fingerprint_for_shape(shape: &str, mech: u64, operation: Operation, len: u64) -> u64 {
    expected_fingerprint_for_shape_under(shape, mech, operation, len, LP64)
}

fn expected_fingerprint_for_shape_under(
    shape: &str,
    mech: u64,
    operation: Operation,
    len: u64,
    abi: ParamAbi,
) -> u64 {
    ShapeResolver::resolve(
        Some(shape),
        OperationContext { mechanism: mech, operation, length: len },
        abi,
    )
    .unwrap()
    .fingerprint(abi)
}

fn flat_mechanism(
    mech: u64,
    _operation: Operation,
    fingerprint: u64,
) -> pkcs11_proxy_ng_proto::Mechanism {
    pkcs11_proxy_ng_proto::Mechanism {
        mechanism_type: mech,
        params: Some(pkcs11_proxy_ng_proto::mechanism::Params::FlatMechanismParams(
            pkcs11_proxy_ng_proto::FlatMechanismParams {
                data: vec![0xA5u8; 16],
                declared_len: 16,
                source_abi: pkcs11_proxy_ng_proto::MechanismParamAbi::Lp64NativeLe as i32,
                shape_layout_fingerprint: fingerprint,
            },
        )),
        parameter_encoding_version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
    }
}

fn null_mechanism(mech: u64) -> pkcs11_proxy_ng_proto::Mechanism {
    pkcs11_proxy_ng_proto::Mechanism {
        mechanism_type: mech,
        params: Some(pkcs11_proxy_ng_proto::mechanism::Params::NullMechanismParams(
            pkcs11_proxy_ng_proto::NullMechanismParams { declared_len: 16 },
        )),
        parameter_encoding_version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
    }
}

fn raw_mechanism(mech: u64) -> pkcs11_proxy_ng_proto::Mechanism {
    pkcs11_proxy_ng_proto::Mechanism {
        mechanism_type: mech,
        params: Some(pkcs11_proxy_ng_proto::mechanism::Params::RawMechanismParams(
            pkcs11_proxy_ng_proto::RawMechanismParams { data: vec![0xA5u8; 16] },
        )),
        parameter_encoding_version: 0,
    }
}

fn version_newer_mechanism(mech: u64) -> pkcs11_proxy_ng_proto::Mechanism {
    pkcs11_proxy_ng_proto::Mechanism {
        mechanism_type: mech,
        params: Some(pkcs11_proxy_ng_proto::mechanism::Params::IvParams(
            pkcs11_proxy_ng_proto::IvParams { iv: vec![0xA5u8; 16] },
        )),
        parameter_encoding_version: MECHANISM_PARAMETER_TRANSPORT_VERSION + 1,
    }
}

fn parameterless_mechanism(mech: u64) -> pkcs11_proxy_ng_proto::Mechanism {
    pkcs11_proxy_ng_proto::Mechanism {
        mechanism_type: mech,
        params: None,
        parameter_encoding_version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
    }
}

fn empty_flat_mechanism(
    mech: u64,
    fingerprint: u64,
    abi: ParamAbi,
) -> pkcs11_proxy_ng_proto::Mechanism {
    pkcs11_proxy_ng_proto::Mechanism {
        mechanism_type: mech,
        params: Some(pkcs11_proxy_ng_proto::mechanism::Params::FlatMechanismParams(
            pkcs11_proxy_ng_proto::FlatMechanismParams {
                data: Vec::new(),
                declared_len: 0,
                source_abi: source_abi_wire(abi),
                shape_layout_fingerprint: fingerprint,
            },
        )),
        parameter_encoding_version: MECHANISM_PARAMETER_TRANSPORT_VERSION,
    }
}

struct Harness {
    ctx: HandlerContext,
    ctx_id: ClientContextId,
    session: u64,
    key: u64,
    key2: u64,
    _tempdir: Option<tempfile::TempDir>,
}

impl Harness {
    async fn new(mechanisms: Vec<CkMechanismType>) -> Self {
        Self::with_registry_source(mechanisms, MechanismRegistrySource::load(None).unwrap()).await
    }

    async fn with_registry_source(
        mechanisms: Vec<CkMechanismType>,
        registry_source: MechanismRegistrySource,
    ) -> Self {
        let backend = Arc::new(MockBackend::new(vec![CkSlotId(0)], mechanisms));
        let mock_session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let mock_key = backend.create_object(mock_session, None).unwrap();
        let mock_key2 = backend.create_object(mock_session, None).unwrap();
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(BackendHandle(mock_session.0), BackendSlotId(CkSlotId(0)))
            })
            .await
            .unwrap();
        let backend_dyn: Arc<dyn Pkcs11Backend> = backend;
        let mut ctx = HandlerContext::for_test(&ctx_mgr, &backend_dyn);
        ctx.mechanism_registry_source = registry_source;
        // Public session objects: the D6(1) USE check passes while logged out.
        let key = register_session_object_handle(
            &ctx_mgr,
            &ctx_id,
            VirtualHandle(session_vh.0),
            CkObjectHandle(mock_key.0),
            false,
            Some(false),
        )
        .await;
        let key2 = register_session_object_handle(
            &ctx_mgr,
            &ctx_id,
            VirtualHandle(session_vh.0),
            CkObjectHandle(mock_key2.0),
            false,
            Some(false),
        )
        .await;
        Self { ctx, ctx_id, session: session_vh.0, key, key2, _tempdir: None }
    }

    fn ctx_id(&self) -> String {
        self.ctx_id.0.clone()
    }

    /// Harness whose registry source excludes `AES_CBC_PAD` (keeps the
    /// registry-file tempdir alive for the harness lifetime).
    async fn with_exclusion(mechanisms: Vec<CkMechanismType>) -> Self {
        let (source, tempdir) = excluding_registry_source();
        let mut harness = Self::with_registry_source(mechanisms, source).await;
        harness._tempdir = Some(tempdir);
        harness
    }
}

/// Custom registry source: embedded base plus `exclude = [AES_CBC_PAD]`.
/// Returns the tempdir alongside so the registry file outlives the test.
fn excluding_registry_source() -> (MechanismRegistrySource, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.toml");
    std::fs::write(&path, "exclude = [0x1085]\n").unwrap();
    let source = MechanismRegistrySource::load(Some(path.as_path())).unwrap();
    (source, dir)
}

// ---------------------------------------------------------------------------
// Site drivers: each drives one `parse_mechanism(` call site and returns the
// response ck_rv. `operation` selects the Flat fingerprint context (WrapKey
// for the shared `prepare_wrap` admission, General elsewhere).
// ---------------------------------------------------------------------------

type P = pkcs11_proxy_ng_proto::Mechanism;

async fn drive_digest_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::DigestInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
    };
    super::digest_cipher::digest_init(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_encrypt_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::EncryptInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        key_handle: h.key,
        mechanism,
    };
    super::digest_cipher::encrypt_init(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_decrypt_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::DecryptInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        key_handle: h.key,
        mechanism,
    };
    super::digest_cipher::decrypt_init(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_wrap_key(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::WrapKeyRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        wrapping_key_handle: h.key,
        key_handle: h.key2,
    };
    super::key_ops::wrap_key(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_generate_key_pair(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::GenerateKeyPairRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        public_key_template: vec![],
        private_key_template: vec![],
        public_template_null: false,
        private_template_null: false,
    };
    super::key_ops::generate_key_pair(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_generate_key(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::GenerateKeyRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        template: vec![],
        template_null: false,
    };
    super::key_ops::generate_key(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_derive_key(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::DeriveKeyRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        base_key_handle: h.key,
        template: vec![],
        template_null: false,
    };
    super::key_ops::derive_key(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_unwrap_key_authenticated(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::UnwrapKeyAuthenticatedRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        unwrapping_key_handle: h.key,
        wrapped_key: vec![1, 2, 3, 4],
        template: vec![],
        template_null: false,
        associated_data: vec![],
        wrapped_key_null_len: None,
        associated_data_null_len: None,
        authenticated_parameters: None,
    };
    super::key_ops::unwrap_key_authenticated(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn drive_encapsulate_key(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::EncapsulateKeyRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        public_key_handle: h.key,
        template: vec![],
        template_null: false,
    };
    super::key_ops::encapsulate_key(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_decapsulate_key(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::DecapsulateKeyRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        private_key_handle: h.key,
        template: vec![],
        ciphertext: vec![7, 8, 9],
        ciphertext_null_len: None,
        template_null: false,
    };
    super::key_ops::decapsulate_key(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_encapsulate_key_exact(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        public_key_handle: h.key,
        template: vec![],
        output_spec: None,
        exact_output_effects_version: 1,
        template_null: false,
    };
    super::key_ops::encapsulate_key_exact(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap()
        .ck_rv
}

async fn drive_unwrap_key(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::UnwrapKeyRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        unwrapping_key_handle: h.key,
        wrapped_key: vec![1, 2, 3, 4],
        template: vec![],
        wrapped_key_null_len: None,
        template_null: false,
    };
    super::key_ops::unwrap_key(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_message_encrypt_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        key_handle: h.key,
        init_message_parameter: None,
        parameter_out_spec: None,
        parameter_shape: None,
    };
    super::message_crypto::message_encrypt_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn drive_message_decrypt_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::MessageDecryptInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        key_handle: h.key,
        init_message_parameter: None,
        parameter_out_spec: None,
        parameter_shape: None,
    };
    super::message_crypto::message_decrypt_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn drive_message_sign_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::MessageSignInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        key_handle: h.key,
    };
    super::message_crypto::message_sign_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn drive_message_verify_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::MessageVerifyInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        key_handle: h.key,
    };
    super::message_crypto::message_verify_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn drive_verify_signature_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::VerifySignatureInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism,
        key_handle: h.key,
        signature: vec![5, 6, 7, 8],
        signature_null_len: None,
    };
    super::sign_verify::verify_signature_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn drive_sign_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::SignInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        key_handle: h.key,
        mechanism,
    };
    super::sign_verify::sign_init(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_sign_recover_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::SignRecoverInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        key_handle: h.key,
        mechanism,
    };
    super::sign_verify::sign_recover_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

async fn drive_verify_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::VerifyInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        key_handle: h.key,
        mechanism,
    };
    super::sign_verify::verify_init(&h.ctx, Request::new(req)).await.unwrap().into_inner().ck_rv
}

async fn drive_verify_recover_init(h: &Harness, mechanism: Option<P>) -> u64 {
    let req = pkcs11_proxy_ng_proto::VerifyRecoverInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        key_handle: h.key,
        mechanism,
    };
    super::sign_verify::verify_recover_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv
}

// ---------------------------------------------------------------------------
// 5-vector battery per site. Fresh harness per vector (no cross-vector
// session/op state). Accept expectations: OK everywhere except
// unwrap_key_authenticated, where the pre-existing authenticated-parameter
// gate answers FNS for non-legacy params AFTER transport validation.
// ---------------------------------------------------------------------------

macro_rules! site_battery {
    ($test:ident, $drive:ident, $op:expr, $accept_flat:expr, $accept_null:expr) => {
        #[tokio::test]
        async fn $test() {
            let mechs = || vec![CkMechanismType(AES_CBC)];
            let good_fp = expected_fingerprint(AES_CBC, $op, 16);
            // Flat-accept: validated Flat reaches the backend (mock OK).
            let h = Harness::new(mechs()).await;
            assert_eq!(
                $drive(&h, Some(flat_mechanism(AES_CBC, $op, good_fp))).await,
                $accept_flat,
                "flat-accept",
            );
            // Flat-reject: bad fingerprint is PARAM_INVALID. The reject
            // vector rides RSA_PSS (`rsa_pss` is ScalarStruct, so the
            // fingerprint is checked); AES_CBC's `iv` is ByteBuffer and
            // fingerprint-exempt by design.
            let h = Harness::new(mechs()).await;
            let pss_fp = expected_fingerprint_for_shape("rsa_pss", RSA_PSS, $op, 16);
            assert_eq!(
                $drive(&h, Some(flat_mechanism(RSA_PSS, $op, pss_fp.wrapping_add(1)))).await,
                CkRv::MECHANISM_PARAM_INVALID.0,
                "flat-reject",
            );
            // Null: NULL + narrowed length forwards without a descriptor.
            let h = Harness::new(mechs()).await;
            assert_eq!($drive(&h, Some(null_mechanism(AES_CBC))).await, $accept_null, "null",);
            // Legacy Raw: fail-closed PARAM_INVALID at transport validation.
            let h = Harness::new(mechs()).await;
            assert_eq!(
                $drive(&h, Some(raw_mechanism(AES_CBC))).await,
                CkRv::MECHANISM_PARAM_INVALID.0,
                "raw-reject",
            );
            // Version-newer: FUNCTION_NOT_SUPPORTED during domain conversion.
            let h = Harness::new(mechs()).await;
            assert_eq!(
                $drive(&h, Some(version_newer_mechanism(AES_CBC))).await,
                CkRv::FUNCTION_NOT_SUPPORTED.0,
                "version-newer",
            );
        }
    };
}

site_battery!(wired_digest_init, drive_digest_init, Operation::General, CkRv::OK.0, CkRv::OK.0);
site_battery!(wired_encrypt_init, drive_encrypt_init, Operation::General, CkRv::OK.0, CkRv::OK.0);
site_battery!(wired_decrypt_init, drive_decrypt_init, Operation::General, CkRv::OK.0, CkRv::OK.0);
site_battery!(wired_wrap_key, drive_wrap_key, Operation::WrapKey, CkRv::OK.0, CkRv::OK.0);
site_battery!(
    wired_generate_key_pair,
    drive_generate_key_pair,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(wired_generate_key, drive_generate_key, Operation::General, CkRv::OK.0, CkRv::OK.0);
site_battery!(wired_derive_key, drive_derive_key, Operation::General, CkRv::OK.0, CkRv::OK.0);
site_battery!(
    wired_unwrap_key_authenticated,
    drive_unwrap_key_authenticated,
    Operation::General,
    CkRv::FUNCTION_NOT_SUPPORTED.0,
    CkRv::FUNCTION_NOT_SUPPORTED.0
);
site_battery!(
    wired_encapsulate_key,
    drive_encapsulate_key,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(
    wired_decapsulate_key,
    drive_decapsulate_key,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(
    wired_encapsulate_key_exact,
    drive_encapsulate_key_exact,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(wired_unwrap_key, drive_unwrap_key, Operation::General, CkRv::OK.0, CkRv::OK.0);
/// Message encrypt/decrypt inits forbid mechanism params by pre-existing
/// design (`validate_message_init_contract` rejects `mechanism_had_params`
/// before session resolution): every params-carrying vector answers
/// MECHANISM_PARAM_INVALID at the contract, never reaching transport
/// validation. This pins the precedence (contract first, unchanged by R13);
/// the wired path itself is pinned parameterless below.
#[tokio::test]
async fn wired_message_encrypt_init_contract_preempts_params() {
    let mechs = || vec![CkMechanismType(AES_CBC)];
    let good_fp = expected_fingerprint(AES_CBC, Operation::General, 16);
    let pss_fp = expected_fingerprint_for_shape("rsa_pss", RSA_PSS, Operation::General, 16);
    for (name, mechanism) in [
        ("flat-accept", flat_mechanism(AES_CBC, Operation::General, good_fp)),
        ("flat-reject", flat_mechanism(RSA_PSS, Operation::General, pss_fp.wrapping_add(1))),
        ("null", null_mechanism(AES_CBC)),
        ("raw-reject", raw_mechanism(AES_CBC)),
        ("version-newer", version_newer_mechanism(AES_CBC)),
    ] {
        let h = Harness::new(mechs()).await;
        assert_eq!(
            drive_message_encrypt_init(&h, Some(mechanism)).await,
            CkRv::MECHANISM_PARAM_INVALID.0,
            "{name}",
        );
    }
}

/// Issue #37 (daemon-side backstop): a materialized opaque image for a
/// pointer-struct registry shape is refused with clean MPI instead of
/// reaching the provider (stale client addresses segfault the daemon).
#[tokio::test]
async fn message_encrypt_init_refuses_opaque_pointer_struct_image() {
    use pkcs11_proxy_ng_proto::convert::message_params::{MessageParameter, MessageParameterShape};
    use pkcs11_proxy_ng_types::SecretBytes;
    const CHACHA20: u64 = 0x0000_1226;
    let h = Harness::new(vec![CkMechanismType(CHACHA20)]).await;
    // A 32-byte CK_CHACHA20_PARAMS image, as the pre-fix shim emitted it.
    let wire_param = MessageParameter::Raw(SecretBytes::new(vec![0xA5u8; 32]))
        .to_wire_with_transport_version(1)
        .expect("opaque image encodes");
    let req = pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism: Some(parameterless_mechanism(CHACHA20)),
        key_handle: h.key,
        init_message_parameter: Some(wire_param),
        parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
            buffer_present: true,
            buffer_len: 32,
            value: None,
        }),
        parameter_shape: Some(MessageParameterShape::Unmodeled.to_proto_i32()),
    };
    let rv = super::message_crypto::message_encrypt_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
    assert_eq!(rv, CkRv::MECHANISM_PARAM_INVALID.0);
}

/// Issue #37 (plain-path fail-fast): a type-only (empty) message init
/// for a pointer-struct registry shape is refused without installing —
/// an install that can never complete must never start (transitively
/// closes Begin/Next/OneShot follow-ups, which reuse the installed
/// Unmodeled shape).
#[tokio::test]
async fn message_encrypt_init_refuses_empty_pointer_struct_init() {
    const CHACHA20: u64 = 0x0000_1226;
    let h = Harness::new(vec![CkMechanismType(CHACHA20)]).await;
    assert_eq!(
        drive_message_encrypt_init(&h, Some(parameterless_mechanism(CHACHA20))).await,
        CkRv::MECHANISM_PARAM_INVALID.0,
    );
    assert_eq!(
        drive_message_decrypt_init(&h, Some(parameterless_mechanism(CHACHA20))).await,
        CkRv::MECHANISM_PARAM_INVALID.0,
    );
}

/// Review F-05 (explicit empty-parameterless admit): a typed-empty
/// message init (Unmodeled shape declared, no parameter bytes) for a
/// registry-declared parameterless mechanism passes the #37 init gate
/// and installs — the fail-fast must not swallow the normal empty form.
/// Unlike the `drive_*` helpers (which send no shape and skip the
/// contract), this builds the full request so the gate actually runs.
#[tokio::test]
async fn message_encrypt_init_admits_empty_parameterless_init() {
    use pkcs11_proxy_ng_proto::convert::message_params::MessageParameterShape;
    const AES_ECB: u64 = 0x0000_1081;
    let h = Harness::new(vec![CkMechanismType(AES_ECB)]).await;
    let req = pkcs11_proxy_ng_proto::MessageEncryptInitRequest {
        client_context_id: h.ctx_id(),
        session_handle: h.session,
        mechanism: Some(parameterless_mechanism(AES_ECB)),
        key_handle: h.key,
        init_message_parameter: None,
        parameter_out_spec: Some(pkcs11_proxy_ng_proto::ParameterRoundtripSpec {
            buffer_present: false,
            buffer_len: 0,
            value: None,
        }),
        parameter_shape: Some(MessageParameterShape::Unmodeled.to_proto_i32()),
    };
    let rv = super::message_crypto::message_encrypt_init(&h.ctx, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
    assert_eq!(rv, CkRv::OK.0);
}

/// Issue #37 (alternate forms): `gcm_compat` resolves ByteBuffer for
/// short IVs but PointerStruct for struct-sized images — opaque
/// carriage must refuse it (length-selected alternates considered).
#[tokio::test]
async fn message_encrypt_init_refuses_gcm_compat_opaque() {
    const GMAC: u64 = 0x0000_108E;
    let h = Harness::new(vec![CkMechanismType(GMAC)]).await;
    assert_eq!(
        drive_message_encrypt_init(&h, Some(parameterless_mechanism(GMAC))).await,
        CkRv::MECHANISM_PARAM_INVALID.0,
    );
}

/// Same contract precedence for message decrypt init (see above).
#[tokio::test]
async fn wired_message_decrypt_init_contract_preempts_params() {
    let mechs = || vec![CkMechanismType(AES_CBC)];
    let good_fp = expected_fingerprint(AES_CBC, Operation::General, 16);
    let pss_fp = expected_fingerprint_for_shape("rsa_pss", RSA_PSS, Operation::General, 16);
    for (name, mechanism) in [
        ("flat-accept", flat_mechanism(AES_CBC, Operation::General, good_fp)),
        ("flat-reject", flat_mechanism(RSA_PSS, Operation::General, pss_fp.wrapping_add(1))),
        ("null", null_mechanism(AES_CBC)),
        ("raw-reject", raw_mechanism(AES_CBC)),
        ("version-newer", version_newer_mechanism(AES_CBC)),
    ] {
        let h = Harness::new(mechs()).await;
        assert_eq!(
            drive_message_decrypt_init(&h, Some(mechanism)).await,
            CkRv::MECHANISM_PARAM_INVALID.0,
            "{name}",
        );
    }
}
site_battery!(
    wired_message_sign_init,
    drive_message_sign_init,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(
    wired_message_verify_init,
    drive_message_verify_init,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(
    wired_verify_signature_init,
    drive_verify_signature_init,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(wired_sign_init, drive_sign_init, Operation::General, CkRv::OK.0, CkRv::OK.0);
site_battery!(
    wired_sign_recover_init,
    drive_sign_recover_init,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);
site_battery!(wired_verify_init, drive_verify_init, Operation::General, CkRv::OK.0, CkRv::OK.0);
site_battery!(
    wired_verify_recover_init,
    drive_verify_recover_init,
    Operation::General,
    CkRv::OK.0,
    CkRv::OK.0
);

// ---------------------------------------------------------------------------
// Message-site wired path, pinned parameterless (the contract forbids
// mechanism params there, so transport validation only ever sees `None`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wired_message_encrypt_init_parameterless_accept() {
    let h = Harness::new(vec![CkMechanismType(AES_CBC)]).await;
    assert_eq!(
        drive_message_encrypt_init(&h, Some(parameterless_mechanism(AES_CBC))).await,
        CkRv::OK.0,
    );
}

#[tokio::test]
async fn wired_message_decrypt_init_parameterless_accept() {
    let h = Harness::new(vec![CkMechanismType(AES_CBC)]).await;
    assert_eq!(
        drive_message_decrypt_init(&h, Some(parameterless_mechanism(AES_CBC))).await,
        CkRv::OK.0,
    );
}

// ---------------------------------------------------------------------------
// Exclusion-before-auth pins (2 sites: a direct handler + the shared
// `prepare_wrap` admission). The harness policy is default-allow, so the
// MECHANISM_INVALID can only come from the exclusion gate — which runs
// before authorization per the source-scan assertion below.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exclusion_fires_before_auth_at_sign_init() {
    let h = Harness::with_exclusion(vec![CkMechanismType(AES_CBC_PAD)]).await;
    assert_eq!(
        drive_sign_init(&h, Some(parameterless_mechanism(AES_CBC_PAD))).await,
        CkRv::MECHANISM_INVALID.0,
    );
    // Sanity: the same mechanism is accepted without the exclusion.
    let h = Harness::new(vec![CkMechanismType(AES_CBC_PAD)]).await;
    assert_eq!(drive_sign_init(&h, Some(parameterless_mechanism(AES_CBC_PAD))).await, CkRv::OK.0,);
}

#[tokio::test]
async fn exclusion_fires_before_auth_at_wrap_key() {
    let h = Harness::with_exclusion(vec![CkMechanismType(AES_CBC_PAD)]).await;
    assert_eq!(
        drive_wrap_key(&h, Some(parameterless_mechanism(AES_CBC_PAD))).await,
        CkRv::MECHANISM_INVALID.0,
    );
    // Sanity: the same mechanism is accepted without the exclusion.
    let h = Harness::new(vec![CkMechanismType(AES_CBC_PAD)]).await;
    assert_eq!(drive_wrap_key(&h, Some(parameterless_mechanism(AES_CBC_PAD))).await, CkRv::OK.0,);
}

// ---------------------------------------------------------------------------
// Single-snapshot property: exactly ONE `current_registry()` call per
// request (the snapshot feeds exclusion + validation; no re-acquire).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_snapshot_per_request_at_sign_init() {
    let h = Harness::new(vec![CkMechanismType(AES_CBC)]).await;
    let good_fp = expected_fingerprint(AES_CBC, Operation::General, 16);
    assert_eq!(
        drive_sign_init(&h, Some(flat_mechanism(AES_CBC, Operation::General, good_fp))).await,
        CkRv::OK.0,
    );
    assert_eq!(h.ctx.mechanism_registry_source.current_registry_calls(), 1);
}

#[tokio::test]
async fn single_snapshot_per_request_at_message_encrypt_init() {
    let h = Harness::new(vec![CkMechanismType(AES_CBC)]).await;
    assert_eq!(
        drive_message_encrypt_init(&h, Some(parameterless_mechanism(AES_CBC))).await,
        CkRv::OK.0,
    );
    assert_eq!(h.ctx.mechanism_registry_source.current_registry_calls(), 1);
}

// ---------------------------------------------------------------------------
// Null-vs-empty-Flat non-conflation: an empty Flat still rides the shape
// path (wrong fingerprint rejected), while Null forwards without one.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn null_and_empty_flat_do_not_conflate() {
    let mechs = || vec![CkMechanismType(RSA_PSS)];
    // Struct-prefix vector: fingerprint + label under the daemon's native
    // ABI (LP64 metadata is an AbiMismatch on ILP32 daemons).
    let abi = native_abi();
    let pss_fp =
        expected_fingerprint_for_shape_under("rsa_pss", RSA_PSS, Operation::General, 0, abi);
    // Empty Flat, correct fingerprint: shape path admits the zero prefix.
    let h = Harness::new(mechs()).await;
    assert_eq!(
        drive_sign_init(&h, Some(empty_flat_mechanism(RSA_PSS, pss_fp, abi))).await,
        CkRv::OK.0,
        "empty-flat-accept",
    );
    // Empty Flat, wrong fingerprint: shape path rejects (not Null-routed).
    let h = Harness::new(mechs()).await;
    assert_eq!(
        drive_sign_init(&h, Some(empty_flat_mechanism(RSA_PSS, pss_fp.wrapping_add(1), abi))).await,
        CkRv::MECHANISM_PARAM_INVALID.0,
        "empty-flat-reject",
    );
    // Null: forwards with no descriptor at all.
    let h = Harness::new(mechs()).await;
    assert_eq!(drive_sign_init(&h, Some(null_mechanism(RSA_PSS))).await, CkRv::OK.0, "null",);
}

// ---------------------------------------------------------------------------
// Source-scan assertion (R14 extends to all sites), MAINT-03 hardened (Q08):
// at every `parse_mechanism(` call site in the wired handler files, the S2
// §6 gate order holds: exclusion → auth → transport validation → remap.
//
// Two gates over one reviewed inventory:
//  1. Reverse discovery: every `.rs` file under `src/server/grpc_service`
//     with a real (comment/string-stripped, test-region-excluded)
//     `parse_mechanism` call site must be listed in `WIRE_SITES` — a new
//     handler file can no longer slip past the list. `INVENTORY_EXEMPT`
//     names the reviewed non-handler mentions and `EARLY_GATE_EXEMPT`
//     the files whose test gates a cut cannot handle; each exemption is
//     re-validated every run.
//  2. Gate order over stripped code: gate markers sitting only in comments
//     or strings no longer satisfy the check (the pre-Q08 raw-substring
//     scan accepted them).
// No new Rust parser or code generator: token/comment handling is the
// existing `consistency_checks` helpers (`strip_rust_code`,
// `find_keyword`, `read_ident`, `skip_ws`) plus explicit exemptions.
// Deliberately uncovered: an aliased helper import (`use ... as pm`)
// cannot be resolved without import tracking, but its `use` line still
// mentions the helper, so the mention tripwire forces it into reviewed
// listing-or-exemption instead of a silent pass.
// ---------------------------------------------------------------------------

/// Reviewed inventory of mechanism-bearing handler files: (path relative
/// to `src/server/grpc_service`, expected `parse_mechanism(` call-site
/// count). The anchor count per file pins the no-bypass invariant (a new
/// call site without the gates fails the order check); the
/// reverse-discovery gate pins the list itself (an unlisted handler file
/// fails the inventory check).
const WIRE_SITES: &[(&str, usize)] = &[
    ("message_crypto/mod.rs", 4),
    ("digest_cipher/digest.rs", 1),
    ("digest_cipher/cipher.rs", 2),
    ("key_ops/generation.rs", 3),
    ("key_ops/kem.rs", 3),
    ("key_ops/wrapping.rs", 1),
    ("key_ops/authenticated_wrap.rs", 1),
    ("key_ops/wrap_preparation.rs", 1),
    ("sign_verify/sign.rs", 2),
    ("sign_verify/verify.rs", 2),
    ("sign_verify/verify_signature.rs", 1),
];

/// Reviewed non-handler files that mention the `parse_mechanism` helper
/// without calling it. Each exemption is re-validated on every run: the
/// file must still mention the helper (a stale exemption fails) and must
/// hold zero real call sites (a handler site fails and belongs in
/// `WIRE_SITES`).
const INVENTORY_EXEMPT: &[&str] = &[
    // Holds the shared helper definition (`fn parse_mechanism (`), not a
    // handler call site.
    "service_utils.rs",
];

/// Reviewed files whose `#[cfg(test)]` gates do not all open inline test
/// modules, so a first-gate cut cannot separate test code without item
/// parsing. Structural-exempt files are scanned whole (a test-region call
/// there fails loud and forces a restructure or a listing) and must hold
/// zero call sites. Each entry is re-validated: it must still contain a
/// non-inline gate (a restructured file drops the exemption).
const EARLY_GATE_EXEMPT: &[&str] = &[
    // Early `mod foo;` declarations plus a trailing test module.
    "service_utils.rs",
    // Mid-file test `impl HandlerContext`.
    "context.rs",
    // Early `mod mechanism_wiring_tests;` declaration plus trailing modules.
    "mod.rs",
    // Test-only `async fn` doubles plus an external `mod tests;`.
    "session.rs",
    // Test-only `async fn` double.
    "state_ops/mod.rs",
];

/// S2 §6 gate calls, in required textual order after `parse_mechanism(`.
const GATES: &[&str] = &[
    "check_operator_exclusion(",
    "mechanism_permitted(",
    "validate_mechanism_transport(",
    "remap_mechanism_handles(",
];

fn grpc_service_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server/grpc_service")
}

/// Scannable code of one file plus whether it needs structural
/// treatment: the comment/string-stripped source, cut before the first
/// `#[cfg(test)]` inline test module. Files with a non-inline test gate
/// (early `mod foo;`, mid-file test `impl`, ...) cannot be cut safely
/// without item parsing, so they must be listed in `EARLY_GATE_EXEMPT`
/// and are scanned whole instead (test-region calls there fail loud).
/// Only the exact `#[cfg(test)]` spelling is recognized; exotic
/// spellings (`#[cfg(all(test, ...))]`) scan as production code — none
/// exist under `grpc_service/` today.
fn scannable_code(text: &str) -> (String, bool) {
    let stripped = strip_rust_code(text);
    if gates_are_inline_mods(&stripped) {
        let cut = stripped.find("#[cfg(test)]").unwrap_or(stripped.len());
        (stripped[..cut].to_string(), false)
    } else {
        (stripped, true)
    }
}

/// Whether every `#[cfg(test)]` gate in `stripped` opens an inline
/// `mod {` (cut-compatible). Gates are located on stripped code, so
/// comments and strings cannot forge one. No brace matching: anything
/// else forces a structural exemption (fail-loud).
fn gates_are_inline_mods(stripped: &str) -> bool {
    const ATTR: &str = "#[cfg(test)]";
    let mut search_from = 0;
    while let Some(rel) = stripped[search_from..].find(ATTR) {
        let after_attr = search_from + rel + ATTR.len();
        if !gate_opens_inline_mod(stripped, after_attr) {
            return false;
        }
        search_from = after_attr;
    }
    true
}

/// Whether the `#[cfg(test)]` gate ending at `after_attr` opens an inline
/// test module (`mod tests {`, possibly `pub`-qualified or same-line).
/// Only the gate's own line plus the next line are inspected, with the
/// existing `find_keyword`/`read_ident`/`skip_ws` token helpers: wider
/// gaps force a structural exemption instead of a silent cut.
fn gate_opens_inline_mod(stripped: &str, after_attr: usize) -> bool {
    let end_of_gate_line =
        stripped[after_attr..].find('\n').map(|i| after_attr + i + 1).unwrap_or(stripped.len());
    let next_line_end = stripped[end_of_gate_line..]
        .find('\n')
        .map(|i| end_of_gate_line + i)
        .unwrap_or(stripped.len());
    let window = &stripped[after_attr..next_line_end];
    let Some(mod_at) = find_keyword(window, 0, "mod") else { return false };
    let Some((_, after_name)) = read_ident(window, mod_at + "mod".len()) else { return false };
    window.as_bytes().get(skip_ws(window, after_name)) == Some(&b'{')
}

/// Byte offsets of real `parse_mechanism` call sites in scannable code:
/// the word-boundary helper name (existing `find_keyword` token
/// handling) followed by `(` after optional whitespace — so a comment
/// split across the paren (`parse_mechanism /* c */ (`, blanked to
/// spaces by the stripper) cannot evade the gate. The shared helper
/// definition (`fn parse_mechanism (`) is not a site.
fn call_site_anchors(scannable: &str) -> Vec<usize> {
    let mut anchors = Vec::new();
    let mut from = 0;
    while let Some(index) = find_keyword(scannable, from, "parse_mechanism") {
        let after = skip_ws(scannable, index + "parse_mechanism".len());
        if scannable.as_bytes().get(after) == Some(&b'(') && !is_fn_definition(scannable, index) {
            anchors.push(index);
        }
        from = index + 1;
    }
    anchors
}

/// Whether the `parse_mechanism(` occurrence at `index` is a `fn`
/// definition (`pub(super) fn parse_mechanism(`, ...) rather than a call.
fn is_fn_definition(stripped: &str, index: usize) -> bool {
    let before = stripped[..index].trim_end();
    const FN_LEN: usize = 2; // `fn`
    before.len() >= FN_LEN
        && before.ends_with("fn")
        && before.as_bytes()[..before.len() - FN_LEN]
            .last()
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
}

/// Reverse inventory discovery (MAINT-03) over every `.rs` file under
/// `root`. Keys are `/`-joined relative paths, so the tables match
/// `WIRE_SITES` on every platform.
struct HandlerInventory {
    /// Files holding at least one real call site, mapped to the site count.
    sites: BTreeMap<String, usize>,
    /// Files whose test gates a cut cannot handle (need a structural
    /// exemption) — scanned whole.
    needs_structural: BTreeSet<String>,
    /// Files mentioning the helper without a direct call site (an aliased
    /// import lands here): the mention tripwire forces reviewed
    /// listing-or-exemption instead of a silent pass.
    mentions_without_sites: BTreeSet<String>,
}

fn discover_mechanism_handler_files(root: &Path) -> HandlerInventory {
    let mut inventory = HandlerInventory {
        sites: BTreeMap::new(),
        needs_structural: BTreeSet::new(),
        mentions_without_sites: BTreeSet::new(),
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries {
            let path =
                entry.unwrap_or_else(|e| panic!("read entry in {}: {e}", dir.display())).path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let (code, needs_structural) = scannable_code(&text);
            let anchors = call_site_anchors(&code);
            if anchors.is_empty()
                && !needs_structural
                && find_keyword(&code, 0, "parse_mechanism").is_none()
            {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or_else(|_| panic!("{} escapes {}", path.display(), root.display()));
            let file = rel_slash_path(rel);
            if !anchors.is_empty() {
                inventory.sites.insert(file.clone(), anchors.len());
            }
            if needs_structural {
                inventory.needs_structural.insert(file.clone());
            }
            if anchors.is_empty() && find_keyword(&code, 0, "parse_mechanism").is_some() {
                inventory.mentions_without_sites.insert(file);
            }
        }
    }
    inventory
}

/// `/`-joined relative path, so discovered keys match `WIRE_SITES` on
/// every platform (Windows included).
fn rel_slash_path(rel: &Path) -> String {
    rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/")
}

/// Pure inventory comparison: every discovered handler file must be
/// listed, every listed file must still be discovered, every file with
/// non-inline test gates must be structurally exempt, and every
/// helper mention without a direct call site must be reviewed. Returns
/// one human-readable problem per violation (empty when the reviewed
/// inventory matches reality).
fn inventory_problems(
    listed: &[(&str, usize)],
    structural_exempt: &[&str],
    mention_exempt: &[&str],
    inventory: &HandlerInventory,
) -> Vec<String> {
    let mut problems = Vec::new();
    for file in inventory.sites.keys() {
        if !listed.iter().any(|(listed_file, _)| listed_file == file) {
            problems.push(format!(
                "unlisted mechanism-bearing handler file: {file} \
                 (add it to WIRE_SITES with behavioral coverage, or remove its call site)"
            ));
        }
    }
    for (listed_file, _) in listed {
        if !inventory.sites.contains_key(*listed_file) {
            problems.push(format!(
                "stale WIRE_SITES entry: {listed_file} holds no call site anymore \
                 (move it to INVENTORY_EXEMPT with a reason, or drop it)"
            ));
        }
    }
    for file in &inventory.needs_structural {
        if !structural_exempt.contains(&file.as_str()) {
            problems.push(format!(
                "non-inline #[cfg(test)] gate in {file} \
                 (move test gates trailing or add a structural exemption with reason)"
            ));
        }
    }
    for file in structural_exempt {
        if !inventory.needs_structural.contains(*file) {
            problems.push(format!(
                "stale structural exemption: {file} has only inline test gates now; drop it"
            ));
        }
    }
    for file in &inventory.mentions_without_sites {
        if !mention_exempt.contains(&file.as_str()) {
            problems.push(format!(
                "unreviewed parse_mechanism mention in {file} without a direct call site \
                 (aliased import? add behavioral coverage plus listing, or exempt with reason)"
            ));
        }
    }
    problems
}

/// Re-validate every exemption entry against the real tree: a mention
/// exemption must still mention the helper and must hold zero call
/// sites; a structural exemption must still contain a non-inline gate
/// and must hold zero call sites.
fn exempt_problems(root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    for file in INVENTORY_EXEMPT {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let (code, _) = scannable_code(&text);
        let anchors = call_site_anchors(&code);
        if !anchors.is_empty() {
            problems.push(format!(
                "{file}: exempt file gained {} call site(s); move it to WIRE_SITES",
                anchors.len()
            ));
        } else if find_keyword(&code, 0, "parse_mechanism").is_none() {
            problems.push(format!(
                "{file}: stale mention exemption, no longer mentions parse_mechanism; drop it"
            ));
        }
    }
    for file in EARLY_GATE_EXEMPT {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let (code, needs_structural) = scannable_code(&text);
        let anchors = call_site_anchors(&code);
        if !anchors.is_empty() {
            problems.push(format!(
                "{file}: structurally exempt file gained {} call site(s); \
                 list it in WIRE_SITES too (it stays structurally exempt)",
                anchors.len()
            ));
        } else if !needs_structural {
            problems.push(format!(
                "{file}: stale structural exemption, all test gates are inline now; drop it"
            ));
        }
    }
    problems
}

/// S2 §6 gate order over one stripped anchor window: exclusion → auth →
/// transport validation → remap. `Ok` when every gate call is present in
/// order; `Err` naming the first violation otherwise. The window must be
/// comment/string-stripped: markers in comments or strings are not calls.
fn check_gate_order(
    file: &str,
    site: usize,
    stripped_window: &str,
    gates: &[&str],
) -> Result<(), String> {
    let mut positions = Vec::with_capacity(gates.len());
    for gate in gates {
        match stripped_window.find(gate) {
            Some(position) => positions.push(position),
            None => return Err(format!("{file} site {site}: missing gate {gate}")),
        }
    }
    let mut ordered = positions.clone();
    ordered.sort_unstable();
    if positions == ordered {
        Ok(())
    } else {
        Err(format!(
            "{file} site {site}: S2 §6 gate order violated \
             (want exclusion → auth → validation → remap)"
        ))
    }
}

#[test]
fn source_scan_pins_gate_order_at_every_wired_site() {
    let root = grpc_service_root();
    // Reverse discovery first: the reviewed list must equal reality before
    // the per-file order checks below mean anything.
    let inventory = discover_mechanism_handler_files(&root);
    let mut problems =
        inventory_problems(WIRE_SITES, EARLY_GATE_EXEMPT, INVENTORY_EXEMPT, &inventory);
    problems.extend(exempt_problems(&root));
    assert!(problems.is_empty(), "handler inventory drift:\n{}", problems.join("\n"));
    for (file, expected_anchors) in WIRE_SITES {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let (stripped, needs_structural) = scannable_code(&text);
        assert!(
            !needs_structural || EARLY_GATE_EXEMPT.contains(file),
            "{file}: listed file needs a structural exemption too"
        );
        let anchors = call_site_anchors(&stripped);
        assert_eq!(
            anchors.len(),
            *expected_anchors,
            "{file}: parse_mechanism( anchor count changed (new site or bypasser?)"
        );
        for (site, window) in anchors.windows(2).map(|w| &stripped[w[0]..w[1]]).enumerate() {
            check_gate_order(file, site, window, GATES).unwrap_or_else(|e| panic!("{e}"));
        }
        let last = anchors.last().map(|start| &stripped[*start..]).expect("at least one anchor");
        check_gate_order(file, anchors.len() - 1, last, GATES).unwrap_or_else(|e| panic!("{e}"));
    }
}

/// MAINT-03 negative control: gate markers that appear only in comments
/// or strings must NOT satisfy the order check. The pre-Q08 raw-substring
/// scan accepted this fixture; if comment stripping regresses, this
/// control fails.
#[test]
fn source_scan_rejects_comment_only_gate_markers() {
    let window = r#"
        let mechanism = match parse_mechanism(req.mechanism) {
            Ok(mechanism) => mechanism,
            Err(rv) => return Err(rv),
        };
        // S2 §6: check_operator_exclusion( before everything (a comment is not a call).
        /* mechanism_permitted( then validate_mechanism_transport(
           then remap_mechanism_handles( — all in a block comment. */
        let note = "validate_mechanism_transport(";
        backend_call(mechanism).await
    "#;
    let (stripped, _) = scannable_code(window);
    let result = check_gate_order("comment_only_fixture", 0, &stripped, GATES);
    assert!(
        result.is_err(),
        "comment-only gate markers must fail the S2 §6 order check, got {result:?}"
    );
}

/// MAINT-03 negative control: reverse discovery must flag a
/// mechanism-bearing handler file missing from the reviewed inventory. A
/// list-only scan (the pre-Q08 shape) never sees this file; if discovery
/// regresses to list-only, this control fails. The fixture also pins the
/// evasive forms: a comment split across the paren still counts as a
/// site, while an aliased import trips the mention tripwire.
#[test]
fn reverse_discovery_flags_unlisted_handler_file() {
    let dir = tempfile::tempdir().expect("fixture tempdir");
    std::fs::write(
        dir.path().join("wired.rs"),
        "fn wired(req: Req) -> Rv {\n    parse_mechanism(req.mechanism)\n}\n",
    )
    .expect("write listed fixture");
    std::fs::write(
        dir.path().join("sneaky_handler.rs"),
        "fn sneaky(req: Req) -> Rv {\n    let m = parse_mechanism(req.mechanism);\n    check_operator_exclusion(&r, m.mechanism_type)\n}\n",
    )
    .expect("write unlisted fixture");
    // A comment-only mention must not count as a handler file.
    std::fs::write(
        dir.path().join("comment_only.rs"),
        "// parse_mechanism( mentioned here, never called\nfn plain() {}\n",
    )
    .expect("write comment fixture");
    // A comment split across the paren still counts as a call site.
    std::fs::write(
        dir.path().join("split_paren.rs"),
        "fn split(req: Req) -> Rv {\n    parse_mechanism /* kept by rustfmt */ (req.mechanism)\n}\n",
    )
    .expect("write split-paren fixture");
    // An aliased import mentions the helper without a direct call site.
    std::fs::write(
        dir.path().join("aliased.rs"),
        "use crate::service_utils::parse_mechanism as pm;\nfn aliased(req: Req) -> Rv {\n    pm(req.mechanism)\n}\n",
    )
    .expect("write aliased fixture");
    let inventory = discover_mechanism_handler_files(dir.path());
    assert_eq!(
        inventory.sites.get("wired.rs"),
        Some(&1),
        "listed-shaped fixture must be discovered: {:?}",
        inventory.sites
    );
    assert_eq!(
        inventory.sites.get("sneaky_handler.rs"),
        Some(&1),
        "unlisted handler must be discovered: {:?}",
        inventory.sites
    );
    assert_eq!(
        inventory.sites.get("split_paren.rs"),
        Some(&1),
        "comment-split paren must still count as a site: {:?}",
        inventory.sites
    );
    assert!(
        !inventory.sites.contains_key("comment_only.rs"),
        "comment-only mention must not count as a handler file: {:?}",
        inventory.sites
    );
    assert!(
        !inventory.sites.contains_key("aliased.rs"),
        "aliased call has no direct site: {:?}",
        inventory.sites
    );
    assert!(
        inventory.mentions_without_sites.contains("aliased.rs"),
        "aliased import must trip the mention tripwire: {:?}",
        inventory.mentions_without_sites
    );
    let problems = inventory_problems(&[("wired.rs", 1)], &[], &[], &inventory);
    assert_eq!(problems.len(), 3, "unlisted, split-paren and aliased are problems: {problems:?}");
    for file in ["sneaky_handler.rs", "split_paren.rs", "aliased.rs"] {
        assert!(
            problems.iter().any(|p| p.contains(file)),
            "problems must name {file}: {problems:?}"
        );
    }
}

/// Test-gate shapes: trailing inline test modules are cut (their calls
/// contribute no sites), while early `mod foo;` declarations and mid-file
/// test items force structural treatment instead of a silent cut.
#[test]
fn inline_test_gates_cut_and_early_gates_need_structure() {
    let trailing = "fn handler(req: Req) -> Rv {\n    parse_mechanism(req.mechanism)\n}\n#[cfg(test)]\nmod tests {\n    fn t() {\n        parse_mechanism(None)\n    }\n}\n";
    let (code, needs_structural) = scannable_code(trailing);
    assert!(!needs_structural, "trailing inline module is cut-compatible");
    assert_eq!(call_site_anchors(&code).len(), 1, "test-region call is cut:\n{code}");

    let same_line = "fn h() {}\n#[cfg(test)] mod tests {\n    fn t() {}\n}\n";
    assert!(!scannable_code(same_line).1, "same-line inline module is cut-compatible");

    let early_decl = "#[cfg(test)]\nmod unit_tests;\nfn handler(req: Req) -> Rv {\n    parse_mechanism(req.mechanism)\n}\n";
    let (code, needs_structural) = scannable_code(early_decl);
    assert!(needs_structural, "early `mod foo;` needs structural treatment");
    assert_eq!(
        call_site_anchors(&code).len(),
        1,
        "production code after an early gate stays visible:\n{code}"
    );

    let mid_impl = "fn h() {}\n#[cfg(test)]\nimpl Ctx {\n    fn helper() {}\n}\n";
    assert!(scannable_code(mid_impl).1, "mid-file test impl needs structural treatment");

    // The structural exemption excuses the gate shape but not the
    // missing listing: the file still needs behavioral coverage.
    let dir = tempfile::tempdir().expect("fixture tempdir");
    std::fs::write(dir.path().join("early_gate.rs"), early_decl).expect("write fixture");
    let inventory = discover_mechanism_handler_files(dir.path());
    assert!(
        inventory.needs_structural.contains("early_gate.rs"),
        "early gate must be reported: {:?}",
        inventory.needs_structural
    );
    let unexcused = inventory_problems(&[], &[], &[], &inventory);
    assert!(
        unexcused.iter().any(|p| p.contains("non-inline")),
        "unexcused early gate is a problem: {unexcused:?}"
    );
    let excused = inventory_problems(&[], &["early_gate.rs"], &[], &inventory);
    assert!(
        excused.iter().all(|p| !p.contains("non-inline")),
        "structural exemption excuses the gate shape: {excused:?}"
    );
    assert!(
        excused.iter().any(|p| p.contains("early_gate.rs")),
        "structural exemption must not excuse the missing listing: {excused:?}"
    );
}

// ---------------------------------------------------------------------------
// Behavioral coverage (MAINT-03/Q08): a new handler cannot be covered by
// textual presence alone. Every `WIRE_SITES` file needs at least one
// behavioral battery per call site below, and every name below must
// resolve to a real test in this module (checked via the test binary's
// own `--list`). The gate pins membership, per-site count, and test
// existence; WHICH battery covers a file is review-checked — binding a
// test to the handler it executes would need execution tracing or import
// resolution, both outside the no-new-parser constraint (MAINT-03 names
// the behavioral batteries themselves the principal contract).
// ---------------------------------------------------------------------------

/// (handler file, behavioral battery tests exercising its call sites).
const BEHAVIORAL_COVERAGE: &[(&str, &[&str])] = &[
    (
        "message_crypto/mod.rs",
        &[
            "wired_message_encrypt_init_contract_preempts_params",
            "wired_message_encrypt_init_parameterless_accept",
            "wired_message_decrypt_init_contract_preempts_params",
            "wired_message_decrypt_init_parameterless_accept",
            "wired_message_sign_init",
            "wired_message_verify_init",
        ],
    ),
    ("digest_cipher/digest.rs", &["wired_digest_init"]),
    ("digest_cipher/cipher.rs", &["wired_encrypt_init", "wired_decrypt_init"]),
    (
        "key_ops/generation.rs",
        &["wired_generate_key_pair", "wired_generate_key", "wired_derive_key"],
    ),
    (
        "key_ops/kem.rs",
        &["wired_encapsulate_key", "wired_decapsulate_key", "wired_encapsulate_key_exact"],
    ),
    // `wrapping.rs` holds `unwrap_key`'s own site; `wrap_key` funnels
    // through `prepare_wrap` below.
    ("key_ops/wrapping.rs", &["wired_unwrap_key"]),
    ("key_ops/authenticated_wrap.rs", &["wired_unwrap_key_authenticated"]),
    // Shared `prepare_wrap` admission, exercised through ordinary wrap-key.
    ("key_ops/wrap_preparation.rs", &["wired_wrap_key"]),
    ("sign_verify/sign.rs", &["wired_sign_init", "wired_sign_recover_init"]),
    ("sign_verify/verify.rs", &["wired_verify_init", "wired_verify_recover_init"]),
    ("sign_verify/verify_signature.rs", &["wired_verify_signature_init"]),
];

/// Full test names (`<module>::<test>: test`) reported by this binary's
/// own `--list`. A renamed or deleted battery fails the coverage gate
/// instead of silently covering nothing.
fn listed_module_tests() -> String {
    let exe = std::env::current_exe().expect("current test executable");
    let output = std::process::Command::new(exe)
        .arg("--list")
        .output()
        .expect("list tests of current binary");
    assert!(
        output.status.success(),
        "--list of current test binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn behavioral_battery_covers_handler_inventory() {
    for (file, sites) in WIRE_SITES {
        let batteries = BEHAVIORAL_COVERAGE
            .iter()
            .find(|(covered_file, _)| covered_file == file)
            .map(|(_, tests)| *tests)
            .unwrap_or(&[]);
        assert!(
            batteries.len() >= *sites,
            "{file}: {sites} call site(s) need at least {sites} behavioral batteries, found {} \
             (textual gate presence alone is not coverage)",
            batteries.len()
        );
    }
    let listed = listed_module_tests();
    for (file, tests) in BEHAVIORAL_COVERAGE {
        assert!(
            WIRE_SITES.iter().any(|(listed_file, _)| listed_file == file),
            "{file}: coverage entry names a file outside WIRE_SITES"
        );
        for test in *tests {
            // libtest `--list` omits the crate-name segment that
            // `module_path!()` carries (`server::...`, not
            // `pkcs11_proxy_ng::server::...`).
            let listed_path = match module_path!().split_once("::") {
                Some((_, rest)) => rest,
                None => module_path!(),
            };
            let full = format!("{listed_path}::{test}: test");
            assert!(
                listed.contains(&full),
                "{file}: behavioral test {test} not found in this binary (--list)"
            );
        }
    }
}
