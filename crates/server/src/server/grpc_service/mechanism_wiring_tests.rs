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

use std::collections::BTreeMap;
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
use crate::consistency_checks::{skip_ws, strip_rust_code};
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
//     with a real (comment/string-stripped, `#[cfg(test)]`-excluded)
//     `parse_mechanism(` call site must be listed in `WIRE_SITES` — a new
//     handler file can no longer slip past the list. `INVENTORY_EXEMPT`
//     names the reviewed non-handler mentions; each exemption is
//     re-validated (still mentions the marker, still zero call sites).
//  2. Gate order over stripped code: gate markers sitting only in comments
//     or strings no longer satisfy the check (the pre-Q08 raw-substring
//     scan accepted them).
// No new Rust parser: comment/string handling is the existing
// `consistency_checks::strip_rust_code` tokenizer.
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

/// Reviewed non-handler files that textually mention `parse_mechanism(`.
/// Each exemption is re-validated on every run: the file must still
/// mention the marker (a stale exemption fails) and must hold zero real
/// call sites (a handler site fails and belongs in `WIRE_SITES`).
const INVENTORY_EXEMPT: &[&str] = &[
    // Holds the shared helper definition (`fn parse_mechanism(`), not a
    // handler call site.
    "service_utils.rs",
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

/// Production code of a handler file: the comment/string-stripped
/// source with every `#[cfg(test)]`-gated item blanked to spaces.
/// Test-gated regions sit in several shapes in-tree (trailing
/// `mod tests { ... }`, early `mod foo;` declarations in
/// `service_utils.rs`, a mid-file test `impl` in `context.rs`), so a
/// first-`#[cfg(test)]` cut would either scan test helpers as production
/// code or hide production code after an early gate. Blanking preserves
/// byte offsets. Only the exact `#[cfg(test)]` spelling is recognized;
/// exotic spellings (`#[cfg(all(test, ...))]`) would scan as production
/// code — none exist under `grpc_service/` today.
fn prod_code(text: &str) -> String {
    blank_cfg_test_regions(&strip_rust_code(text))
}

/// `stripped` (see [`strip_rust_code`]) with every `#[cfg(test)]`-gated
/// item blanked: `;`-terminated items (`mod foo;`) through their
/// semicolon, braced items (`mod tests { ... }`, `impl ... { ... }`,
/// `fn ... { ... }`) through their balanced closing brace. The `;`-vs-`{`
/// decision skips nested `(...)`/`[...]`, so a `;` inside a signature
/// (e.g. `[u8; 4]`) cannot end the item early. A malformed gate blanks
/// only the attribute itself, leaving the aftermath visible (fail-loud:
/// stray test code can only add anchors, never hide production sites).
fn blank_cfg_test_regions(stripped: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let mut out = stripped.as_bytes().to_vec();
    let mut search_from = 0;
    while let Some(rel) = stripped[search_from..].find(ATTR) {
        let attr_start = search_from + rel;
        let mut cursor = attr_start + ATTR.len();
        // Skip any further attributes (`#[allow(...)]`, ...) on the item.
        loop {
            cursor = skip_ws(stripped, cursor);
            if stripped[cursor..].starts_with("#[") {
                cursor = skip_balanced(stripped, cursor + 1, b'[', b']').unwrap_or(stripped.len());
            } else {
                break;
            }
        }
        let end = item_end(stripped, cursor).unwrap_or(attr_start + ATTR.len());
        blank_span(&mut out, attr_start, end);
        search_from = end;
    }
    String::from_utf8(out).expect("blanking preserves UTF-8 boundaries")
}

/// Offset just past the item starting at `cursor`: just past `;` for
/// declaration items, just past the balanced `}` for braced items.
/// `None` when the item is malformed (unbalanced, or a `}` arrives first).
fn item_end(stripped: &str, cursor: usize) -> Option<usize> {
    let bytes = stripped.as_bytes();
    let mut i = cursor;
    let mut paren = 0usize;
    let mut bracket = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => paren += 1,
            b'[' => bracket += 1,
            b')' => paren = paren.saturating_sub(1),
            b']' => bracket = bracket.saturating_sub(1),
            b';' if paren == 0 && bracket == 0 => return Some(i + 1),
            b'{' if paren == 0 && bracket == 0 => return skip_balanced(stripped, i, b'{', b'}'),
            b'}' if paren == 0 && bracket == 0 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

/// Offset just past the balanced `open..close` pair starting at `start`
/// (which must hold `open`), or `None` when unbalanced.
fn skip_balanced(text: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&open) {
        return None;
    }
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(start) {
        if *b == open {
            depth += 1;
        } else if *b == close {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
    }
    None
}

fn blank_span(out: &mut [u8], from: usize, to: usize) {
    let end = to.min(out.len());
    for b in &mut out[from..end] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

/// Byte offsets of real `parse_mechanism(` call sites in stripped code.
/// The shared helper definition (`fn parse_mechanism(`) is not a site.
fn call_site_anchors(stripped: &str) -> Vec<usize> {
    stripped
        .match_indices("parse_mechanism(")
        .map(|(index, _)| index)
        .filter(|index| !is_fn_definition(stripped, *index))
        .collect()
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

/// Reverse inventory discovery (MAINT-03): every `.rs` file under `root`
/// holding at least one real `parse_mechanism(` call site, mapped to its
/// site count. Keys are `/`-joined relative paths, so the table matches
/// `WIRE_SITES` on every platform.
fn discover_mechanism_handler_files(root: &Path) -> BTreeMap<String, usize> {
    let mut discovered = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries {
            let path =
                entry.unwrap_or_else(|e| panic!("read entry in {}: {e}", dir.display())).path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                let anchors = call_site_anchors(&prod_code(&text));
                if !anchors.is_empty() {
                    let rel = path.strip_prefix(root).unwrap_or_else(|_| {
                        panic!("{} escapes {}", path.display(), root.display())
                    });
                    discovered.insert(rel_slash_path(rel), anchors.len());
                }
            }
        }
    }
    discovered
}

/// `/`-joined relative path, so discovered keys match `WIRE_SITES` on
/// every platform (Windows included).
fn rel_slash_path(rel: &Path) -> String {
    rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/")
}

/// Pure inventory comparison: every discovered handler file must be
/// listed, and every listed file must still be discovered. Returns one
/// human-readable problem per violation (empty when the reviewed
/// inventory matches reality).
fn inventory_problems(
    listed: &[(&str, usize)],
    discovered: &BTreeMap<String, usize>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for file in discovered.keys() {
        if !listed.iter().any(|(listed_file, _)| listed_file == file) {
            problems.push(format!(
                "unlisted mechanism-bearing handler file: {file} \
                 (add it to WIRE_SITES with behavioral coverage, or remove its call site)"
            ));
        }
    }
    for (listed_file, _) in listed {
        if !discovered.contains_key(*listed_file) {
            problems.push(format!(
                "stale WIRE_SITES entry: {listed_file} holds no call site anymore \
                 (move it to INVENTORY_EXEMPT with a reason, or drop it)"
            ));
        }
    }
    problems
}

/// Re-validate every `INVENTORY_EXEMPT` entry against the real tree: an
/// exemption must still textually mention the marker and must hold zero
/// real call sites.
fn exempt_problems(root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    for file in INVENTORY_EXEMPT {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let anchors = call_site_anchors(&prod_code(&text));
        if !anchors.is_empty() {
            problems.push(format!(
                "{file}: exempt file gained {} call site(s); move it to WIRE_SITES",
                anchors.len()
            ));
        } else if !text.contains("parse_mechanism(") {
            problems.push(format!(
                "{file}: stale exemption, no longer mentions parse_mechanism(; drop it"
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
    let discovered = discover_mechanism_handler_files(&root);
    let mut problems = inventory_problems(WIRE_SITES, &discovered);
    problems.extend(exempt_problems(&root));
    assert!(problems.is_empty(), "handler inventory drift:\n{}", problems.join("\n"));
    for (file, expected_anchors) in WIRE_SITES {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let stripped = prod_code(&text);
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
    let stripped = prod_code(window);
    let result = check_gate_order("comment_only_fixture", 0, &stripped, GATES);
    assert!(
        result.is_err(),
        "comment-only gate markers must fail the S2 §6 order check, got {result:?}"
    );
}

/// MAINT-03 negative control: reverse discovery must flag a
/// mechanism-bearing handler file missing from the reviewed inventory. A
/// list-only scan (the pre-Q08 shape) never sees this file; if discovery
/// regresses to list-only, this control fails.
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
    let discovered = discover_mechanism_handler_files(dir.path());
    assert_eq!(
        discovered.get("wired.rs"),
        Some(&1),
        "listed-shaped fixture must be discovered: {discovered:?}"
    );
    assert_eq!(
        discovered.get("sneaky_handler.rs"),
        Some(&1),
        "unlisted handler must be discovered: {discovered:?}"
    );
    assert!(
        !discovered.contains_key("comment_only.rs"),
        "comment-only mention must not count as a handler file: {discovered:?}"
    );
    let problems = inventory_problems(&[("wired.rs", 1)], &discovered);
    assert_eq!(problems.len(), 1, "exactly the unlisted file is a problem: {problems:?}");
    assert!(
        problems[0].contains("sneaky_handler.rs"),
        "problem must name the unlisted file: {problems:?}"
    );
}

/// `#[cfg(test)]` handling must blank test-gated regions wherever they
/// sit: an early `mod foo;` declaration or a mid-file test `impl` (both
/// shapes exist in-tree — `service_utils.rs`, `context.rs`) must not
/// hide subsequent production code, and test-region calls must not
/// contribute sites.
#[test]
fn cfg_test_blanking_keeps_only_production_sites() {
    let src = r#"
#[cfg(test)]
mod unit_tests;
fn handler(req: Req) -> Rv {
    parse_mechanism(req.mechanism)
}
#[cfg(test)]
impl Ctx {
    fn helper() {
        parse_mechanism(None)
    }
}
fn second(req: Req) -> Rv {
    parse_mechanism(req.mechanism)
}
#[cfg(test)]
mod tests {
    fn t() {
        parse_mechanism(None)
    }
}
"#;
    let code = prod_code(src);
    assert_eq!(
        code.match_indices("parse_mechanism(").count(),
        2,
        "exactly the two production calls survive blanking:\n{code}"
    );
    assert_eq!(call_site_anchors(&code).len(), 2);
}

// ---------------------------------------------------------------------------
// Behavioral coverage (MAINT-03/Q08): a new handler cannot be covered by
// textual presence alone. Every `WIRE_SITES` file needs at least one
// behavioral battery below, and every name below must resolve to a real
// test in this module (checked via the test binary's own `--list`).
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
    for (file, _) in WIRE_SITES {
        let covered = BEHAVIORAL_COVERAGE
            .iter()
            .any(|(covered_file, tests)| covered_file == file && !tests.is_empty());
        assert!(
            covered,
            "{file}: listed handler file has no behavioral battery \
             (textual gate presence alone is not coverage)"
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
