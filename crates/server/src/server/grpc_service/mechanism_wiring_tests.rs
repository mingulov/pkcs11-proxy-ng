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
// Source-scan assertion (R14 extends to all sites): at every `parse_mechanism(`
// call site in the wired handler files, the S2 §6 gate order holds
// textually: exclusion → auth → transport validation → remap. The anchor
// count per file also pins the no-bypass invariant (a new `parse_mechanism(`
// caller without the gates fails this test).
// ---------------------------------------------------------------------------

#[test]
fn source_scan_pins_gate_order_at_every_wired_site() {
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
    const GATES: &[&str] = &[
        "check_operator_exclusion(",
        "mechanism_permitted(",
        "validate_mechanism_transport(",
        "remap_mechanism_handles(",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server/grpc_service");
    for (file, expected_anchors) in WIRE_SITES {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        // Test helpers trail the prod code; scan the prod head only.
        let prod = match text.find("#[cfg(test)]") {
            Some(cut) => &text[..cut],
            None => text.as_str(),
        };
        let anchors: Vec<usize> =
            prod.match_indices("parse_mechanism(").map(|(index, _)| index).collect();
        assert_eq!(
            anchors.len(),
            *expected_anchors,
            "{file}: parse_mechanism( anchor count changed (new site or bypasser?)"
        );
        for (site, window) in anchors.windows(2).map(|w| &prod[w[0]..w[1]]).enumerate() {
            assert_gate_order(file, site, window, GATES);
        }
        let last = anchors.last().map(|start| &prod[*start..]).expect("at least one anchor");
        assert_gate_order(file, anchors.len() - 1, last, GATES);
    }
}

fn assert_gate_order(file: &str, site: usize, window: &str, gates: &[&str]) {
    let mut positions = Vec::with_capacity(gates.len());
    for gate in gates {
        let position =
            window.find(gate).unwrap_or_else(|| panic!("{file} site {site}: missing gate {gate}"));
        positions.push(position);
    }
    let mut ordered = positions.clone();
    ordered.sort_unstable();
    assert_eq!(
        positions, ordered,
        "{file} site {site}: S2 §6 gate order violated (want exclusion → auth → validation → remap)"
    );
}
