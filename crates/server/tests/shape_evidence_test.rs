// W1-L12-03: test diagnostics (skip notices, receipts, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! Q07 (MAINT-02) shape-evidence controls: attempted vs init-accepted vs
//! native-entered vs success, with backend-admission discrimination.
//!
//! The 79-shape SoftHSM2 driver classifies every RPC outcome WITHOUT native
//! entry evidence: `Ok` from a COMPLETING operation (derive, wrap) is a
//! successful real-provider operation (no local layer synthesizes `Ok` on
//! the driver's op paths), `Ok` from an init-only call is merely
//! init-accepted (operation state opened, no cryptographic work done —
//! NEVER qualifying), while any error RV is merely *attempted* —
//! RPC-completed, origin unproven — because the same RV value can come
//! from server transport validation, backend FFI reconstruction, or the
//! provider itself. No RV alone proves origin.
//!
//! This file pins that taxonomy twice:
//!
//! * Default-run unit tests pin the shared classifier in
//!   [`support::shape_matrix`](mod@support) (RV-only mapping, entry-record
//!   mapping, receipt-line grammar, transport-acceptance pin). No provider
//!   needed.
//! * Ignored oracle controls drive the full stack (client -> gRPC -> server
//!   handlers -> counting backend -> `FfiBackend` -> native oracle) against
//!   the entry-recording oracle and assert, with an independent backend
//!   admission count AND an independent native entry count, that the
//!   server-local reject admits the backend zero times, the
//!   backend-reconstruction reject admits it once without native entry,
//!   and the genuine native error admits it once with one native entry —
//!   all three sharing one bit-identical RV. Server-local and
//!   backend-local rejects earn no native-entry credit; the genuine native
//!   error earns native-entry credit but NOT success credit.
//!
//! Run the default unit tests with:
//! ```sh
//! cargo test -p pkcs11-proxy-ng --test shape_evidence_test -- --test-threads=1
//! ```
//!
//! Build the oracle, then run the ignored controls with:
//! ```sh
//! cargo build --locked --manifest-path tests/ffi_oracles/entry_recording/Cargo.toml
//! PKCS11_PROXY_ENTRY_RECORDING_ORACLE_LIB="$PWD/tests/ffi_oracles/entry_recording/target/debug/libpkcs11_entry_recording_oracle.so" \
//!   cargo test --locked -p pkcs11-proxy-ng --test shape_evidence_test \
//!   -- --ignored --test-threads=1 --nocapture
//! ```

mod support;

#[allow(dead_code)]
#[path = "../../../tests/ffi_oracles/entry_recording/src/lib.rs"]
mod oracle_types;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use libloading::Library;
use oracle_types::{EntryRecordingObservation, EntryRecordingScenario};
use pkcs11_proxy_ng::server::{context_manager::ContextManager, grpc_service::Pkcs11ProxyService};
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_types::shape_descriptors::{Operation, ParamAbi};
use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkAttributeValue, CkInBuf, CkInfo, CkMechanism, CkMechanismInfo,
    CkMechanismParams, CkMechanismType, CkObjectClass, CkObjectHandle, CkResult, CkRv,
    CkSessionFlags, CkSessionHandle, CkSessionInfo, CkSlotId, CkSlotInfo, CkTokenInfo, CkUserType,
    GcmParams, InterfaceCapabilities, IvParams, MechanismRegistry, PointerBytes,
    RawMechanismParams, SecretBytes, ValidatedMechanismParams,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use support::{
    MatrixReceipt, NativeObservation, ShapeDisposition, ShapeOpClass, ShapeOutcome,
    classify_rv_only, classify_with_entry_record, find_token_slot, format_matrix_summary,
    format_shape_line, initialized_client, open_public_session,
};

// ---------------------------------------------------------------------------
// Default-run taxonomy unit tests (no provider needed)
// ---------------------------------------------------------------------------

#[test]
fn shape_disposition_tags_are_stable() {
    assert_eq!(ShapeDisposition::Success.tag(), "success");
    assert_eq!(ShapeDisposition::InitAccepted.tag(), "init-accepted");
    assert_eq!(ShapeDisposition::Attempted.tag(), "attempted");
    assert_eq!(ShapeDisposition::NativeEntered.tag(), "native-entered");
}

#[test]
fn shape_outcome_constructors_carry_disposition_and_rv() {
    let ok = ShapeOutcome::success("derive ok".to_string());
    assert_eq!(ok.disposition, ShapeDisposition::Success);
    assert_eq!(ok.rv, None);

    let init = ShapeOutcome::init_accepted("sign-init ok".to_string());
    assert_eq!(init.disposition, ShapeDisposition::InitAccepted);
    assert_eq!(init.rv, None);

    // Native RVs are preserved on the outcome: the taxonomy re-labels the
    // evidence, it never rewrites the provider's own return value.
    let err = ShapeOutcome::attempted(
        CkRv::MECHANISM_PARAM_INVALID,
        "encrypt-init -> CKR_MECHANISM_PARAM_INVALID".to_string(),
    );
    assert_eq!(err.disposition, ShapeDisposition::Attempted);
    assert_eq!(err.rv, Some(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn classify_rv_only_separates_init_acceptance_from_meaningful_success() {
    // M1: only a COMPLETING operation's Ok is meaningful success. An
    // init-only Ok (e.g. Eddsa `sign-init ok`, which never signs) is init
    // acceptance — explicitly unqualified.
    let ok: Result<(), CkRv> = Ok(());
    assert_eq!(classify_rv_only(&ok, ShapeOpClass::Meaningful), ShapeDisposition::Success);
    assert_eq!(classify_rv_only(&ok, ShapeOpClass::InitOnly), ShapeDisposition::InitAccepted);

    // Every error RV — including ones real providers return — is merely
    // attempted without entry evidence, for both op classes: no RV alone
    // proves origin.
    for rv in [
        CkRv::MECHANISM_PARAM_INVALID,
        CkRv::ARGUMENTS_BAD,
        CkRv::KEY_TYPE_INCONSISTENT,
        CkRv::MECHANISM_INVALID,
        CkRv::DEVICE_ERROR,
    ] {
        let err: Result<(), CkRv> = Err(rv);
        for op in [ShapeOpClass::Meaningful, ShapeOpClass::InitOnly] {
            assert_eq!(
                classify_rv_only(&err, op),
                ShapeDisposition::Attempted,
                "rv={rv} op={op:?}"
            );
        }
    }
}

#[test]
fn classify_with_entry_record_distinguishes_origin() {
    let err: Result<(), CkRv> = Err(CkRv::MECHANISM_PARAM_INVALID);
    for op in [ShapeOpClass::Meaningful, ShapeOpClass::InitOnly] {
        assert_eq!(
            classify_with_entry_record(&err, 0, op),
            ShapeDisposition::Attempted,
            "error without entry is attempted, never native-entered (op={op:?})"
        );
        assert_eq!(
            classify_with_entry_record(&err, 1, op),
            ShapeDisposition::NativeEntered,
            "error with entry record earns native-entry credit (op={op:?})"
        );
        assert_eq!(
            classify_with_entry_record(&err, 7, op),
            ShapeDisposition::NativeEntered,
            "entry count above one is still native-entered, not success (op={op:?})"
        );
    }

    // Success needs no entry record: no local layer on the driver's op
    // paths synthesizes Ok (every pre-backend handler return carries an
    // error RV; every Ok flows from a backend Ok).
    let ok: Result<(), CkRv> = Ok(());
    assert_eq!(
        classify_with_entry_record(&ok, 0, ShapeOpClass::Meaningful),
        ShapeDisposition::Success
    );
    assert_eq!(
        classify_with_entry_record(&ok, 3, ShapeOpClass::Meaningful),
        ShapeDisposition::Success
    );
    // ...but an entry record never promotes init-only Ok to meaningful
    // success: entry evidence proves origin, not completed work.
    assert_eq!(
        classify_with_entry_record(&ok, 0, ShapeOpClass::InitOnly),
        ShapeDisposition::InitAccepted
    );
    assert_eq!(
        classify_with_entry_record(&ok, 2, ShapeOpClass::InitOnly),
        ShapeDisposition::InitAccepted
    );
}

#[test]
fn same_rv_without_entry_record_is_not_native_evidence() {
    // The Q07 crux in one assertion: the RV value carries zero origin
    // information, so identical RVs with and without an entry record
    // classify differently. The oracle lane drives encrypt-init (init-only).
    let err: Result<(), CkRv> = Err(CkRv::MECHANISM_PARAM_INVALID);
    assert_ne!(
        classify_with_entry_record(&err, 0, ShapeOpClass::InitOnly),
        classify_with_entry_record(&err, 1, ShapeOpClass::InitOnly),
    );
    assert_eq!(
        classify_with_entry_record(&err, 1, ShapeOpClass::InitOnly),
        ShapeDisposition::NativeEntered
    );
    assert_ne!(
        classify_with_entry_record(&err, 1, ShapeOpClass::InitOnly),
        ShapeDisposition::Success
    );
}

#[test]
fn init_only_ok_never_earns_success_credit() {
    // M1 pin across both classifiers and both constructors: init-only Ok
    // is InitAccepted, never Success, with or without an entry record.
    let ok: Result<(), CkRv> = Ok(());
    for entries in [0, 1, 5] {
        assert_eq!(
            classify_with_entry_record(&ok, entries, ShapeOpClass::InitOnly),
            ShapeDisposition::InitAccepted,
            "entries={entries}"
        );
    }
    assert_eq!(classify_rv_only(&ok, ShapeOpClass::InitOnly), ShapeDisposition::InitAccepted);
    assert_ne!(
        ShapeOutcome::init_accepted("sign-init ok".to_string()).disposition,
        ShapeDisposition::Success
    );
}

#[test]
fn shape_line_grammar_carries_disposition() {
    let detail = format!("encrypt-init -> {}", CkRv::MECHANISM_PARAM_INVALID);
    let outcome = ShapeOutcome::attempted(CkRv::MECHANISM_PARAM_INVALID, detail.clone());
    assert_eq!(
        format_shape_line("Iv", CkMechanismType::AES_CBC.0, &outcome),
        format!("shape Iv (0x00001082): [attempted] {detail}")
    );

    // Success lines carry completing-operation detail only: init-only Ok
    // (e.g. `encrypt-init ok`) can no longer appear under [success].
    let ok = ShapeOutcome::success("derive ok".to_string());
    assert_eq!(
        format_shape_line("Ecdh1Derive", CkMechanismType::ECDH1_DERIVE.0, &ok),
        "shape Ecdh1Derive (0x00001050): [success] derive ok"
    );

    let init = ShapeOutcome::init_accepted("sign-init ok".to_string());
    assert_eq!(
        format_shape_line("Eddsa", CkMechanismType::EDDSA.0, &init),
        "shape Eddsa (0x00001057): [init-accepted] sign-init ok"
    );
}

#[test]
fn matrix_summary_grammar_carries_separate_counts() {
    // Receipt grammar: meaningful-success, init-accepted (unqualified),
    // attempted (origin unproven), native-entered (entry-proven), and
    // unsupported-skipped are separate counts, plus the derived
    // RPC-observed total and the explicit native-observation status. Only
    // meaningful success qualifies; the oracle lane's native-entry shapes
    // qualify only with their entry-record scope limitation (see the
    // ignored controls below).
    let driver = MatrixReceipt {
        meaningful_success: 0,
        init_accepted: 4,
        attempted: 5,
        native_entered: 0,
        unsupported_skipped: 70,
        total: 79,
        native_observation: NativeObservation::Unavailable { lane: "softhsm2-driver" },
    };
    driver.assert_conserved();
    assert_eq!(driver.rpc_observed(), 9, "rpc-observed derives from the four RPC buckets");
    assert_eq!(
        driver.qualified(),
        0,
        "init-accepted/attempted/native-entered/skipped never qualify"
    );
    assert_eq!(
        format_matrix_summary(&driver),
        "shape matrix: 0 meaningful-success, 4 init-accepted (unqualified), 5 attempted \
         (origin unproven), 0 native-entered (entry-proven), 70 unsupported-skipped \
         (79 total; 9 rpc-observed; \
         native-observation: unavailable (softhsm2-driver; no entry record))"
    );

    // The observed variant accounts its entry-proven RPC in the
    // native-entered bucket (oracle lane): 2 attempted + 1 native-entered
    // over 3 controls, all RPC-observed.
    let oracle = MatrixReceipt {
        meaningful_success: 0,
        init_accepted: 0,
        attempted: 2,
        native_entered: 1,
        unsupported_skipped: 0,
        total: 3,
        native_observation: NativeObservation::Observed { entries: 1 },
    };
    oracle.assert_conserved();
    assert_eq!(oracle.rpc_observed(), 3);
    assert_eq!(oracle.qualified(), 0);
    assert_eq!(
        format_matrix_summary(&oracle),
        "shape matrix: 0 meaningful-success, 0 init-accepted (unqualified), 2 attempted \
         (origin unproven), 1 native-entered (entry-proven), 0 unsupported-skipped \
         (3 total; 3 rpc-observed; native-observation: observed (entries=1))"
    );
}

#[test]
fn oracle_receipt_grammar_carries_identity_shape_and_limitation() {
    // M2: every oracle receipt names its provider, tested shape/function,
    // both admission counts, the disposition, and the entry-only scope
    // limitation — the limitation the coverage doc promises.
    let line = format_oracle_receipt(
        "backend-reject",
        "Gcm",
        "encrypt-init",
        CkRv::MECHANISM_PARAM_INVALID,
        1,
        0,
        ShapeDisposition::Attempted,
    );
    assert_eq!(
        line,
        format!(
            "shape-evidence backend-reject: provider=entry-recording-oracle shape=Gcm \
             op=encrypt-init rv={} backend_admissions=1 native_entries=0 disposition=attempted \
             scope=\"entry-only; no cryptographic/provider qualification\"",
            CkRv::MECHANISM_PARAM_INVALID,
        )
    );
}

/// Mirror of the daemon's validation ABIs
/// (`daemon_validation_abis` in `mechanism_input.rs`, private to the
/// server crate): the deciding edge's native ABI plus the backend
/// `CK_ULONG` width. Kept in this test so the transport pin below runs
/// the exact public-API half of the daemon's own check.
fn daemon_abis_for_pin() -> (ParamAbi, ParamAbi) {
    let width_abi = if pkcs11_proxy_ng_backend::host_abi::host_ulong_size() >= 8 {
        ParamAbi::Lp64NativeLe
    } else {
        ParamAbi::Ilp32NativeLe
    };
    (ParamAbi::native().unwrap_or(width_abi), width_abi)
}

/// m3: pin transport acceptance of the ignored controls' fixtures through
/// the public validation API over the embedded default registry — the
/// same registry the test server loads. The Raw server-local fixture must
/// reject here (so the control's zero admissions prove a local reject),
/// while the GCM reconstruction fixture must PASS here (so that control's
/// single admission proves transport acceptance before the backend's own
/// 512 MiB `gcm_iv_capacity` reject).
#[test]
fn gcm_reconstruction_fixture_passes_transport_while_raw_rejects() {
    let registry = MechanismRegistry::load(None).expect("embedded default registry must load");
    let (local_abi, backend_abi) = daemon_abis_for_pin();

    let raw = ValidatedMechanismParams::validate(
        &raw_aes_cbc_mechanism(),
        &registry,
        Operation::General,
        local_abi,
        backend_abi,
    );
    assert_eq!(
        raw.unwrap_err(),
        CkRv::MECHANISM_PARAM_INVALID,
        "Raw params must reject in transport validation"
    );

    assert!(
        ValidatedMechanismParams::validate(
            &gcm_huge_mechanism(),
            &registry,
            Operation::General,
            local_abi,
            backend_abi,
        )
        .is_ok(),
        "GCM reconstruction fixture must pass transport validation"
    );
    assert!(
        ValidatedMechanismParams::validate(
            &iv_aes_cbc_mechanism(),
            &registry,
            Operation::General,
            local_abi,
            backend_abi,
        )
        .is_ok(),
        "native-entry fixture must pass transport validation"
    );
}

// ---------------------------------------------------------------------------
// Ignored oracle controls (entry-recording provider behind the full stack)
// ---------------------------------------------------------------------------

/// Environment variable pointing at the built entry-recording oracle cdylib.
const ORACLE_LIB_ENV: &str = "PKCS11_PROXY_ENTRY_RECORDING_ORACLE_LIB";

/// m3: `FfiBackend` wrapper that records backend `encrypt_init` admissions
/// separately from the oracle's native entry count. A server-local reject
/// never reaches the backend (0 admissions); a backend-reconstruction
/// reject is admitted once but never enters native code (1 admission, 0
/// entries); a genuine native error is admitted once with one entry (1/1).
/// The counter increments on backend ENTRY, before `mechanism_to_ffi`, so
/// reconstruction rejects still count as admissions.
///
/// Every other required trait method delegates verbatim, plus parity
/// forwards for the lifecycle/capability/output-params defaults
/// `FfiBackend` overrides. The remaining defaulted families
/// (cancel/exact-output/message/async/3.x) keep trait defaults: each
/// control below issues exactly one `encrypt_init` RPC plus session
/// lifecycle calls, so those paths are unreachable here.
struct AdmissionCountingBackend {
    inner: FfiBackend,
    encrypt_init_admissions: Arc<AtomicU64>,
}

impl Pkcs11Backend for AdmissionCountingBackend {
    fn encrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.encrypt_init_admissions.fetch_add(1, Ordering::SeqCst);
        self.inner.encrypt_init(session, mechanism, key)
    }

    // Parity forwards: defaulted methods `FfiBackend` overrides that this
    // harness could plausibly reach (lifecycle, capability queries,
    // quarantine cleanup, cached mechanism output).
    fn finalize_with_grace(&self, grace: std::time::Duration) -> CkResult<()> {
        self.inner.finalize_with_grace(grace)
    }

    fn finalize_is_natively_bounded(&self) -> bool {
        self.inner.finalize_is_natively_bounded()
    }

    fn admit_slot_wait(&self, flags: u64) -> CkResult<()> {
        self.inner.admit_slot_wait(flags)
    }

    fn destroy_quarantined_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.destroy_quarantined_object(session, object)
    }

    fn session_output_mechanism_params(
        &self,
        session: CkSessionHandle,
    ) -> Option<CkMechanismParams> {
        self.inner.session_output_mechanism_params(session)
    }

    fn get_interface_capabilities(&self) -> InterfaceCapabilities {
        self.inner.get_interface_capabilities()
    }

    // Verbatim delegations for the remaining required trait methods
    // (signatures mirror `crates/backend/src/traits.rs`).
    fn initialize(&self) -> CkResult<()> {
        self.inner.initialize()
    }

    fn finalize(&self) -> CkResult<()> {
        self.inner.finalize()
    }

    fn get_info(&self) -> CkResult<CkInfo> {
        self.inner.get_info()
    }

    fn get_slot_list(&self, token_present: bool) -> CkResult<Vec<CkSlotId>> {
        self.inner.get_slot_list(token_present)
    }

    fn get_slot_info(&self, slot_id: CkSlotId) -> CkResult<CkSlotInfo> {
        self.inner.get_slot_info(slot_id)
    }

    fn get_token_info(&self, slot_id: CkSlotId) -> CkResult<CkTokenInfo> {
        self.inner.get_token_info(slot_id)
    }

    fn get_mechanism_list(&self, slot_id: CkSlotId) -> CkResult<Vec<CkMechanismType>> {
        self.inner.get_mechanism_list(slot_id)
    }

    fn get_mechanism_info(
        &self,
        slot_id: CkSlotId,
        mech: CkMechanismType,
    ) -> CkResult<CkMechanismInfo> {
        self.inner.get_mechanism_info(slot_id, mech)
    }

    fn init_token(&self, slot_id: CkSlotId, so_pin: Option<&[u8]>, label: &str) -> CkResult<()> {
        self.inner.init_token(slot_id, so_pin, label)
    }

    fn init_pin(&self, session: CkSessionHandle, pin: Option<&[u8]>) -> CkResult<()> {
        self.inner.init_pin(session, pin)
    }

    fn set_pin(
        &self,
        session: CkSessionHandle,
        old_pin: Option<&[u8]>,
        new_pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.inner.set_pin(session, old_pin, new_pin)
    }

    fn open_session(&self, slot_id: CkSlotId, flags: CkSessionFlags) -> CkResult<CkSessionHandle> {
        self.inner.open_session(slot_id, flags)
    }

    fn close_session(&self, session: CkSessionHandle) -> CkResult<()> {
        self.inner.close_session(session)
    }

    fn close_all_sessions(&self, slot_id: CkSlotId) -> CkResult<()> {
        self.inner.close_all_sessions(slot_id)
    }

    fn get_session_info(&self, session: CkSessionHandle) -> CkResult<CkSessionInfo> {
        self.inner.get_session_info(session)
    }

    fn login(
        &self,
        session: CkSessionHandle,
        user_type: CkUserType,
        pin: Option<&[u8]>,
    ) -> CkResult<()> {
        self.inner.login(session, user_type, pin)
    }

    fn logout(&self, session: CkSessionHandle) -> CkResult<()> {
        self.inner.logout(session)
    }

    fn find_objects_init(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        self.inner.find_objects_init(session, template)
    }

    fn find_objects(
        &self,
        session: CkSessionHandle,
        max_count: u32,
    ) -> CkResult<Vec<CkObjectHandle>> {
        self.inner.find_objects(session, max_count)
    }

    fn find_objects_final(&self, session: CkSessionHandle) -> CkResult<()> {
        self.inner.find_objects_final(session)
    }

    fn get_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: &mut [CkAttribute],
    ) -> CkResult<()> {
        self.inner.get_attribute_value(session, object, template)
    }

    fn sign_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.sign_init(session, mechanism, key)
    }

    fn sign(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.sign(session, data)
    }

    fn sign_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()> {
        self.inner.sign_update(session, part)
    }

    fn sign_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.sign_final(session)
    }
    fn digest_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.digest_encrypt_update(session, part)
    }

    fn decrypt_digest_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.decrypt_digest_update(session, encrypted_part)
    }

    fn sign_encrypt_update(
        &self,
        session: CkSessionHandle,
        part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.sign_encrypt_update(session, part)
    }

    fn decrypt_verify_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.decrypt_verify_update(session, encrypted_part)
    }

    fn sign_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.sign_recover_init(session, mechanism, key)
    }

    fn sign_recover(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.sign_recover(session, data)
    }

    fn verify_recover_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.verify_recover_init(session, mechanism, key)
    }

    fn verify_recover(
        &self,
        session: CkSessionHandle,
        signature: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.verify_recover(session, signature)
    }

    fn verify_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        key: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.verify_init(session, mechanism, key)
    }

    fn verify(
        &self,
        session: CkSessionHandle,
        data: CkInBuf<'_>,
        signature: CkInBuf<'_>,
    ) -> CkResult<()> {
        self.inner.verify(session, data, signature)
    }

    fn verify_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()> {
        self.inner.verify_update(session, part)
    }

    fn verify_final(&self, session: CkSessionHandle, signature: CkInBuf<'_>) -> CkResult<()> {
        self.inner.verify_final(session, signature)
    }

    fn create_object(
        &self,
        session: CkSessionHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.create_object(session, template)
    }

    fn copy_object(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.copy_object(session, object, template)
    }

    fn destroy_object(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<()> {
        self.inner.destroy_object(session, object)
    }

    fn get_object_size(&self, session: CkSessionHandle, object: CkObjectHandle) -> CkResult<u64> {
        self.inner.get_object_size(session, object)
    }

    fn set_attribute_value(
        &self,
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<()> {
        self.inner.set_attribute_value(session, object, template)
    }

    fn digest_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
    ) -> CkResult<()> {
        self.inner.digest_init(session, mechanism)
    }

    fn digest(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.digest(session, data)
    }

    fn digest_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<()> {
        self.inner.digest_update(session, part)
    }

    fn digest_key(&self, session: CkSessionHandle, key: CkObjectHandle) -> CkResult<()> {
        self.inner.digest_key(session, key)
    }

    fn digest_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.digest_final(session)
    }

    fn encrypt(&self, session: CkSessionHandle, data: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.encrypt(session, data)
    }

    fn encrypt_update(&self, session: CkSessionHandle, part: CkInBuf<'_>) -> CkResult<SecretBytes> {
        self.inner.encrypt_update(session, part)
    }

    fn encrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.encrypt_final(session)
    }
    fn decrypt_init(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        key: CkObjectHandle,
    ) -> CkResult<Option<CkMechanismParams>> {
        self.inner.decrypt_init(session, mechanism, key)
    }

    fn decrypt(
        &self,
        session: CkSessionHandle,
        encrypted_data: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.decrypt(session, encrypted_data)
    }

    fn decrypt_update(
        &self,
        session: CkSessionHandle,
        encrypted_part: CkInBuf<'_>,
    ) -> CkResult<SecretBytes> {
        self.inner.decrypt_update(session, encrypted_part)
    }

    fn decrypt_final(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.decrypt_final(session)
    }

    fn derive_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        base_key: CkObjectHandle,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.derive_key(session, mechanism, base_key, template)
    }

    fn wrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        wrapping_key: CkObjectHandle,
        key: CkObjectHandle,
    ) -> CkResult<SecretBytes> {
        self.inner.wrap_key(session, mechanism, wrapping_key, key)
    }

    fn unwrap_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        unwrapping_key: CkObjectHandle,
        wrapped_key: CkInBuf<'_>,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.unwrap_key(session, mechanism, unwrapping_key, wrapped_key, template)
    }

    fn generate_key(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        template: Option<&[CkAttribute]>,
    ) -> CkResult<CkObjectHandle> {
        self.inner.generate_key(session, mechanism, template)
    }

    fn generate_key_pair(
        &self,
        session: CkSessionHandle,
        mechanism: &ValidatedMechanismParams,
        pub_template: Option<&[CkAttribute]>,
        priv_template: Option<&[CkAttribute]>,
    ) -> CkResult<(CkObjectHandle, CkObjectHandle)> {
        self.inner.generate_key_pair(session, mechanism, pub_template, priv_template)
    }

    fn wait_for_slot_event(&self, flags: u64) -> CkResult<CkSlotId> {
        self.inner.wait_for_slot_event(flags)
    }

    fn get_operation_state(&self, session: CkSessionHandle) -> CkResult<SecretBytes> {
        self.inner.get_operation_state(session)
    }

    fn set_operation_state(
        &self,
        session: CkSessionHandle,
        state: CkInBuf<'_>,
        enc_key: CkObjectHandle,
        auth_key: CkObjectHandle,
    ) -> CkResult<()> {
        self.inner.set_operation_state(session, state, enc_key, auth_key)
    }

    fn seed_random(&self, session: CkSessionHandle, seed: CkInBuf<'_>) -> CkResult<()> {
        self.inner.seed_random(session, seed)
    }

    fn generate_random(&self, session: CkSessionHandle, len: u32) -> CkResult<SecretBytes> {
        self.inner.generate_random(session, len)
    }
}

/// Full-stack harness: real gRPC server handlers + admission-counting
/// `FfiBackend` over the recording oracle, driven by the real async
/// client. Mirrors the `noncontract_begin_health_test` in-process server
/// shape.
struct EvidenceHarness {
    client: Pkcs11Client,
    session: CkSessionHandle,
    key: CkObjectHandle,
    oracle: Library,
    backend: Arc<dyn Pkcs11Backend>,
    encrypt_init_admissions: Arc<AtomicU64>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl EvidenceHarness {
    async fn start() -> Result<Self, String> {
        let Some(path) = std::env::var_os(ORACLE_LIB_ENV).map(PathBuf::from) else {
            return Err(support::fail_explicit_skip(support::SkipReason::ProviderMissing(
                "entry-recording-oracle",
            )));
        };
        if !path.is_file() {
            return Err(format!(
                "{ORACLE_LIB_ENV} does not identify a built library: {}",
                path.display()
            ));
        }
        // Same-path dlopen shares the oracle instance: the backend drives
        // one handle while this control handle reads the same observation.
        let oracle = unsafe { Library::new(&path) }
            .map_err(|e| format!("load oracle control handle failed: {e}"))?;
        let encrypt_init_admissions = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(AdmissionCountingBackend {
            inner: FfiBackend::load(&path).map_err(|e| format!("load oracle backend: {e}"))?,
            encrypt_init_admissions: encrypt_init_admissions.clone(),
        }) as Arc<dyn Pkcs11Backend>;
        backend.initialize().map_err(|rv| format!("C_Initialize failed: {rv}"))?;
        let contexts = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        contexts.populate_slots(&backend).await.map_err(|rv| format!("populate_slots: {rv}"))?;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let endpoint = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let service = Pkcs11ProxyServer::new(Pkcs11ProxyService::insecure_for_tests(
            contexts,
            backend.clone(),
        ));
        let server = tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = stopped.await;
                })
                .await;
        });

        let mut client = initialized_client(&endpoint).await?;
        let slot = find_token_slot(&mut client).await?;
        let session = open_public_session(&mut client, slot, true).await?;
        let template = vec![
            CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
            },
            CkAttribute {
                attr_type: CkAttributeType::KEY_TYPE,
                value: Some(CkAttributeValue::Ulong(support::CKK_GENERIC_SECRET)),
            },
            CkAttribute {
                attr_type: CkAttributeType::TOKEN,
                value: Some(CkAttributeValue::Bool(false)),
            },
        ];
        let key = client
            .create_object(session, Some(&template))
            .await
            .map_err(|rv| format!("C_CreateObject failed: {rv}"))?;

        Ok(Self {
            client,
            session,
            key,
            oracle,
            backend,
            encrypt_init_admissions,
            stop: Some(stop),
            server: Some(server),
        })
    }

    /// Backend `encrypt_init` admissions so far: 0 means the server
    /// rejected locally, before the backend was admitted.
    fn backend_admissions(&self) -> u64 {
        self.encrypt_init_admissions.load(Ordering::SeqCst)
    }

    fn reset_observation(&self) -> Result<(), String> {
        unsafe {
            let reset = self
                .oracle
                .get::<unsafe extern "C" fn() -> u32>(b"EntryRecording_ResetObservation\0")
                .map_err(|e| format!("missing ResetObservation export: {e}"))?;
            if reset() != 0 {
                return Err("ResetObservation failed".to_string());
            }
        }
        Ok(())
    }

    fn set_scenario_rv(&self, init_rv: CkRv) -> Result<(), String> {
        unsafe {
            let scenario = EntryRecordingScenario { init_rv: init_rv.0 };
            let set = self
                .oracle
                .get::<unsafe extern "C" fn(*const EntryRecordingScenario) -> u32>(
                    b"EntryRecording_SetScenario\0",
                )
                .map_err(|e| format!("missing SetScenario export: {e}"))?;
            if set(&scenario) != 0 {
                return Err("SetScenario failed".to_string());
            }
        }
        Ok(())
    }

    fn observation(&self) -> Result<EntryRecordingObservation, String> {
        unsafe {
            let mut observation = EntryRecordingObservation::default();
            let get = self
                .oracle
                .get::<unsafe extern "C" fn(*mut EntryRecordingObservation) -> u32>(
                    b"EntryRecording_GetObservation\0",
                )
                .map_err(|e| format!("missing GetObservation export: {e}"))?;
            if get(&mut observation) != 0 {
                return Err("GetObservation failed".to_string());
            }
            Ok(observation)
        }
    }

    async fn shutdown(mut self) -> Result<(), String> {
        self.client
            .close_session(self.session)
            .await
            .map_err(|rv| format!("C_CloseSession failed: {rv}"))?;
        self.client.finalize().await.map_err(|rv| format!("C_Finalize failed: {rv}"))?;
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(server) = self.server.take() {
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .map_err(|_| "server shutdown timed out".to_string())?
                .map_err(|e| format!("server task failed: {e}"))?;
        }
        // Production-order teardown (mirrors DaemonHarness): the backend
        // must finalize explicitly — dropping an unfinalized backend trips
        // the final-owner guard (exit 70).
        self.backend.finalize().map_err(|rv| format!("C_Finalize failed: {rv}"))?;
        Ok(())
    }
}

/// Oracle lane identity for receipts.
const ORACLE_PROVIDER: &str = "entry-recording-oracle";
/// Scope limitation every oracle receipt carries: entry recording proves
/// native C entry for this oracle only — no cryptographic or
/// real-provider qualification.
const ENTRY_ONLY_SCOPE: &str = "entry-only; no cryptographic/provider qualification";

/// One machine-checkable receipt per control: provider identity, tested
/// shape/function, observed RV, backend admissions, independent native
/// entry count, resulting disposition, and the entry-only scope
/// limitation.
fn format_oracle_receipt(
    control: &str,
    shape: &str,
    op: &str,
    rv: CkRv,
    backend_admissions: u64,
    native_entries: u64,
    disposition: ShapeDisposition,
) -> String {
    format!(
        "shape-evidence {control}: provider={ORACLE_PROVIDER} shape={shape} op={op} rv={rv} \
         backend_admissions={backend_admissions} native_entries={native_entries} \
         disposition={} scope=\"{ENTRY_ONLY_SCOPE}\"",
        disposition.tag()
    )
}

fn receipt(
    control: &str,
    shape: &str,
    op: &str,
    rv: CkRv,
    backend_admissions: u64,
    native_entries: u64,
    disposition: ShapeDisposition,
) {
    eprintln!(
        "{}",
        format_oracle_receipt(
            control,
            shape,
            op,
            rv,
            backend_admissions,
            native_entries,
            disposition
        )
    );
}

/// Server-local reject fixture: AES-CBC with legacy `Raw` params fails
/// server transport validation before the backend is admitted.
fn raw_aes_cbc_mechanism() -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Raw(RawMechanismParams { data: vec![0x01, 0x02].into() })),
    }
}

/// Backend-reconstruction reject fixture: AES-GCM with an absurd
/// `iv_buffer_len` passes server transport validation (typed presence is
/// pass-through for GCM; `gcm` is registry-bound to `CKM_AES_GCM`) but
/// fails `gcm_iv_capacity` during `mechanism_to_ffi`.
fn gcm_huge_mechanism() -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::AES_GCM,
        params: Some(CkMechanismParams::Gcm(GcmParams {
            iv_bits: 96,
            // 600 MiB exceeds the backend's 512 MiB generated-IV cap: the
            // server forwards it (no typed cap), the backend rejects it.
            iv_buffer_len: 600 * 1024 * 1024,
            tag_bits: 128,
            iv_presence: PointerBytes::present_copy(&[0u8; 12]),
            aad_presence: PointerBytes::null_len(0),
        })),
    }
}

/// Genuine native-entry fixture: well-formed AES-CBC Iv params reach the
/// native oracle, which answers with the scenario RV verbatim.
fn iv_aes_cbc_mechanism() -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x01; 16] })),
    }
}

/// Server transport validation rejects locally: AES-CBC with legacy `Raw`
/// params fails `validate_mechanism_transport` with
/// `CKR_MECHANISM_PARAM_INVALID` before `spawn_backend`, so the backend is
/// never admitted (0 admissions) and the native oracle sees zero entries.
/// Same RV value a provider returns natively — zero native-entry credit.
#[ignore] // requires the entry-recording oracle cdylib
#[tokio::test]
async fn server_transport_local_reject_earns_no_native_entry() -> Result<(), String> {
    let mut harness = EvidenceHarness::start().await?;
    // Scenario OK: if native entry WERE reached, init would succeed — so the
    // observed error below can only come from before the native call.
    harness.set_scenario_rv(CkRv::OK)?;
    harness.reset_observation()?;

    let mechanism = raw_aes_cbc_mechanism();
    let err = match harness.client.encrypt_init(harness.session, &mechanism, harness.key).await {
        Ok(_) => return Err("Raw params must not reach native success".to_string()),
        Err(rv) => rv,
    };
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "server transport validation RV");

    // m3 layer discrimination: 0 backend admissions AND 0 native entries —
    // a server-local reject, provably distinct from the backend-reject
    // control below (1 admission, 0 entries) despite the identical RV.
    let admissions = harness.backend_admissions();
    assert_eq!(admissions, 0, "server-local reject admits the backend zero times");
    let observation = harness.observation()?;
    assert_eq!(observation.encrypt_init_calls, 0, "no native entry on local reject");
    let outcome = Err::<(), CkRv>(err);
    assert_eq!(
        classify_with_entry_record(&outcome, 0, ShapeOpClass::InitOnly),
        ShapeDisposition::Attempted
    );
    assert_eq!(classify_rv_only(&outcome, ShapeOpClass::InitOnly), ShapeDisposition::Attempted);
    receipt(
        "server-local-reject",
        "Raw",
        "encrypt-init",
        err,
        admissions,
        0,
        ShapeDisposition::Attempted,
    );

    harness.shutdown().await?;
    Ok(())
}

/// Backend FFI reconstruction rejects before the native call: AES-GCM with
/// an absurd `iv_buffer_len` passes server transport validation (typed
/// presence is pass-through for GCM; `gcm` is registry-bound to
/// `CKM_AES_GCM`) but fails `gcm_iv_capacity` during `mechanism_to_ffi`
/// with `CKR_MECHANISM_PARAM_INVALID`. Zero native entries, zero
/// native-entry credit — same RV value as a genuine native error.
#[ignore] // requires the entry-recording oracle cdylib
#[tokio::test]
async fn backend_reconstruction_reject_earns_no_native_entry() -> Result<(), String> {
    let mut harness = EvidenceHarness::start().await?;
    harness.set_scenario_rv(CkRv::OK)?;
    harness.reset_observation()?;

    let mechanism = gcm_huge_mechanism();
    let err = match harness.client.encrypt_init(harness.session, &mechanism, harness.key).await {
        Ok(_) => return Err("oversized GCM buffer must not reach native success".to_string()),
        Err(rv) => rv,
    };
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "backend reconstruction RV");

    // m3 layer discrimination: exactly 1 backend admission (transport
    // accepted — pinned by
    // `gcm_reconstruction_fixture_passes_transport_while_raw_rejects`) with
    // 0 native entries. A server-local reject with the same RV shows 0
    // admissions instead, so this pair can no longer false-pass.
    let admissions = harness.backend_admissions();
    assert_eq!(admissions, 1, "backend reject admits the backend exactly once");
    let observation = harness.observation()?;
    assert_eq!(observation.encrypt_init_calls, 0, "no native entry on backend reject");
    let outcome = Err::<(), CkRv>(err);
    assert_eq!(
        classify_with_entry_record(&outcome, 0, ShapeOpClass::InitOnly),
        ShapeDisposition::Attempted
    );
    assert_eq!(classify_rv_only(&outcome, ShapeOpClass::InitOnly), ShapeDisposition::Attempted);
    receipt(
        "backend-reject",
        "Gcm",
        "encrypt-init",
        err,
        admissions,
        0,
        ShapeDisposition::Attempted,
    );

    harness.shutdown().await?;
    Ok(())
}

/// A genuine native error with an independent entry record earns
/// native-entry credit but NOT success credit. The oracle returns the SAME
/// `CKR_MECHANISM_PARAM_INVALID` the two negative controls above observe
/// without entry — the entry record is the only thing that tells them
/// apart. Scope limitation: entry recording proves native C entry for this
/// oracle only; it says nothing about real-provider behavior, which the
/// dedicated SoftHSM2 round-trip tests cover.
#[ignore] // requires the entry-recording oracle cdylib
#[tokio::test]
async fn native_entry_with_same_rv_earns_entry_credit_not_success() -> Result<(), String> {
    let mut harness = EvidenceHarness::start().await?;
    harness.set_scenario_rv(CkRv::MECHANISM_PARAM_INVALID)?;
    harness.reset_observation()?;

    let mechanism = iv_aes_cbc_mechanism();
    let err = match harness.client.encrypt_init(harness.session, &mechanism, harness.key).await {
        Ok(_) => return Err("scenario error RV must surface, not success".to_string()),
        Err(rv) => rv,
    };
    // Bit-identical RV to both negative controls — RV equality proves nothing.
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "native scenario RV");

    // m3 layer discrimination: 1 admission with 1 native entry — the only
    // control of the three where the native oracle was reached.
    let admissions = harness.backend_admissions();
    assert_eq!(admissions, 1, "native entry admits the backend exactly once");
    let observation = harness.observation()?;
    assert_eq!(observation.encrypt_init_calls, 1, "exactly one native entry");
    assert_eq!(
        observation.init_mech_type,
        CkMechanismType::AES_CBC.0,
        "entry record names the mechanism"
    );
    let outcome = Err::<(), CkRv>(err);
    assert_eq!(
        classify_with_entry_record(
            &outcome,
            observation.encrypt_init_calls,
            ShapeOpClass::InitOnly
        ),
        ShapeDisposition::NativeEntered
    );
    // ...while the RV-only view — all the SoftHSM2 lane ever has — still
    // says attempted. That gap is why the driver must not claim more.
    assert_eq!(classify_rv_only(&outcome, ShapeOpClass::InitOnly), ShapeDisposition::Attempted);
    receipt(
        "native-entry",
        "Iv",
        "encrypt-init",
        err,
        admissions,
        observation.encrypt_init_calls,
        ShapeDisposition::NativeEntered,
    );

    harness.shutdown().await?;
    Ok(())
}
