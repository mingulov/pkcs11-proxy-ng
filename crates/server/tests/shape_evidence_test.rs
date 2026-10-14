// W1-L12-03: test diagnostics (skip notices, receipts, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! Q07 (MAINT-02) shape-evidence controls: attempted vs native-entered vs success.
//!
//! The 79-shape SoftHSM2 driver classifies every RPC outcome WITHOUT native
//! entry evidence: `Ok` is a successful real-provider operation (no local
//! layer synthesizes `Ok` on the driver's op paths), while any error RV is
//! merely *attempted* — RPC-completed, origin unproven — because the same RV
//! value can come from server transport validation, backend FFI
//! reconstruction, or the provider itself. No RV alone proves origin.
//!
//! This file pins that taxonomy twice:
//!
//! * Default-run unit tests pin the shared classifier in
//!   [`support::shape_matrix`](mod@support) (RV-only mapping, entry-record
//!   mapping, receipt-line grammar). No provider needed.
//! * Ignored oracle controls drive the full stack (client -> gRPC -> server
//!   handlers -> `FfiBackend` -> native oracle) against the
//!   entry-recording oracle and assert, with an independent native entry
//!   count, that server-local and backend-local rejects earn no
//!   native-entry credit even when their RV is bit-identical to a genuine
//!   native error — while the genuine native error earns native-entry
//!   credit but NOT success credit.
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
use std::time::Duration;

use libloading::Library;
use oracle_types::{EntryRecordingObservation, EntryRecordingScenario};
use pkcs11_proxy_ng::server::{context_manager::ContextManager, grpc_service::Pkcs11ProxyService};
use pkcs11_proxy_ng_backend::{FfiBackend, Pkcs11Backend};
use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkAttributeValue, CkMechanism, CkMechanismParams,
    CkMechanismType, CkObjectClass, CkObjectHandle, CkRv, CkSessionHandle, GcmParams, IvParams,
    PointerBytes, RawMechanismParams,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use support::{
    ShapeDisposition, ShapeOutcome, classify_rv_only, classify_with_entry_record, find_token_slot,
    format_matrix_summary, format_shape_line, initialized_client, open_public_session,
};

// ---------------------------------------------------------------------------
// Default-run taxonomy unit tests (no provider needed)
// ---------------------------------------------------------------------------

#[test]
fn shape_disposition_tags_are_stable() {
    assert_eq!(ShapeDisposition::Success.tag(), "success");
    assert_eq!(ShapeDisposition::Attempted.tag(), "attempted");
    assert_eq!(ShapeDisposition::NativeEntered.tag(), "native-entered");
}

#[test]
fn shape_outcome_constructors_carry_disposition_and_rv() {
    let ok = ShapeOutcome::success("encrypt-init ok".to_string());
    assert_eq!(ok.disposition, ShapeDisposition::Success);
    assert_eq!(ok.rv, None);

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
fn classify_rv_only_ok_is_success_and_any_err_is_attempted() {
    let ok: Result<(), CkRv> = Ok(());
    assert_eq!(classify_rv_only(&ok), ShapeDisposition::Success);

    // Every error RV — including ones real providers return — is merely
    // attempted without entry evidence: no RV alone proves origin.
    for rv in [
        CkRv::MECHANISM_PARAM_INVALID,
        CkRv::ARGUMENTS_BAD,
        CkRv::KEY_TYPE_INCONSISTENT,
        CkRv::MECHANISM_INVALID,
        CkRv::DEVICE_ERROR,
    ] {
        let err: Result<(), CkRv> = Err(rv);
        assert_eq!(classify_rv_only(&err), ShapeDisposition::Attempted, "rv={rv}");
    }
}

#[test]
fn classify_with_entry_record_distinguishes_origin() {
    let err: Result<(), CkRv> = Err(CkRv::MECHANISM_PARAM_INVALID);
    assert_eq!(
        classify_with_entry_record(&err, 0),
        ShapeDisposition::Attempted,
        "error without entry is attempted, never native-entered"
    );
    assert_eq!(
        classify_with_entry_record(&err, 1),
        ShapeDisposition::NativeEntered,
        "error with entry record earns native-entry credit"
    );
    assert_eq!(
        classify_with_entry_record(&err, 7),
        ShapeDisposition::NativeEntered,
        "entry count above one is still native-entered, not success"
    );

    // Success needs no entry record: no local layer on the driver's op
    // paths synthesizes Ok (every pre-backend handler return carries an
    // error RV; every Ok flows from a backend Ok).
    let ok: Result<(), CkRv> = Ok(());
    assert_eq!(classify_with_entry_record(&ok, 0), ShapeDisposition::Success);
    assert_eq!(classify_with_entry_record(&ok, 3), ShapeDisposition::Success);
}

#[test]
fn same_rv_without_entry_record_is_not_native_evidence() {
    // The Q07 crux in one assertion: the RV value carries zero origin
    // information, so identical RVs with and without an entry record
    // classify differently.
    let err: Result<(), CkRv> = Err(CkRv::MECHANISM_PARAM_INVALID);
    assert_ne!(classify_with_entry_record(&err, 0), classify_with_entry_record(&err, 1),);
    assert_eq!(classify_with_entry_record(&err, 1), ShapeDisposition::NativeEntered);
    assert_ne!(classify_with_entry_record(&err, 1), ShapeDisposition::Success);
}

#[test]
fn shape_line_grammar_carries_disposition() {
    let detail = format!("encrypt-init -> {}", CkRv::MECHANISM_PARAM_INVALID);
    let outcome = ShapeOutcome::attempted(CkRv::MECHANISM_PARAM_INVALID, detail.clone());
    assert_eq!(
        format_shape_line("Iv", CkMechanismType::AES_CBC.0, &outcome),
        format!("shape Iv (0x00001082): [attempted] {detail}")
    );

    let ok = ShapeOutcome::success("encrypt-init ok (mechanism_out: false)".to_string());
    assert_eq!(
        format_shape_line("Iv", CkMechanismType::AES_CBC.0, &ok),
        "shape Iv (0x00001082): [success] encrypt-init ok (mechanism_out: false)"
    );
}

#[test]
fn matrix_summary_grammar_carries_separate_counts() {
    // Receipt grammar: succeeded, attempted (origin unproven), and honestly
    // skipped are separate counts. Attempted and skipped shapes never add
    // to a qualified total: only succeeded shapes (this lane) and
    // oracle-scoped native-entry shapes (the ignored lane below, each with
    // its entry-record limitation) qualify.
    assert_eq!(
        format_matrix_summary(4, 5, 70, 79),
        "shape matrix: 4 succeeded, 5 attempted (origin unproven), 70 honestly skipped (79 total)"
    );
    assert_eq!(
        format_matrix_summary(0, 0, 79, 79),
        "shape matrix: 0 succeeded, 0 attempted (origin unproven), 79 honestly skipped (79 total)"
    );
}

// ---------------------------------------------------------------------------
// Ignored oracle controls (entry-recording provider behind the full stack)
// ---------------------------------------------------------------------------

/// Environment variable pointing at the built entry-recording oracle cdylib.
const ORACLE_LIB_ENV: &str = "PKCS11_PROXY_ENTRY_RECORDING_ORACLE_LIB";

/// Full-stack harness: real gRPC server handlers + real `FfiBackend` over the
/// recording oracle, driven by the real async client. Mirrors the
/// `noncontract_begin_health_test` in-process server shape.
struct EvidenceHarness {
    client: Pkcs11Client,
    session: CkSessionHandle,
    key: CkObjectHandle,
    oracle: Library,
    backend: Arc<dyn Pkcs11Backend>,
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
        let backend =
            Arc::new(FfiBackend::load(&path).map_err(|e| format!("load oracle backend: {e}"))?)
                as Arc<dyn Pkcs11Backend>;
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

        Ok(Self { client, session, key, oracle, backend, stop: Some(stop), server: Some(server) })
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

/// One machine-checkable receipt per control: the observed RV, the
/// independent native entry count, and the resulting disposition.
fn receipt(control: &str, rv: CkRv, native_entries: u64, disposition: ShapeDisposition) {
    eprintln!(
        "shape-evidence {control}: rv={rv} native_entries={native_entries} disposition={}",
        disposition.tag()
    );
}

/// Server transport validation rejects locally: AES-CBC with legacy `Raw`
/// params fails `validate_mechanism_transport` with
/// `CKR_MECHANISM_PARAM_INVALID` before `spawn_backend`, so the native
/// oracle sees zero entries. Same RV value a provider returns natively —
/// zero native-entry credit.
#[ignore] // requires the entry-recording oracle cdylib
#[tokio::test]
async fn server_transport_local_reject_earns_no_native_entry() -> Result<(), String> {
    let mut harness = EvidenceHarness::start().await?;
    // Scenario OK: if native entry WERE reached, init would succeed — so the
    // observed error below can only come from before the native call.
    harness.set_scenario_rv(CkRv::OK)?;
    harness.reset_observation()?;

    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Raw(RawMechanismParams { data: vec![0x01, 0x02].into() })),
    };
    let err = match harness.client.encrypt_init(harness.session, &mechanism, harness.key).await {
        Ok(_) => return Err("Raw params must not reach native success".to_string()),
        Err(rv) => rv,
    };
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "server transport validation RV");

    let observation = harness.observation()?;
    assert_eq!(observation.encrypt_init_calls, 0, "no native entry on local reject");
    let outcome = Err::<(), CkRv>(err);
    assert_eq!(classify_with_entry_record(&outcome, 0), ShapeDisposition::Attempted);
    assert_eq!(classify_rv_only(&outcome), ShapeDisposition::Attempted);
    receipt("server-local-reject", err, 0, ShapeDisposition::Attempted);

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

    let mechanism = CkMechanism {
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
    };
    let err = match harness.client.encrypt_init(harness.session, &mechanism, harness.key).await {
        Ok(_) => return Err("oversized GCM buffer must not reach native success".to_string()),
        Err(rv) => rv,
    };
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "backend reconstruction RV");

    let observation = harness.observation()?;
    assert_eq!(observation.encrypt_init_calls, 0, "no native entry on backend reject");
    let outcome = Err::<(), CkRv>(err);
    assert_eq!(classify_with_entry_record(&outcome, 0), ShapeDisposition::Attempted);
    receipt("backend-reject", err, 0, ShapeDisposition::Attempted);

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

    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::AES_CBC,
        params: Some(CkMechanismParams::Iv(IvParams { iv: vec![0x01; 16] })),
    };
    let err = match harness.client.encrypt_init(harness.session, &mechanism, harness.key).await {
        Ok(_) => return Err("scenario error RV must surface, not success".to_string()),
        Err(rv) => rv,
    };
    // Bit-identical RV to both negative controls — RV equality proves nothing.
    assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID, "native scenario RV");

    let observation = harness.observation()?;
    assert_eq!(observation.encrypt_init_calls, 1, "exactly one native entry");
    assert_eq!(
        observation.init_mech_type,
        CkMechanismType::AES_CBC.0,
        "entry record names the mechanism"
    );
    let outcome = Err::<(), CkRv>(err);
    assert_eq!(
        classify_with_entry_record(&outcome, observation.encrypt_init_calls),
        ShapeDisposition::NativeEntered
    );
    // ...while the RV-only view — all the SoftHSM2 lane ever has — still
    // says attempted. That gap is why the driver must not claim more.
    assert_eq!(classify_rv_only(&outcome), ShapeDisposition::Attempted);
    receipt("native-entry", err, observation.encrypt_init_calls, ShapeDisposition::NativeEntered);

    harness.shutdown().await?;
    Ok(())
}
