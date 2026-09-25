use super::*;
use ::pkcs11_proxy_ng::config::AuditConfig;
use ::pkcs11_proxy_ng::server::audit::{AuditSink, spawn_audit_sink};

// The audit writer gets its own blocked runtime. Provider work runs on the
// normal test runtime, so a full sink can be forced without timing races.
struct HeldWriter {
    runtime: Option<tokio::runtime::Runtime>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}
impl Drop for HeldWriter {
    fn drop(&mut self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
        self.runtime.take().unwrap().shutdown_background();
    }
}
fn held_sink(dir: &tempfile::TempDir) -> (AuditSink, HeldWriter) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let gate = release.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    runtime.spawn_blocking(move || {
        tx.send(()).unwrap();
        let mut ready = gate.0.lock().unwrap();
        while !*ready {
            ready = gate.1.wait(ready).unwrap();
        }
    });
    rx.recv().unwrap();
    let entered = runtime.enter();
    let sink = spawn_audit_sink(&AuditConfig {
        dir: Some(dir.path().join("audit")),
        channel_capacity: 128,
        fail_closed_reserve: 0,
        ..Default::default()
    })
    .unwrap()
    .unwrap();
    drop(entered);
    (sink, HeldWriter { runtime: Some(runtime), release })
}

fn fill(sink: &AuditSink) {
    use ::pkcs11_proxy_ng::server::audit::EmitOutcome;
    use pkcs11_proxy_ng_audit::{AUDIT_SCHEMA_VERSION, AuditRecord, EventClass};
    for _ in 0..129 {
        if sink.emit(AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            seq: 0,
            ts_unix_ms: 0,
            ts_monotonic_ns: 0,
            prev_hash: String::new(),
            request_id: "test".into(),
            identity: None,
            method: "test_fill".into(),
            class: EventClass::KeyMgmt,
            slot: None,
            session: None,
            object_ref: None,
            ck_rv: 0,
            latency_us: 0,
            dropped_count: None,
        }) == EmitOutcome::RejectedFailClosed
        {
            return;
        }
    }
    panic!("held writer did not saturate");
}

fn sink(dir: &tempfile::TempDir) -> AuditSink {
    spawn_audit_sink(&AuditConfig { dir: Some(dir.path().join("audit")), ..Default::default() })
        .unwrap()
        .unwrap()
}

async fn records(sink: &AuditSink, dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
    sink.flush().await.unwrap();
    let data = std::fs::read_to_string(dir.path().join("audit/audit.jsonl")).unwrap();
    assert!(!data.contains("aad-canary-wrap-policy"));
    data.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

fn method(route: Route) -> &'static str {
    match route {
        Route::Wrap | Route::Exact => "C_WrapKey",
        Route::Authenticated | Route::AuthenticatedExact => "C_WrapKeyAuthenticated",
        Route::UnwrapAuthenticated => "C_UnwrapKeyAuthenticated",
    }
}

#[tokio::test]
async fn all_wrap_outcomes_audit_actual_rv_including_transport_and_exact_errors() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let f = fixture_with_audit(grant(), Some(sink.clone())).await;
    let mut c = open(&f, false).await;
    for route in ROUTES.into_iter().chain([Route::UnwrapAuthenticated]) {
        for (action, want) in [
            (None, CkRv::OK),
            (Some(MockWrapAction::Return(CkRv::DEVICE_ERROR)), CkRv::DEVICE_ERROR),
            (Some(MockWrapAction::Panic), CkRv::FUNCTION_FAILED),
        ] {
            let before = records(&sink, &dir).await.len();
            if let Some(a) = action {
                f.backend.set_wrap_action(a);
            }
            let r = invoke(&mut c, route, mechanism(0), output_spec()).await;
            if want == CkRv::FUNCTION_FAILED {
                assert!(r.is_err());
            } else {
                assert_eq!(r.unwrap().rv, want.0);
            }
            let rows = records(&sink, &dir).await;
            assert_eq!(rows.len(), before + 1, "{route:?}, want={want:?}");
            let record = &rows.last().unwrap();
            assert_eq!(record["method"], method(route));
            assert_eq!(record["ck_rv"], want.0);
            assert_eq!(record["session"], c.session);
            assert!(record["identity"].as_str().unwrap().starts_with("x509:"));
        }
    }
    for route in [Route::Exact, Route::AuthenticatedExact] {
        let spec =
            OutputBufferSpec { buffer_present: true, buffer_len: 1, length_pointer_null: false };
        assert_eq!(
            invoke(&mut c, route, mechanism(0), spec).await.unwrap().rv,
            CkRv::BUFFER_TOO_SMALL.0
        );
        let rows = records(&sink, &dir).await;
        assert_eq!(rows.last().unwrap()["ck_rv"], CkRv::BUFFER_TOO_SMALL.0);
    }
}

#[tokio::test]
async fn policy_denials_have_equivalent_wrap_audit_records() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut g = grant();
    g.extract = ExtractPolicyConfig::Deny;
    let f = fixture_with_audit(g, Some(sink.clone())).await;
    let mut c = open(&f, false).await;
    for route in ROUTES {
        let before = records(&sink, &dir).await.len();
        assert_eq!(
            invoke(&mut c, route, mechanism(0), output_spec()).await.unwrap().rv,
            CkRv::KEY_FUNCTION_NOT_PERMITTED.0
        );
        let rows = records(&sink, &dir).await;
        assert_eq!(rows.len(), before + 1, "{route:?}");
        let r = &rows.last().unwrap();
        assert_eq!(r["method"], method(route));
        assert_eq!(r["ck_rv"], CkRv::KEY_FUNCTION_NOT_PERMITTED.0);
    }
}

#[tokio::test]
async fn audit_rejection_suppresses_all_wrap_and_authenticated_unwrap_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let (sink, _held) = held_sink(&dir);
    let f = fixture_with_audit(grant(), Some(sink.clone())).await;
    let mut c = open(&f, false).await;
    f.backend.set_wrap_key_exact_output(Some(CkMechanismParams::Iv(
        pkcs11_proxy_ng_types::IvParams { iv: vec![0x55; 16] },
    )));
    fill(&sink);
    for route in ROUTES.into_iter().chain([Route::UnwrapAuthenticated]) {
        for action in
            [None, Some(MockWrapAction::Return(CkRv::DEVICE_ERROR)), Some(MockWrapAction::Panic)]
        {
            if let Some(a) = action {
                f.backend.set_wrap_action(a);
            }
            let before = f.backend.wrap_observations().len();
            let r = invoke(&mut c, route, mechanism(0), output_spec())
                .await
                .expect("audit failure supersedes transport errors");
            assert_eq!(r.rv, CkRv::FUNCTION_FAILED.0, "{route:?}");
            r.assert_suppressed();
            if matches!(route, Route::Exact | Route::AuthenticatedExact) {
                assert!(r.value.is_none());
                assert!(r.parameter.is_none());
            }
            assert_eq!(f.backend.wrap_observations().len(), before + 1);
        }
    }
}
