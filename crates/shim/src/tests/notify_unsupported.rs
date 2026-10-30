use super::*;

const NOTIFY_UNSUPPORTED_MSG: &str = "Notify callbacks are not supported by the proxy";

/// Shared buffer capturing tracing output for assertions, mirroring the
/// `capture_logs` harness in `interface.rs`. Thread-local (`with_default`):
/// `c_open_session` runs synchronously on the calling thread.
#[derive(Clone, Default)]
struct CapturedWriter {
    buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedWriter {
    type Writer = CapturedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    let writer = CapturedWriter::default();
    // No timestamps: the assertions only inspect message content, and
    // SystemTime::now() is rejected under Miri isolation.
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    let logs = String::from_utf8_lossy(&writer.buf.lock().unwrap()).to_string();
    (out, logs)
}

unsafe extern "C" fn dummy_notify(
    _h_session: CK_SESSION_HANDLE,
    _event: CK_NOTIFICATION,
    _p_application: CK_VOID_PTR,
) -> CK_RV {
    CKR_OK as CK_RV
}

/// P1-11: a non-NULL `Notify` passed to `C_OpenSession` must surface a
/// once-per-process warning (the proxy never delivers surrender
/// notifications); a NULL `Notify` stays silent. The RV is unchanged
/// (NULL `phSession` still yields `CKR_ARGUMENTS_BAD` before any client
/// use, so this needs no daemon). One test function, strictly ordered:
/// the NULL case runs first so it cannot be masked by the spent `Once`,
/// and no other test in this binary passes a non-NULL `Notify`.
#[test]
fn c_open_session_with_notify_warns_once_null_notify_silent() {
    let _guard = shim_state_test_guard();

    let (rv, logs) = capture_logs(|| unsafe {
        dispatch::general::c_open_session(0, 0, std::ptr::null_mut(), None, std::ptr::null_mut())
    });
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    assert!(!logs.contains(NOTIFY_UNSUPPORTED_MSG), "NULL Notify must stay silent, logs: {logs}");

    let (rvs, logs) = capture_logs(|| unsafe {
        [
            dispatch::general::c_open_session(
                0,
                0,
                std::ptr::null_mut(),
                Some(dummy_notify),
                std::ptr::null_mut(),
            ),
            dispatch::general::c_open_session(
                0,
                0,
                std::ptr::null_mut(),
                Some(dummy_notify),
                std::ptr::null_mut(),
            ),
        ]
    });
    assert_eq!(rvs, [CKR_ARGUMENTS_BAD as CK_RV; 2]);
    assert_eq!(
        logs.matches(NOTIFY_UNSUPPORTED_MSG).count(),
        1,
        "non-NULL Notify must warn exactly once per process, logs: {logs}"
    );
}

/// The factored once-check, exercised with fresh cells so it is
/// independent of the process-global `Once` spent above: NULL never
/// arms the cell or logs; non-NULL logs on the first call only.
#[test]
fn warn_notify_unsupported_once_helper_null_vs_non_null() {
    let null_once = std::sync::Once::new();
    let (_, logs) = capture_logs(|| {
        dispatch::general::warn_notify_unsupported_once(None, &null_once);
        dispatch::general::warn_notify_unsupported_once(None, &null_once);
    });
    assert!(!null_once.is_completed());
    assert!(!logs.contains(NOTIFY_UNSUPPORTED_MSG), "NULL Notify must stay silent, logs: {logs}");

    let some_once = std::sync::Once::new();
    let (_, logs) = capture_logs(|| {
        dispatch::general::warn_notify_unsupported_once(Some(dummy_notify), &some_once);
        dispatch::general::warn_notify_unsupported_once(Some(dummy_notify), &some_once);
    });
    assert!(some_once.is_completed());
    assert_eq!(
        logs.matches(NOTIFY_UNSUPPORTED_MSG).count(),
        1,
        "non-NULL Notify must warn exactly once, logs: {logs}"
    );
    assert!(logs.contains("WARN"), "the once-log must be a warning, logs: {logs}");
}
