use super::*;
use crate::server::grpc_service::session::tests::capture_logs as capture_shared_logs;
use serde_json::Value;
use std::io;
use tracing::Instrument;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[derive(Clone, Default)]
struct DiagnosticWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for DiagnosticWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn capture_logs<F, Fut>(f: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let writer = DiagnosticWriter::default();
    let destination = writer.clone();
    // Register a private subscriber AFTER the shared subscriber is installed.
    // Earlier tests can leave workers carrying Dispatch::none across that
    // installation. With just one registered subscriber, tracing's first-use
    // interest fast path can cache their completion callsite as disabled.
    // Keeping both subscribers registered avoids that startup race and gives
    // these assertions their own output, including on detached worker threads.
    capture_shared_logs(|| async {
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || destination.clone())
            .finish();
        f().with_subscriber(subscriber).await;
    })
    .await;
    String::from_utf8(writer.0.lock().unwrap().clone()).unwrap()
}

fn rpc_span(request_id: &'static str) -> tracing::Span {
    tracing::info_span!("rpc", request_id, method = "/test.Backend/Operation")
}

fn completion(output: &str, request_id: &str) -> Value {
    let events: Vec<Value> =
        output.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
    let matches: Vec<_> = events
        .into_iter()
        .filter(|event| {
            event["fields"]["message"] == "backend task completed"
                && event["span"]["request_id"] == request_id
        })
        .collect();
    assert_eq!(matches.len(), 1, "expected one correlated completion; logs: {output}");
    let event = matches.into_iter().next().unwrap();
    assert_eq!(event["span"]["method"], "/test.Backend/Operation");
    for field in ["backend_queue_ms", "backend_task_ms"] {
        assert!(event["fields"][field].as_f64().is_some_and(|duration| duration >= 0.0));
    }
    event
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while counter.load(Ordering::SeqCst) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("backend count reached expected state");
}

#[tokio::test]
async fn backend_diagnostics_preserve_provider_error_and_rpc_identity() {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    static STUCK: AtomicUsize = AtomicUsize::new(0);
    let output = capture_logs(|| async {
        let result = spawn_backend_core(&COUNTER, &STUCK, Duration::from_secs(5), 1, || {
            Err::<(), _>(CkRv::TOKEN_NOT_PRESENT)
        })
        .instrument(rpc_span("diagnostics-provider-error"))
        .await;
        assert_eq!(result.unwrap().unwrap_err(), CkRv::TOKEN_NOT_PRESENT);
        assert_eq!(COUNTER.load(Ordering::SeqCst), 0);
        assert_eq!(STUCK.load(Ordering::SeqCst), 0);
    })
    .await;

    let event = completion(&output, "diagnostics-provider-error");
    assert_eq!(event["level"], "DEBUG");
    assert_eq!(event["fields"]["completion"], "returned");
    assert_eq!(event["fields"]["released_stuck_slot"], false);
}

async fn late_completion(panic: bool, request_id: &'static str) -> Value {
    // capture_logs serializes these tests; the task is drained before releasing
    // capture ownership, so these counters cannot overlap between test calls.
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    static STUCK: AtomicUsize = AtomicUsize::new(0);
    let output = capture_logs(|| async {
        let (release, parked) = std::sync::mpsc::channel();
        let result =
            spawn_backend_core(&COUNTER, &STUCK, Duration::from_millis(50), 1, move || {
                let _ = parked.recv();
                assert!(!panic, "diagnostics fixture panic");
                Ok(17u8)
            })
            .instrument(rpc_span(request_id))
            .await;
        assert_eq!(result.unwrap().unwrap_err(), CkRv::FUNCTION_FAILED);
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(STUCK.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        wait_for_count(&COUNTER, 0).await;
        assert_eq!(STUCK.load(Ordering::SeqCst), 0);
    })
    .await;
    completion(&output, request_id)
}

#[tokio::test]
async fn backend_diagnostics_correlate_late_return() {
    let event = late_completion(false, "diagnostics-late-return").await;
    assert_eq!(event["level"], "INFO");
    assert_eq!(event["fields"]["completion"], "returned");
    assert_eq!(event["fields"]["released_stuck_slot"], true);
    assert_eq!(event["fields"]["stuck_calls"], 0);
}

#[tokio::test]
async fn backend_diagnostics_distinguish_late_panic_from_return() {
    let event = late_completion(true, "diagnostics-late-panic").await;
    assert_eq!(event["level"], "INFO");
    assert_eq!(event["fields"]["completion"], "panicked");
    assert_eq!(event["fields"]["released_stuck_slot"], true);
    assert_eq!(event["fields"]["stuck_calls"], 0);
}

#[tokio::test]
async fn backend_diagnostics_survive_caller_cancellation_without_releasing_capacity() {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    static STUCK: AtomicUsize = AtomicUsize::new(0);
    let output = capture_logs(|| async {
        let (release, parked) = std::sync::mpsc::channel();
        let (started, entered) = tokio::sync::oneshot::channel();
        let rpc = tokio::spawn(
            spawn_backend_core(&COUNTER, &STUCK, Duration::from_secs(5), 1, move || {
                let _ = started.send(());
                let _ = parked.recv();
                Ok(17u8)
            })
            .instrument(rpc_span("diagnostics-cancelled"))
            .with_current_subscriber(),
        );
        entered.await.unwrap();
        rpc.abort();
        assert!(rpc.await.unwrap_err().is_cancelled());
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(STUCK.load(Ordering::SeqCst), 0);
        release.send(()).unwrap();
        wait_for_count(&COUNTER, 0).await;
        assert_eq!(STUCK.load(Ordering::SeqCst), 0);
    })
    .await;

    let event = completion(&output, "diagnostics-cancelled");
    assert_eq!(event["fields"]["completion"], "returned");
    assert_eq!(event["fields"]["released_stuck_slot"], false);
}

#[test]
fn backend_diagnostics_separate_worker_queue_from_task_duration() {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    static STUCK: AtomicUsize = AtomicUsize::new(0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let mut duration_bounds = None;
    let output = runtime.block_on(capture_logs(|| async {
        let (release_worker, worker_parked) = std::sync::mpsc::channel();
        let (worker_started, worker_entered) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = worker_started.send(());
            let _ = worker_parked.recv();
        });
        worker_entered.await.unwrap();

        let (release_task, task_parked) = std::sync::mpsc::channel();
        let (task_started, task_entered) = tokio::sync::oneshot::channel();
        let before_submission = Instant::now();
        let rpc = tokio::spawn(
            spawn_backend_core(&COUNTER, &STUCK, Duration::from_secs(5), 1, move || {
                let _ = task_started.send(());
                let _ = task_parked.recv();
                Ok(23u8)
            })
            .instrument(rpc_span("diagnostics-queued"))
            .with_current_subscriber(),
        );
        wait_for_count(&COUNTER, 1).await;
        let after_submission = Instant::now();
        // Force observable waits in both boundaries. There is no upper latency
        // bound: a slow CI worker is allowed to take arbitrarily longer.
        tokio::time::sleep(Duration::from_millis(25)).await;
        let before_worker_start = Instant::now();
        release_worker.send(()).unwrap();
        blocker.await.unwrap();
        task_entered.await.unwrap();
        let after_worker_start = Instant::now();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before_completion = Instant::now();
        release_task.send(()).unwrap();
        assert_eq!(rpc.await.unwrap().unwrap().unwrap(), 23);
        let after_completion = Instant::now();
        duration_bounds = Some([
            (
                before_worker_start.duration_since(after_submission),
                after_worker_start.duration_since(before_submission),
            ),
            (
                before_completion.duration_since(after_worker_start),
                after_completion.duration_since(before_worker_start),
            ),
        ]);
        assert_eq!(COUNTER.load(Ordering::SeqCst), 0);
        assert_eq!(STUCK.load(Ordering::SeqCst), 0);
    }));

    let event = completion(&output, "diagnostics-queued");
    for (field, (lower, upper)) in
        ["backend_queue_ms", "backend_task_ms"].into_iter().zip(duration_bounds.unwrap())
    {
        let measured = event["fields"][field].as_f64().unwrap();
        assert!(measured >= lower.as_secs_f64() * 1e3, "{field} must include its parked interval");
        assert!(measured <= upper.as_secs_f64() * 1e3, "{field} must exclude the other interval");
    }
}

#[tokio::test]
async fn backend_diagnostics_carry_the_active_subscriber_to_the_worker() {
    struct LocalSubscriberMarker;
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LocalSubscriberMarker {}
    let subscriber = tracing_subscriber::registry().with(LocalSubscriberMarker);
    let carried = spawn_task(|| {
        tracing::dispatcher::get_default(|dispatch| dispatch.is::<LocalSubscriberMarker>())
    })
    .with_subscriber(subscriber)
    .await
    .unwrap();
    assert!(carried, "the blocking task must use the caller's active subscriber");
}
