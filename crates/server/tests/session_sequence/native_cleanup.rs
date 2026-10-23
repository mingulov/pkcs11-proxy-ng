//! Test-owned native workers. Their lifetime must outlive every local deadline.
use std::time::Duration;
use tokio::task::{JoinError, JoinHandle};

/// An unjoined native owner must never be detached by cancellation or unwinding.
/// Exit71 stops this test process without finalizing or unloading its native module.
pub struct NativeOwner<T> {
    worker: Option<JoinHandle<T>>,
}
impl<T> Drop for NativeOwner<T> {
    fn drop(&mut self) {
        if self.worker.is_some() {
            std::process::exit(71);
        }
    }
}
impl<T: Send + 'static> NativeOwner<T> {
    pub fn spawn(operation: impl FnOnce() -> T + Send + 'static) -> Self {
        Self { worker: Some(tokio::task::spawn_blocking(operation)) }
    }
    pub fn pending(&self) -> bool {
        self.worker.is_some()
    }
    pub async fn wait(&mut self, deadline: Duration) -> Option<Result<T, JoinError>> {
        let worker = self.worker.as_mut().expect("native worker is owned");
        match tokio::time::timeout(deadline, worker).await {
            Ok(joined) => {
                self.worker.take();
                Some(joined)
            }
            Err(_) => None,
        }
    }
    pub async fn join(&mut self) -> Option<Result<T, JoinError>> {
        let joined = self.worker.as_mut()?.await;
        self.worker.take();
        Some(joined)
    }
}

/// Deadlines remain errors even when explicit gate release permits later joining.
/// If both local waits expire, keep the owner until actual completion or the
/// existing outer process timeout. Never advance into finalize over native work.
pub async fn settle_native<T: Send + 'static>(
    owner: &mut NativeOwner<T>,
    deadline: Duration,
    mut release: impl FnMut() -> Result<(), String>,
    errors: &mut Vec<String>,
    label: &str,
) -> Option<Result<T, JoinError>> {
    if let Some(joined) = owner.wait(deadline).await {
        return Some(joined);
    }
    errors.push(format!("{label} deadline exceeded; native owner retained"));
    if let Err(error) = release() {
        errors.push(error);
    }
    if let Some(joined) = owner.wait(deadline).await {
        return Some(joined);
    }
    errors.push(format!(
        "{label} recovery deadline exceeded; awaiting owner at outer process boundary"
    ));
    if let Err(error) = release() {
        errors.push(error);
    }
    owner.join().await
}

#[cfg(test)]
mod controls {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    const SHORT: Duration = Duration::from_millis(5);
    const BOUND: Duration = Duration::from_millis(500);

    /// The old timeout-by-value branch loses the only join owner here.
    #[tokio::test]
    async fn timeout_retains_native_worker_for_late_join() {
        let (release, held) = std::sync::mpsc::channel();
        let (entered, entry) = std::sync::mpsc::channel();
        let mut owner = NativeOwner::spawn(move || {
            let _ = entered.send(());
            let _ = held.recv();
            17
        });
        let entry_observed = entry.recv_timeout(BOUND).is_ok();
        let first = owner.wait(SHORT).await;
        let retained = owner.pending();
        let _ = release.send(());
        let joined = tokio::time::timeout(BOUND, owner.join()).await;
        assert!(entry_observed && first.is_none(), "native entry must outlive the first deadline");
        assert!(retained, "native cleanup timeout discarded the worker owner");
        assert!(matches!(joined, Ok(Some(Ok(17)))), "late native completion was not joined");
    }

    /// A local timeout cannot advance cleanup into finalize while native work is held.
    #[tokio::test]
    async fn recovery_waits_for_settlement_before_entering_finalize() {
        let (release, held) = std::sync::mpsc::channel();
        let (entered, entry) = std::sync::mpsc::channel();
        let settled = Arc::new(AtomicBool::new(false));
        let native_settled = settled.clone();
        let mut owner = NativeOwner::spawn(move || {
            let _ = entered.send(());
            let _ = held.recv();
            native_settled.store(true, Ordering::SeqCst);
        });
        let entry_observed = entry.recv_timeout(BOUND).is_ok();
        let finalized = Arc::new(AtomicBool::new(false));
        let finalizing = finalized.clone();
        let (notice, mut notices) = tokio::sync::mpsc::unbounded_channel();
        let mut driver = tokio::spawn(async move {
            let mut errors = Vec::new();
            let joined = settle_native(
                &mut owner,
                SHORT,
                || notice.send(()).map_err(|e| e.to_string()),
                &mut errors,
                "controlled close",
            )
            .await;
            let premature = !settled.load(Ordering::SeqCst);
            finalizing.store(true, Ordering::SeqCst);
            (joined, errors, premature)
        });
        let first_notice = tokio::time::timeout(BOUND, notices.recv()).await;
        // Either the second deadline is observed, or a broken helper has already finalized.
        let phase = tokio::time::timeout(BOUND, async {
            tokio::select! {
                result = &mut driver => Some(result),
                _ = notices.recv() => None,
            }
        })
        .await;
        let finalized_while_held = finalized.load(Ordering::SeqCst);
        let _ = release.send(());
        let joined = match phase {
            Ok(Some(result)) => Ok(result),
            _ => tokio::time::timeout(BOUND, &mut driver).await,
        };
        assert!(
            entry_observed && matches!(first_notice, Ok(Some(()))),
            "first deadline was not observed"
        );
        assert!(!finalized_while_held, "finalization was entered before native settlement");
        let (joined, errors, premature) = joined.expect("driver deadline").expect("driver panic");
        assert!(
            !premature && matches!(joined, Some(Ok(()))),
            "native owner was not joined before finalize"
        );
        assert!(errors.len() >= 2, "deadline recovery must remain failing cleanup evidence");
    }
}
