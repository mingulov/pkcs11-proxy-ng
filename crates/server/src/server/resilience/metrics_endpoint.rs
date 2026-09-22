//! Minimal hand-rolled HTTP/1.1 `GET /metrics` responder on a mode-0600 Unix
//! socket. Zero new deps (tokio only). Local + authenticated by socket perms
//! (design V14). Read-only; exports COUNTS only (no secret material).

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{render_prometheus, snapshot};

/// Max concurrent metrics connections (W1-L6-09). Past the cap, newly
/// accepted connections are dropped loudly instead of spawning
/// unbounded tasks. 32 is ample for a local debug endpoint; each
/// admitted task is small (one 1KiB read + one render).
const MAX_CONCURRENT_METRICS_CONNS: usize = 32;

/// Bind a mode-0600 Unix metrics socket and serve on a spawned task.
/// Returns once bound. Uses [`crate::server::transport::bind_unix_listener`]
/// for atomic 0600 creation (umask guard + is_socket stale-path check).
pub async fn spawn_metrics_endpoint(path: PathBuf) -> Result<(), String> {
    let listener = crate::server::transport::bind_unix_listener(&path)?;
    let admission = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_METRICS_CONNS));
    tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    consecutive_failures = 0;
                    // W1-L6-09: bound concurrent connection tasks. The
                    // permit is acquired synchronously in the accept
                    // loop (never queued) and held by the serving task
                    // until the connection closes, so socket-spam
                    // cannot spawn unbounded tasks/FDs.
                    let permit: OwnedSemaphorePermit = match admission.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!(
                                max = MAX_CONCURRENT_METRICS_CONNS,
                                "metrics connection dropped: too many concurrent connections"
                            );
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = serve_conn(stream).await {
                            tracing::debug!(error = %e, "metrics connection error");
                        }
                    });
                }
                Err(e) => {
                    // W1-C2-02: back off so a persistent accept failure
                    // (e.g. EMFILE) cannot busy-spin this task at 100% CPU.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    tracing::warn!(
                        error = %e,
                        consecutive_failures,
                        "metrics listener accept failed; backing off"
                    );
                    tokio::time::sleep(accept_failure_backoff(consecutive_failures)).await;
                }
            }
        }
    });
    Ok(())
}

/// Delay before retrying `accept()` after `consecutive_failures` failures
/// in a row (W1-C2-02). Exponential from a 10ms base, capped at 1s so a
/// recovered listener resumes promptly. Pure for testability.
fn accept_failure_backoff(consecutive_failures: u32) -> Duration {
    const BASE_MS: u64 = 10;
    const CAP: Duration = Duration::from_secs(1);
    let shift = consecutive_failures.saturating_sub(1).min(7);
    let delay = Duration::from_millis(BASE_MS.saturating_mul(1 << shift));
    delay.min(CAP)
}

async fn serve_conn(mut stream: UnixStream) -> io::Result<()> {
    // Bounded, time-limited read of the request head (defends against slow/large clients).
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request read timeout"))??;
    let head = String::from_utf8_lossy(&buf[..n]);
    let request_line = head.lines().next().unwrap_or("");

    let response = if is_metrics_get(request_line) {
        let body = render_prometheus(&snapshot());
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        let body = "not found\n";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    };
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Pure: is this request line exactly `GET /metrics [HTTP/x]`?
fn is_metrics_get(request_line: &str) -> bool {
    let mut parts = request_line.split_whitespace();
    matches!((parts.next(), parts.next()), (Some("GET"), Some(p)) if p == "/metrics")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    fn temp_sock(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pkcs11-metrics-{}-{}.sock", tag, std::process::id()))
    }

    #[test]
    fn accept_failure_backoff_grows_and_caps() {
        // W1-C2-02: persistent accept failure must back off (bounded CPU),
        // not busy-spin. First failure pauses briefly; sustained failure
        // grows the delay up to a cap.
        let first = accept_failure_backoff(1);
        assert!(first > Duration::ZERO, "first failure must pause");
        assert!(first <= Duration::from_millis(50), "transient failure barely pauses: {first:?}");
        let mut prev = first;
        for failures in 2..=10 {
            let next = accept_failure_backoff(failures);
            assert!(next >= prev, "backoff must not shrink: {prev:?} -> {next:?}");
            prev = next;
        }
        assert!(prev > first, "sustained failure must grow the delay");
        assert_eq!(
            accept_failure_backoff(1_000),
            Duration::from_secs(1),
            "backoff must cap so a recovered listener resumes promptly"
        );
    }

    #[test]
    fn is_metrics_get_matches_only_get_metrics() {
        assert!(is_metrics_get("GET /metrics HTTP/1.1"));
        assert!(is_metrics_get("GET /metrics"));
        assert!(!is_metrics_get("POST /metrics HTTP/1.1"));
        assert!(!is_metrics_get("GET /metricsX HTTP/1.1"));
        assert!(!is_metrics_get("GET / HTTP/1.1"));
        assert!(!is_metrics_get(""));
    }

    #[tokio::test]
    async fn serves_prometheus_on_get_metrics() {
        let path = temp_sock("ok");
        let _ = std::fs::remove_file(&path);
        spawn_metrics_endpoint(path.clone()).await.expect("bind");

        let mut s = UnixStream::connect(&path).await.expect("connect");
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        s.flush().await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut resp))
            .await
            .unwrap()
            .unwrap();
        let resp = String::from_utf8_lossy(&resp);

        assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
        assert!(resp.contains("pkcs11_proxy_find_objects_total"));
        assert!(resp.contains("pkcs11_proxy_find_objects_over_threshold_total"));
        assert!(resp.contains("pkcs11_proxy_find_result_size_max"));
        assert!(resp.contains("pkcs11_proxy_get_attribute_value_total"));
        assert!(resp.contains("pkcs11_proxy_audit_emitted_total"));
        assert!(resp.contains("pkcs11_proxy_audit_dropped_total"));
        assert!(resp.contains("pkcs11_proxy_rate_limit_rejected_total"));
        assert!(resp.contains("pkcs11_proxy_session_quota_rejected_total"));
        assert!(resp.contains("pkcs11_proxy_login_budget_tripped_total"));
        assert!(resp.contains("pkcs11_proxy_attr_coalesce_hits_total"));
        assert!(resp.contains("pkcs11_proxy_attr_coalesce_misses_total"));
        let _ = std::fs::remove_file(&path);
    }

    /// W1-L6-09: socket-spam must not spawn unbounded tasks. With the
    /// cap held by silent connections, an over-cap connection is dropped
    /// (peer sees EOF) instead of spawning another task. The holder
    /// count must exceed `MAX_CONCURRENT_METRICS_CONNS`.
    #[tokio::test]
    async fn metrics_endpoint_drops_connections_past_cap() {
        let path = temp_sock("cap");
        let _ = std::fs::remove_file(&path);
        spawn_metrics_endpoint(path.clone()).await.expect("bind");

        // Silent holders: each admitted connection blocks its server task
        // in the 2s request-read, holding one admission permit.
        let mut holders = Vec::new();
        for _ in 0..64 {
            holders.push(UnixStream::connect(&path).await.expect("connect holder"));
        }
        // Let the accept loop drain the backlog and fill the cap.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Over-cap: dropped — the GET is never answered (clean EOF or
        // RST, depending on whether the GET bytes were still queued when
        // the server closed), and no task spawns.
        let mut extra = UnixStream::connect(&path).await.expect("connect extra");
        let _ = extra.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").await;
        let mut resp = Vec::new();
        let outcome = tokio::time::timeout(Duration::from_secs(5), extra.read_to_end(&mut resp))
            .await
            .expect("dropped connection must terminate promptly");
        match outcome {
            Ok(_) => assert!(
                resp.is_empty(),
                "over-cap connection must be dropped (EOF), got: {}",
                String::from_utf8_lossy(&resp)
            ),
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Err(e) => panic!("over-cap connection read must EOF or reset, got: {e}"),
        }
        drop(holders);
        let _ = std::fs::remove_file(&path);
    }

    /// W1-L6-09: admission permits must release when a connection
    /// closes — sequential connections well past the cap must all be
    /// served (a leaked permit would start dropping at cap+1).
    #[tokio::test]
    async fn metrics_permits_release_after_each_connection() {
        let path = temp_sock("caprelease");
        let _ = std::fs::remove_file(&path);
        spawn_metrics_endpoint(path.clone()).await.expect("bind");

        for _ in 0..48 {
            let mut s = UnixStream::connect(&path).await.expect("connect");
            s.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").await.unwrap();
            let mut resp = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut resp))
                .await
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200 OK"),
                "sequential connection must be served (permits must release)"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn returns_404_on_other_path() {
        let path = temp_sock("404");
        let _ = std::fs::remove_file(&path);
        spawn_metrics_endpoint(path.clone()).await.expect("bind");
        let mut s = UnixStream::connect(&path).await.unwrap();
        s.write_all(b"GET /nope HTTP/1.1\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 404"));
        let _ = std::fs::remove_file(&path);
    }
}
