//! Minimal hand-rolled HTTP/1.1 `GET /metrics` responder on a mode-0600 Unix
//! socket. Zero new deps (tokio only). Local + authenticated by socket perms
//! (design V14). Read-only; exports COUNTS only (no secret material).

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{render_prometheus, snapshot};

/// Bind a mode-0600 Unix metrics socket and serve on a spawned task.
/// Returns once bound. Uses [`crate::server::transport::bind_unix_listener`]
/// for atomic 0600 creation (umask guard + is_socket stale-path check).
pub async fn spawn_metrics_endpoint(path: PathBuf) -> Result<(), String> {
    let listener = crate::server::transport::bind_unix_listener(&path)?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        if let Err(e) = serve_conn(stream).await {
                            tracing::debug!(error = %e, "metrics connection error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "metrics listener accept failed; retrying");
                    continue;
                }
            }
        }
    });
    Ok(())
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
