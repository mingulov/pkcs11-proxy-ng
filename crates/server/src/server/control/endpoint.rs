//! Unix control endpoint behind `native-owner-test-hooks`. See
//! [`super`] for the route table.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use pkcs11_proxy_ng_backend::test_hooks;

/// Bind a mode-0600 Unix control socket and serve on a spawned task.
/// Returns once bound. Uses [`crate::server::transport::bind_unix_listener`]
/// for atomic 0600 creation (umask guard + is_socket stale-path check).
pub async fn spawn_control_endpoint(path: PathBuf) -> Result<(), String> {
    let listener = crate::server::transport::bind_unix_listener(&path)?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        if let Err(e) = serve_conn(stream).await {
                            tracing::debug!(error = %e, "control connection error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "control listener accept failed; retrying");
                    continue;
                }
            }
        }
    });
    Ok(())
}

/// Pure: map a `(method, path)` pair to a response body plus status line.
fn route(method: &str, path: &str) -> (&'static str, String) {
    match (method, path) {
        ("GET", "/hooks/instance") => (
            "HTTP/1.1 200 OK",
            format!("{{\"instance_id\":{}}}\n", test_hooks::daemon_instance_id()),
        ),
        ("GET", "/hooks/last-mechanism") => (
            "HTTP/1.1 200 OK",
            match test_hooks::take_last_mechanism() {
                Some(echo) => format!(
                    "{{\"seq\":{},\"mechanism\":{},\"parameter\":\"{}\"}}\n",
                    echo.seq,
                    echo.mechanism,
                    hex::encode(&echo.parameter),
                ),
                None => "{\"none\":true}\n".to_string(),
            },
        ),
        ("POST", "/hooks/fail-next-close") => {
            test_hooks::set_fail_next_close(true);
            ("HTTP/1.1 200 OK", "{\"armed\":true}\n".to_string())
        }
        _ => ("HTTP/1.1 404 Not Found", "not found\n".to_string()),
    }
}

async fn serve_conn(mut stream: UnixStream) -> io::Result<()> {
    // Bounded, time-limited read of the request head (defends against slow/large clients).
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request read timeout"))??;
    let head = String::from_utf8_lossy(&buf[..n]);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let (status, body) = route(parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let response = format!(
        "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    fn temp_sock(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pkcs11-control-{}-{}.sock", tag, std::process::id()))
    }

    async fn round_trip(path: &std::path::Path, request: &[u8]) -> String {
        let mut s = UnixStream::connect(path).await.expect("connect");
        s.write_all(request).await.unwrap();
        s.flush().await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut resp))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    #[test]
    fn unknown_route_is_404() {
        let (status, _) = route("GET", "/nope");
        assert_eq!(status, "HTTP/1.1 404 Not Found");
        let (status, _) = route("POST", "/hooks/instance");
        assert_eq!(status, "HTTP/1.1 404 Not Found");
    }

    #[test]
    fn last_mechanism_empty_reports_none() {
        assert_eq!(test_hooks::take_last_mechanism(), None);
        let (status, body) = route("GET", "/hooks/last-mechanism");
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(body, "{\"none\":true}\n");
    }

    #[tokio::test]
    async fn instance_endpoint_is_stable_and_nonzero() {
        let path = temp_sock("instance");
        let _ = std::fs::remove_file(&path);
        spawn_control_endpoint(path.clone()).await.expect("bind");

        let first = round_trip(&path, b"GET /hooks/instance HTTP/1.1\r\n\r\n").await;
        let second = round_trip(&path, b"GET /hooks/instance HTTP/1.1\r\n\r\n").await;
        assert!(first.starts_with("HTTP/1.1 200 OK"), "resp: {first}");
        assert_eq!(first, second, "instance id must be stable within one daemon");
        let id: u64 = first
            .lines()
            .last()
            .unwrap()
            .trim_start_matches("{\"instance_id\":")
            .trim_end_matches('}')
            .parse()
            .expect("instance body parses");
        assert_ne!(id, 0);
        assert_eq!(id, test_hooks::daemon_instance_id());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn echo_endpoint_reports_recorded_mechanism() {
        let path = temp_sock("echo");
        let _ = std::fs::remove_file(&path);
        spawn_control_endpoint(path.clone()).await.expect("bind");
        assert_eq!(test_hooks::take_last_mechanism(), None);

        let seq = test_hooks::record_mechanism(0x1082, &[0xde, 0xad]);
        let resp = round_trip(&path, b"GET /hooks/last-mechanism HTTP/1.1\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
        let body = resp.lines().last().unwrap();
        assert_eq!(body, &format!("{{\"seq\":{seq},\"mechanism\":4226,\"parameter\":\"dead\"}}"));
        // The read consumes the echo: a second GET reports none.
        let again = round_trip(&path, b"GET /hooks/last-mechanism HTTP/1.1\r\n\r\n").await;
        assert!(again.ends_with("{\"none\":true}\n"), "resp: {again}");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn fail_next_close_endpoint_arms_injector() {
        let path = temp_sock("fault");
        let _ = std::fs::remove_file(&path);
        spawn_control_endpoint(path.clone()).await.expect("bind");
        assert!(!test_hooks::take_fail_next_close());

        let resp = round_trip(&path, b"POST /hooks/fail-next-close HTTP/1.1\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
        assert!(resp.ends_with("{\"armed\":true}\n"), "resp: {resp}");
        assert!(
            test_hooks::take_fail_next_close(),
            "POST must arm exactly one injected close failure"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn unknown_path_is_404_over_the_wire() {
        let path = temp_sock("404");
        let _ = std::fs::remove_file(&path);
        spawn_control_endpoint(path.clone()).await.expect("bind");
        let resp = round_trip(&path, b"GET /nope HTTP/1.1\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404"), "resp: {resp}");
        let _ = std::fs::remove_file(&path);
    }
}
