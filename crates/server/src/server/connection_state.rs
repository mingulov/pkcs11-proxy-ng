//! Per-connection liveness state for transport-aware context reaping.
//!
//! Every accepted TCP/UDS connection gets one [`ConnectionState`],
//! registered in the shared [`ConnectionRegistry`] under a peer key
//! derived from the transport peer (TCP socket address; UDS peer pid
//! when available, else the listener socket path). The tracked stream
//! wrapper ([`TrackedStream`]) marks the state closed and unregisters
//! it on drop, exactly when tonic tears the connection down.
//!
//! A context created by `Initialize` stores only a `Weak` to its
//! connection's state (resolved through the registry from the request's
//! transport extensions, mirroring `request_identity`). It is
//! transport-dead when the weak fails to upgrade (state dropped) or
//! upgrades to a closed state. Contexts with no connection binding
//! (tests, internal callers) store `None` and are never transport-dead.

use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;
#[cfg(unix)]
use tonic::transport::server::UdsConnectInfo;

/// Liveness of one accepted transport connection.
#[derive(Debug)]
pub struct ConnectionState {
    closed: AtomicBool,
}

impl ConnectionState {
    /// A fresh, live connection state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self { closed: AtomicBool::new(false) })
    }

    /// Whether the owning connection has been torn down.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Mark the connection torn down (tracked-stream drop).
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// Registry of live connection states keyed by transport peer.
///
/// Shared between the listeners (which register/unregister on
/// accept/drop) and the [`super::context_manager::ContextManager`]
/// (which resolves a request's connection and reads context liveness).
/// Entries are removed by the tracked stream's drop, so the map stays
/// bounded by live connections.
#[derive(Debug, Default)]
pub struct ConnectionRegistry {
    by_peer: DashMap<String, Arc<ConnectionState>>,
}

impl ConnectionRegistry {
    /// A fresh, empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self { by_peer: DashMap::new() })
    }

    /// Register `state` under `peer_key`, replacing any stale entry
    /// for the same key (a reconnected peer re-registers).
    pub fn register(&self, peer_key: String, state: Arc<ConnectionState>) {
        self.by_peer.insert(peer_key, state);
    }

    /// The live state registered for `peer_key`, if any.
    pub fn lookup(&self, peer_key: &str) -> Option<Arc<ConnectionState>> {
        self.by_peer.get(peer_key).map(|entry| Arc::clone(entry.value()))
    }

    /// Remove the entry for `peer_key` only when it still names
    /// `state` (a newer connection for the same peer must survive an
    /// older connection's teardown).
    pub fn unregister(&self, peer_key: &str, state: &Arc<ConnectionState>) {
        self.by_peer.remove_if(peer_key, |_, current| Arc::ptr_eq(current, state));
    }

    /// Number of registered live connections (tests/diagnostics).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_peer.len()
    }
}

/// Peer key for a TCP connection: its remote socket address, which is
/// unique per connection (ephemeral port included).
pub fn tcp_peer_key(peer: SocketAddr) -> String {
    format!("tcp:{peer}")
}

/// Peer key for a UDS connection: the peer pid when the kernel
/// provides one, else the listener socket path (all connections to
/// that listener then share one key — the coarsest available peer
/// distinction on platforms without peer pids).
#[cfg(unix)]
pub fn uds_peer_key(cred: Option<&tokio::net::unix::UCred>, socket_path: &Path) -> String {
    match cred.and_then(|c| c.pid()) {
        Some(pid) => format!("uds:pid={pid}"),
        None => format!("uds:path={}", socket_path.display()),
    }
}

/// Peer key naming the connection that carried `request`, mirroring
/// `request_identity`'s transport discrimination: a request carrying
/// tonic's `UdsConnectInfo` is UDS, every other request is TCP (its
/// `remote_addr()` also unwraps the mTLS `TlsConnectInfo` form).
/// `None` when the transport peer cannot be named (peerless test
/// requests, or UDS without a peer pid).
pub fn peer_key_for_request<T>(request: &tonic::Request<T>) -> Option<String> {
    #[cfg(unix)]
    if let Some(uds) = request.extensions().get::<UdsConnectInfo>() {
        return uds
            .peer_cred
            .as_ref()
            .and_then(|cred| cred.pid())
            .map(|pid| format!("uds:pid={pid}"));
    }
    request.remote_addr().map(tcp_peer_key)
}

/// Resolve the live [`ConnectionState`] for `request` through
/// `registry`. `None` when the request is peerless or its connection
/// is no longer registered (already torn down).
pub fn connection_state_for_request<T>(
    registry: &ConnectionRegistry,
    request: &tonic::Request<T>,
) -> Option<Arc<ConnectionState>> {
    peer_key_for_request(request).and_then(|key| registry.lookup(&key))
}

/// A transport stream that owns one [`ConnectionState`]: registered
/// on construction, marked closed and unregistered on drop. Delegates
/// `AsyncRead`/`AsyncWrite`/`Connected` to the inner stream, so
/// tonic observes the original connect info (TCP address, UDS peer
/// credentials, and the TLS wrapping over both) unchanged.
pub struct TrackedStream<S> {
    inner: S,
    state: Arc<ConnectionState>,
    registry: Arc<ConnectionRegistry>,
    peer_key: String,
}

impl<S> TrackedStream<S> {
    /// Wrap `inner`, registering a fresh live state under `peer_key`.
    pub fn new(inner: S, registry: Arc<ConnectionRegistry>, peer_key: String) -> Self {
        let state = ConnectionState::new();
        registry.register(peer_key.clone(), Arc::clone(&state));
        Self { inner, state, registry, peer_key }
    }

    /// The connection state owned by this stream.
    pub fn connection_state(&self) -> Arc<ConnectionState> {
        Arc::clone(&self.state)
    }
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        self.state.mark_closed();
        self.registry.unregister(&self.peer_key, &self.state);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: Connected> Connected for TrackedStream<S> {
    type ConnectInfo = S::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_unregister_only_removes_owning_state() {
        let registry = ConnectionRegistry::new();
        let first = ConnectionState::new();
        let second = ConnectionState::new();
        registry.register("tcp:192.0.2.1:1".into(), Arc::clone(&first));
        registry.register("tcp:192.0.2.1:1".into(), Arc::clone(&second));
        // The stale owner's teardown must not evict the newer entry.
        registry.unregister("tcp:192.0.2.1:1", &first);
        assert!(Arc::ptr_eq(&registry.lookup("tcp:192.0.2.1:1").unwrap(), &second));
        registry.unregister("tcp:192.0.2.1:1", &second);
        assert!(registry.lookup("tcp:192.0.2.1:1").is_none());
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn tracked_stream_drop_marks_closed_and_unregisters() {
        let registry = ConnectionRegistry::new();
        let (client, server) = tokio::io::duplex(64);
        let _ = client;
        let tracked = TrackedStream::new(server, Arc::clone(&registry), "test:peer".into());
        let state = tracked.connection_state();
        assert!(!state.is_closed());
        assert!(registry.lookup("test:peer").is_some());
        drop(tracked);
        assert!(state.is_closed(), "drop must mark the connection closed");
        assert!(registry.lookup("test:peer").is_none(), "drop must unregister the connection");
    }

    #[test]
    fn tcp_peer_key_names_remote_addr() {
        let peer: SocketAddr = "192.0.2.7:4321".parse().unwrap();
        assert_eq!(tcp_peer_key(peer), "tcp:192.0.2.7:4321");
    }
}
