//! Transport liveness state for transport-aware context reaping,
//! grouped by peer identity.
//!
//! Liveness contract (per transport):
//!
//! - **UDS is per-process.** Peer identity is the process, identified
//!   by pid from the kernel peer credentials — the same
//!   `SO_PEERCRED` source `request_identity` authenticates from. All
//!   concurrent connections from one pid share one group
//!   [`ConnectionState`]: the group is live while at least one
//!   connection from that process is open, and a context bound to it
//!   is transport-dead only when the process has *no* live
//!   connections left (its last tracked stream drops, which marks
//!   the group closed and unregisters it). One connection of a
//!   process dropping (e.g. a reconnect overlap where the old
//!   connection tears down after its replacement is accepted) never
//!   kills the group. Same process therefore means same connection
//!   for admission replacement; a different pid is a different
//!   connection.
//! - **TCP is per-connection.** The peer key is the remote socket
//!   address including the ephemeral port, so every TCP connection
//!   is its own group (live count 1 in practice) and is
//!   transport-dead exactly when that connection drops.
//! - **Peerless is never transport-dead.** A UDS connection whose
//!   peer pid the kernel did not provide, a TCP connection without
//!   a remote address, and test/internal callers have no peer key:
//!   nothing is registered for them, requests on them resolve no
//!   connection, and their contexts bind `None`.
//!
//! A context created by `Initialize` stores a SET of `Weak`s to
//! the groups that have carried owner-checked requests for it,
//! starting with its `Initialize` group (resolved through the
//! registry from the request's transport extensions, mirroring
//! `request_identity`) and adding each live group a later request
//! arrives on — never evicting a still-live older group, so the
//! set's liveness is independent of request order. It is
//! transport-dead only when it was bound and no live entry remains
//! (every weak fails to upgrade or upgrades to a closed state,
//! pruned on read). Contexts never bound (tests, internal callers)
//! store `None` and are never transport-dead; a bound context whose
//! set prunes to empty IS transport-dead.

use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;
#[cfg(unix)]
use tonic::transport::server::UdsConnectInfo;

/// Liveness of one connection group (see module docs): one process
/// on UDS, one connection on TCP. `live_connections` counts the
/// tracked streams currently sharing this group; the group closes
/// only when that count reaches zero.
#[derive(Debug)]
pub struct ConnectionState {
    closed: AtomicBool,
    live_connections: AtomicUsize,
}

impl ConnectionState {
    /// A fresh, live group state with one live connection.
    pub fn new() -> Arc<Self> {
        Arc::new(Self { closed: AtomicBool::new(false), live_connections: AtomicUsize::new(1) })
    }

    /// Whether every connection in the group has been torn down.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Mark the group torn down. Production callers go through the
    /// registry's counted release; this stays public for tests that
    /// simulate a connection death directly.
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Number of live connections sharing this group.
    pub fn live_connection_count(&self) -> usize {
        self.live_connections.load(Ordering::SeqCst)
    }

    /// Record one more connection joining this group.
    fn join(&self) {
        self.live_connections.fetch_add(1, Ordering::SeqCst);
    }

    /// Record one connection leaving this group; `true` when it was
    /// the last one (count reached zero).
    fn leave_is_last(&self) -> bool {
        let prev = self.live_connections.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            // Double release: stay at zero instead of wrapping.
            self.live_connections.store(0, Ordering::SeqCst);
            true
        } else {
            prev == 1
        }
    }
}

/// Registry of live connection groups keyed by transport peer
/// (UDS pid, TCP socket address; see module docs).
///
/// Shared between the listeners (which register/unregister on
/// accept/drop) and the [`super::context_manager::ContextManager`]
/// (which resolves a request's connection and reads context liveness).
/// An entry is removed by the last tracked stream of its group, so
/// the map stays bounded by live peer groups.
#[derive(Debug, Default)]
pub struct ConnectionRegistry {
    by_peer: DashMap<String, Arc<ConnectionState>>,
}

impl ConnectionRegistry {
    /// A fresh, empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self { by_peer: DashMap::new() })
    }

    /// Register one new connection under `peer_key`, returning the
    /// group state it belongs to. When a group is already registered
    /// for the key (another live connection from the same UDS
    /// process), the new connection *joins* it: the existing state
    /// is returned with its live count incremented and the candidate
    /// `state` is discarded. Otherwise `state` becomes the group.
    pub fn register(&self, peer_key: String, state: Arc<ConnectionState>) -> Arc<ConnectionState> {
        use dashmap::mapref::entry::Entry;
        match self.by_peer.entry(peer_key) {
            Entry::Occupied(entry) => {
                let existing = Arc::clone(entry.get());
                existing.join();
                existing
            }
            Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&state));
                state
            }
        }
    }

    /// The live state registered for `peer_key`, if any.
    pub fn lookup(&self, peer_key: &str) -> Option<Arc<ConnectionState>> {
        self.by_peer.get(peer_key).map(|entry| Arc::clone(entry.value()))
    }

    /// Release one connection's share of the group named by
    /// `peer_key`. Only a release naming the registered group counts
    /// (a discarded candidate's release is a no-op, so a stale owner
    /// cannot evict a live group). The group is marked closed and
    /// unregistered only when its live count reaches zero; while
    /// other connections from the same peer remain, it stays live
    /// and registered. A join racing the final release revives the
    /// group instead of being evicted (checked again under the
    /// shard lock by `remove_if`).
    pub fn unregister(&self, peer_key: &str, state: &Arc<ConnectionState>) {
        let is_last = {
            let Some(entry) = self.by_peer.get(peer_key) else {
                return;
            };
            if !Arc::ptr_eq(entry.value(), state) {
                return;
            }
            state.leave_is_last()
        };
        if is_last
            && self
                .by_peer
                .remove_if(peer_key, |_, current| {
                    Arc::ptr_eq(current, state) && current.live_connection_count() == 0
                })
                .is_some()
        {
            state.mark_closed();
        }
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
/// provides one. `None` when it does not — such a connection is
/// peerless (nothing registered; its contexts bind `None` and are
/// never transport-dead). There is deliberately no socket-path
/// fallback key: the request side can never produce one
/// (`peer_key_for_request` returns `None` without a pid), so
/// registering under it would create entries nothing can look up.
#[cfg(unix)]
pub fn uds_peer_key(cred: Option<&tokio::net::unix::UCred>) -> Option<String> {
    cred.and_then(|c| c.pid()).map(|pid| format!("uds:pid={pid}"))
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

/// A transport stream that holds one share of a [`ConnectionState`]
/// group: registered (or joined into the peer's existing group) on
/// construction, released on drop. The group is marked closed and
/// unregistered only when its last connection drops, so a same-pid
/// UDS reconnect overlap keeps the group live. A peerless stream
/// (`peer_key: None`) registers nothing and releases nothing.
/// Delegates `AsyncRead`/`AsyncWrite`/`Connected` to the inner
/// stream, so tonic observes the original connect info (TCP
/// address, UDS peer credentials, and the TLS wrapping over both)
/// unchanged.
pub struct TrackedStream<S> {
    inner: S,
    state: Arc<ConnectionState>,
    registry: Arc<ConnectionRegistry>,
    peer_key: Option<String>,
}

impl<S> TrackedStream<S> {
    /// Wrap `inner`. With `Some(peer_key)` the stream joins (or
    /// creates) that peer's group in `registry`; with `None` it is
    /// peerless and unregistered.
    pub fn new(inner: S, registry: Arc<ConnectionRegistry>, peer_key: Option<String>) -> Self {
        let state = match &peer_key {
            Some(key) => registry.register(key.clone(), ConnectionState::new()),
            None => ConnectionState::new(),
        };
        Self { inner, state, registry, peer_key }
    }

    /// The group state this stream shares in.
    pub fn connection_state(&self) -> Arc<ConnectionState> {
        Arc::clone(&self.state)
    }
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        match &self.peer_key {
            // Counted release: closes/unregisters only at zero.
            Some(key) => self.registry.unregister(key, &self.state),
            None => self.state.mark_closed(),
        }
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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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
    fn registry_register_joins_group_and_stale_unregister_is_noop() {
        let registry = ConnectionRegistry::new();
        let first = ConnectionState::new();
        let candidate = ConnectionState::new();
        let joined = registry.register("uds:pid=77".into(), Arc::clone(&first));
        assert!(Arc::ptr_eq(&joined, &first));
        // Second registration for the same key joins the existing
        // group (count 2); its candidate state is discarded.
        let joined = registry.register("uds:pid=77".into(), Arc::clone(&candidate));
        assert!(Arc::ptr_eq(&joined, &first), "same key must join the existing group");
        assert_eq!(first.live_connection_count(), 2);
        // Releasing via the discarded candidate is a no-op (ptr
        // guard): it must neither decrement nor evict the group.
        registry.unregister("uds:pid=77", &candidate);
        assert_eq!(first.live_connection_count(), 2);
        assert!(!first.is_closed());
        assert!(registry.lookup("uds:pid=77").is_some());
        // One group connection leaves: still live and registered.
        registry.unregister("uds:pid=77", &first);
        assert_eq!(first.live_connection_count(), 1);
        assert!(!first.is_closed(), "group stays live while a connection remains");
        assert!(registry.lookup("uds:pid=77").is_some());
        // Last connection leaves: closed and unregistered.
        registry.unregister("uds:pid=77", &first);
        assert_eq!(first.live_connection_count(), 0);
        assert!(first.is_closed());
        assert!(registry.lookup("uds:pid=77").is_none());
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn tracked_stream_drop_marks_closed_and_unregisters() {
        let registry = ConnectionRegistry::new();
        let (client, server) = tokio::io::duplex(64);
        let _ = client;
        let tracked = TrackedStream::new(server, Arc::clone(&registry), Some("test:peer".into()));
        let state = tracked.connection_state();
        assert!(!state.is_closed());
        assert!(registry.lookup("test:peer").is_some());
        drop(tracked);
        assert!(state.is_closed(), "drop must mark the connection closed");
        assert!(registry.lookup("test:peer").is_none(), "drop must unregister the connection");
    }

    #[tokio::test]
    async fn peerless_tracked_stream_registers_nothing() {
        let registry = ConnectionRegistry::new();
        let (client, server) = tokio::io::duplex(64);
        let _ = client;
        let tracked = TrackedStream::new(server, Arc::clone(&registry), None);
        let state = tracked.connection_state();
        assert!(!state.is_closed());
        assert_eq!(registry.len(), 0, "peerless stream must not register");
        drop(tracked);
        assert!(state.is_closed());
        assert_eq!(registry.len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn uds_peer_key_without_pid_is_peerless() {
        assert_eq!(uds_peer_key(None), None);
    }

    #[test]
    fn tcp_peer_key_names_remote_addr() {
        let peer: SocketAddr = "192.0.2.7:4321".parse().unwrap();
        assert_eq!(tcp_peer_key(peer), "tcp:192.0.2.7:4321");
    }

    #[tokio::test]
    async fn same_key_tracked_streams_share_group_until_last_drop() {
        let registry = ConnectionRegistry::new();
        let (_c1, s1) = tokio::io::duplex(64);
        let (_c2, s2) = tokio::io::duplex(64);
        let first = TrackedStream::new(s1, Arc::clone(&registry), Some("uds:pid=4242".into()));
        let group = first.connection_state();
        let second = TrackedStream::new(s2, Arc::clone(&registry), Some("uds:pid=4242".into()));
        assert!(
            Arc::ptr_eq(&group, &second.connection_state()),
            "same peer key must join the existing group state"
        );
        drop(first);
        assert!(!group.is_closed(), "group must stay live while one connection remains");
        assert!(registry.lookup("uds:pid=4242").is_some(), "group must stay registered");
        drop(second);
        assert!(group.is_closed(), "group must close when its last connection drops");
        assert!(registry.lookup("uds:pid=4242").is_none(), "group must unregister at zero");
    }

    #[tokio::test]
    async fn distinct_tcp_keys_have_independent_groups() {
        let registry = ConnectionRegistry::new();
        let (_c1, s1) = tokio::io::duplex(64);
        let (_c2, s2) = tokio::io::duplex(64);
        let a = TrackedStream::new(s1, Arc::clone(&registry), Some("tcp:192.0.2.1:40001".into()));
        let b = TrackedStream::new(s2, Arc::clone(&registry), Some("tcp:192.0.2.1:40002".into()));
        let state_a = a.connection_state();
        let state_b = b.connection_state();
        assert!(!Arc::ptr_eq(&state_a, &state_b), "TCP keys are per-connection");
        drop(a);
        assert!(state_a.is_closed());
        assert!(!state_b.is_closed(), "dropping one TCP connection must not close another");
        assert!(registry.lookup("tcp:192.0.2.1:40002").is_some());
        drop(b);
        assert!(state_b.is_closed());
        assert!(registry.lookup("tcp:192.0.2.1:40002").is_none());
    }
}
