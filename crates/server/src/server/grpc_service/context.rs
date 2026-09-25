//! Cross-cutting handler state (ADR-0003 gRPC dispatch).
//!
//! Every dispatched gRPC handler needs the same shared, request-independent
//! state: the context manager, the backend handle, the token policy, the
//! mechanism registry source, the transport auth modes, the `sanitize_inputs`
//! toggle, and the (optional) audit sink. Threading these as separate
//! positional parameters through ~90 handler functions meant every new gateway
//! concern (audit, and later authz / rate-limiting) grew every signature.
//!
//! `HandlerContext` aggregates that state into one value so handlers take
//! `(ctx: &HandlerContext, request)` and a future concern becomes a field, not
//! a fleet of signature changes. It is cheap to `Clone` — every field is an
//! `Arc`, a `Copy` mode enum, a `bool`, or a clone-cheap `Option<AuditSink>`.

use std::sync::Arc;

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use crate::config::{TcpAuthMode, UnixAuthMode};
use crate::mechanism_registry_source::MechanismRegistrySource;
use crate::server::audit::AuditSink;
use crate::server::auth::policy::TokenPolicy;
use crate::server::context_manager::ContextManager;

/// Shared, request-independent state passed by reference to every dispatched
/// gRPC handler. See the module docs for the rationale.
#[derive(Clone)]
pub(crate) struct HandlerContext {
    pub(crate) context_manager: Arc<ContextManager>,
    pub(crate) backend: Arc<dyn Pkcs11Backend>,
    pub(crate) token_policy: Arc<TokenPolicy>,
    /// Holds the current registry payload to publish over
    /// `GetBackendInterfaces`. Wrapped in a `MechanismRegistrySource` so SIGHUP
    /// can swap the payload while live requests are in flight.
    pub(crate) mechanism_registry_source: MechanismRegistrySource,
    pub(crate) tcp_auth_mode: TcpAuthMode,
    pub(crate) unix_auth_mode: UnixAuthMode,
    /// ADR-0010 sanitize_inputs: when true, NULL data pointer with len>0 and
    /// NULL mechanisms on operation init are rejected with CKR_ARGUMENTS_BAD
    /// before reaching the backend module. Default false (transparent
    /// forwarding).
    pub(crate) sanitize_inputs: bool,
    /// G1-PR2: audit sink shared across all gRPC handlers. `None` when audit is
    /// not configured (zero-overhead default). Clone is cheap (Arc internally).
    ///
    /// Emission is wired in `grpc_service/audit_events.rs`; handlers call
    /// `emit_auth_event` after each auth/key-mgmt/system operation.
    pub(crate) audit: Option<AuditSink>,
}

#[cfg(test)]
impl HandlerContext {
    /// Build a `HandlerContext` for handler unit tests: real context manager and
    /// backend, permissive defaults for everything else (default token policy,
    /// no transport auth, embedded mechanism registry, `sanitize_inputs` off, no
    /// audit). Mirrors `Pkcs11ProxyService::insecure_for_tests`.
    pub(crate) fn for_test(
        context_manager: &Arc<ContextManager>,
        backend: &Arc<dyn Pkcs11Backend>,
    ) -> Self {
        let token_policy = Arc::new(
            TokenPolicy::from_config(&crate::config::AuthConfig::default())
                .expect("default policy"),
        );
        let mechanism_registry_source = MechanismRegistrySource::load(None)
            .expect("embedded mechanism registry must always load");
        Self {
            context_manager: Arc::clone(context_manager),
            backend: Arc::clone(backend),
            token_policy,
            mechanism_registry_source,
            tcp_auth_mode: TcpAuthMode::None,
            unix_auth_mode: UnixAuthMode::None,
            sanitize_inputs: false,
            audit: None,
        }
    }
}
