use clap::Parser;
use std::sync::Arc;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use pkcs11_proxy_ng::config;
use pkcs11_proxy_ng::server;
use pkcs11_proxy_ng::server::health;

type BoxError = Box<dyn std::error::Error>;
type Backend = Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>;

#[derive(Debug, Parser)]
#[command(name = "pkcs11-proxy-ng", about = "PKCS#11 remote proxy daemon", version)]
struct Args {
    /// Path to daemon TOML config.
    #[arg(value_name = "CONFIG", default_value = "config.toml", value_hint = clap::ValueHint::FilePath)]
    config: std::path::PathBuf,
}

/// Wait for either SIGINT (ctrl-c) or SIGTERM, then log and return.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
            _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("Received SIGINT, shutting down");
    }
}

fn init_tracing() {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).json().init();
}

fn load_backend(config: &config::DaemonConfig) -> Result<Backend, BoxError> {
    let backend: Backend = Arc::new(pkcs11_proxy_ng_backend::FfiBackend::load_with_init_args(
        &config.backend.module,
        config.backend.initialize_args.as_deref(),
    )?);
    backend.initialize().map_err(|rv| format!("C_Initialize failed: {rv}"))?;
    Ok(backend)
}

async fn build_service(
    config: &config::DaemonConfig,
    backend: &Backend,
) -> Result<
    (
        pkcs11_proxy_ng_proto::Pkcs11ProxyServer<server::grpc_service::Pkcs11ProxyService>,
        Arc<server::context_manager::ContextManager>,
    ),
    BoxError,
> {
    // Warn if the deprecated mechanism_discovery setting is explicitly set to
    // a non-default value.  The server is now a pure proxy for mechanism
    // discovery; filtering has moved to the client shim.
    if config.proxy.mechanism_discovery != config::MechanismDiscovery::default() {
        tracing::warn!(
            "proxy.mechanism_discovery is deprecated and ignored; \
             the server now proxies all backend mechanisms. \
             Mechanism filtering has moved to the client shim."
        );
    }

    let context_manager = Arc::new(server::context_manager::ContextManager::new(
        std::time::Duration::from_secs(config.proxy.lease_seconds),
        config.proxy.max_contexts,
    ));

    context_manager
        .populate_slots(backend)
        .await
        .map_err(|rv| format!("Slot population failed: {rv}"))?;
    tracing::info!("Slot map populated");

    let token_policy = Arc::new(
        server::auth::policy::TokenPolicy::from_config(&config.auth)
            .map_err(std::io::Error::other)?,
    );
    let tcp_auth_mode =
        config.listener.remote.as_ref().map(|tcp| tcp.auth).unwrap_or(config::TcpAuthMode::None);
    let service = server::grpc_service::Pkcs11ProxyService::new(
        context_manager.clone(),
        backend.clone(),
        tcp_auth_mode,
        token_policy,
    );
    let grpc_service = pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(service)
        .max_decoding_message_size(config.proxy.max_message_bytes)
        .max_encoding_message_size(config.proxy.max_message_bytes);

    Ok((grpc_service, context_manager))
}

fn resolve_bind_address(config: &config::DaemonConfig) -> Result<std::net::SocketAddr, BoxError> {
    if let Some(ref tcp_cfg) = config.listener.remote {
        Ok(tcp_cfg.bind.parse()?)
    } else if config.listener.local.is_some() {
        Err("Unix socket listener is dev/test-only and is not implemented in this binary; use [listener.remote] for supported runtime transport".into())
    } else {
        Ok("127.0.0.1:50051".parse()?)
    }
}

fn validate_runtime_listener_support(config: &config::DaemonConfig) -> Result<(), BoxError> {
    if config.listener.local.is_some() {
        return Err(
            "Unix socket listener is dev/test-only and is not implemented in this binary; use [listener.remote] for supported runtime transport".into()
        );
    }

    Ok(())
}

fn spawn_eviction_task(
    context_manager: Arc<server::context_manager::ContextManager>,
    backend: Backend,
    eviction_interval_secs: u64,
    max_contexts: usize,
    max_concurrent_backend_calls: usize,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(eviction_interval_secs));
        loop {
            interval.tick().await;
            let expired = context_manager.evict_expired(&backend).await;
            if !expired.is_empty() {
                tracing::info!(count = expired.len(), "Evicted expired contexts");
            }

            // Resource-aware logging
            let ctx_count = context_manager.context_count().await;
            if max_contexts > 0 && ctx_count > max_contexts * 80 / 100 {
                tracing::warn!(contexts = ctx_count, max = max_contexts, "context usage above 80%");
            }
            let in_flight = server::grpc_service::service_utils::backend_in_flight();
            if in_flight > max_concurrent_backend_calls * 80 / 100 {
                tracing::warn!(
                    in_flight,
                    max = max_concurrent_backend_calls,
                    "backend call usage above 80%"
                );
            }
        }
    });
}

fn main() -> Result<(), BoxError> {
    init_tracing();

    // Parse config early (before runtime) to get max_blocking_threads.
    let args = Args::parse();
    let config = config::DaemonConfig::load(&args.config)?;
    validate_runtime_listener_support(&config)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(config.proxy.max_blocking_threads)
        .build()?;

    runtime.block_on(async_main(config))
}

async fn async_main(config: config::DaemonConfig) -> Result<(), BoxError> {
    validate_runtime_listener_support(&config)?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health::set_not_serving(&mut health_reporter).await;

    let backend = load_backend(&config)?;
    tracing::info!("Backend module loaded and initialized");

    server::grpc_service::service_utils::configure_backend_guard(
        config.proxy.request_timeout_secs,
        config.proxy.max_concurrent_backend_calls,
    );

    let (svc, context_manager) = build_service(&config, &backend).await?;
    health::set_serving(&mut health_reporter).await;
    let addr = resolve_bind_address(&config)?;
    spawn_eviction_task(
        context_manager,
        backend.clone(),
        config.proxy.eviction_interval_secs,
        config.proxy.max_contexts,
        config.proxy.max_concurrent_backend_calls,
    );

    tracing::info!(%addr,
        lease_seconds = config.proxy.lease_seconds,
        max_message_bytes = config.proxy.max_message_bytes,
        request_timeout_secs = config.proxy.request_timeout_secs,
        max_concurrent_backend_calls = config.proxy.max_concurrent_backend_calls,
        max_blocking_threads = config.proxy.max_blocking_threads,
        eviction_interval_secs = config.proxy.eviction_interval_secs,
        max_contexts = config.proxy.max_contexts,
        http2_keepalive_interval_secs = config.proxy.http2_keepalive_interval_secs,
        http2_keepalive_timeout_secs = config.proxy.http2_keepalive_timeout_secs,
        "Starting gRPC server");
    // NOTE: No tonic server-level .timeout() — request timeouts are handled
    // inside spawn_backend() via tokio::time::timeout. A tonic-level timeout
    // would cancel the handler Future before spawn_backend can decrement
    // IN_FLIGHT, causing circuit breaker leaks under heavy load.
    let mut builder = Server::builder();
    if let Some(ref tcp_cfg) = config.listener.remote
        && let Some(tls_config) =
            server::transport::server_tls_config(tcp_cfg).map_err(std::io::Error::other)?
    {
        builder = builder.tls_config(tls_config)?;
    }
    if config.proxy.http2_keepalive_interval_secs > 0 {
        builder = builder
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(
                config.proxy.http2_keepalive_interval_secs,
            )))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(
                config.proxy.http2_keepalive_timeout_secs,
            )));
    }
    builder
        .add_service(health_service)
        .add_service(svc)
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    backend.finalize().map_err(|rv| format!("C_Finalize failed: {rv}"))?;
    tracing::info!("Daemon stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(toml: &str) -> config::DaemonConfig {
        toml::from_str(toml).expect("test config should parse")
    }

    #[test]
    fn runtime_accepts_mtls_listener_when_transport_is_wired() {
        let cfg = parse_config(
            r#"
[backend]
module = "/dev/null"

[listener.remote]
bind = "127.0.0.1:50051"
auth = "mtls"
ca_cert = "/dev/null"
server_cert = "/dev/null"
server_key = "/dev/null"

[auth]
allow_all_authenticated = true
"#,
        );

        validate_runtime_listener_support(&cfg).expect("mTLS runtime support is wired");
    }

    #[test]
    fn runtime_accepts_explicit_insecure_tcp_listener() {
        let cfg = parse_config(
            r#"
[backend]
module = "/dev/null"

[listener.remote]
bind = "127.0.0.1:50051"
auth = "none"
allow_insecure_tcp = true
"#,
        );

        validate_runtime_listener_support(&cfg).expect("explicit insecure TCP dev mode");
    }

    #[test]
    fn runtime_rejects_unix_listener_until_transport_is_wired() {
        let cfg = parse_config(
            r#"
[backend]
module = "/dev/null"

[listener.local]
path = "/tmp/pkcs11-proxy-ng.sock"
auth = "none"
"#,
        );

        let err = validate_runtime_listener_support(&cfg).unwrap_err().to_string();

        assert!(err.contains("Unix socket listener"), "error should name unsupported transport");
        assert!(err.contains("dev/test-only"), "error should explain Unix socket scope: {err}");
        assert!(err.contains("not implemented"), "error should fail closed clearly: {err}");
    }
}
