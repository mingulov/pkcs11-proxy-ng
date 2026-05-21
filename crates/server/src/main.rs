use clap::Parser;
use std::sync::Arc;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use pkcs11_proxy_ng::config;
use pkcs11_proxy_ng::mechanism_registry_source::MechanismRegistrySource;
use pkcs11_proxy_ng::server;
use pkcs11_proxy_ng::server::health;

type BoxError = Box<dyn core::error::Error>;
type Backend = Arc<dyn pkcs11_proxy_ng_backend::Pkcs11Backend>;

#[derive(Debug, Parser)]
#[command(name = "pkcs11-proxy-ng", about = "PKCS#11 remote proxy daemon", version)]
struct Args {
    /// Path to daemon TOML config.
    #[arg(value_name = "CONFIG", default_value = "config.toml", value_hint = clap::ValueHint::FilePath)]
    config: std::path::PathBuf,

    /// Print the table of environment variables the daemon recognises
    /// (and the TOML field each one overrides), then exit. Closes
    /// FOLLOWUP-env-var-cli-help.
    #[arg(long)]
    print_env_vars: bool,
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
        MechanismRegistrySource,
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

    // Backend-probe startup timeout (config.proxy.startup_timeout_secs).
    // If populate_slots takes too long the daemon exits 1 so the operator
    // sees a clear startup failure rather than a hung process.
    let startup_timeout = std::time::Duration::from_secs(config.proxy.startup_timeout_secs);
    match tokio::time::timeout(startup_timeout, context_manager.populate_slots(backend)).await {
        Ok(Ok(())) => {
            tracing::info!("Slot map populated");
        }
        Ok(Err(rv)) => {
            return Err(format!("Slot population failed: {rv}").into());
        }
        Err(_) => {
            return Err(format!(
                "Slot population exceeded proxy.startup_timeout_secs={}s; daemon refusing to start",
                config.proxy.startup_timeout_secs
            )
            .into());
        }
    }

    // Load mechanism registry from configured file (or embedded default).
    // Logged so the operator can see the served revision at startup.
    let registry_source = MechanismRegistrySource::load(config.mechanisms.config_path.as_deref())
        .map_err(|e| format!("Mechanism registry load failed: {e}"))?;
    {
        let payload = registry_source.current();
        tracing::info!(
            revision = %payload.revision,
            discovery_mode = %payload.discovery_mode,
            parameterless = payload.parameterless.len(),
            param_shapes = payload.params.len(),
            "mechanism registry ready"
        );
    }

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
        registry_source.clone(),
    );
    let grpc_service = pkcs11_proxy_ng_proto::Pkcs11ProxyServer::new(service)
        .max_decoding_message_size(config.proxy.max_message_bytes)
        .max_encoding_message_size(config.proxy.max_message_bytes);

    Ok((grpc_service, context_manager, registry_source))
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

/// On SIGHUP the daemon reloads `mechanisms.config_path` and swaps the
/// served payload atomically. Reload failures retain the current
/// registry — the daemon must never crash because the operator pushed
/// a malformed TOML file mid-rollout.
#[cfg(unix)]
fn spawn_sighup_handler(registry_source: MechanismRegistrySource) {
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGHUP handler");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            match registry_source.reload() {
                Ok(payload) => tracing::info!(
                    revision = %payload.revision,
                    discovery_mode = %payload.discovery_mode,
                    parameterless = payload.parameterless.len(),
                    param_shapes = payload.params.len(),
                    "mechanism registry reloaded"
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    config_path = ?registry_source.config_path(),
                    "mechanism registry reload failed; retaining previous registry"
                ),
            }
        }
    });
}

/// Bridge between `spawn_backend`'s outcome channel and the
/// `tonic-health` reporter. Counts consecutive backend failures; flips
/// the per-service health status to `NOT_SERVING` once the count
/// reaches `threshold`, and flips it back to `SERVING` on the next
/// successful backend call. Driven by `proxy.backend_health_consecutive_failures`.
fn spawn_backend_health_gate(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<
        server::grpc_service::service_utils::BackendHealthEvent,
    >,
    mut reporter: tonic_health::server::HealthReporter,
    threshold: u32,
) {
    tracing::info!(threshold, "backend health gate starting");
    tokio::spawn(async move {
        use server::grpc_service::service_utils::BackendHealthEvent;
        let mut consecutive_failures: u32 = 0;
        // We assume the daemon enters this task already in the SERVING
        // state — the spawn point in `async_main` calls
        // `health::set_serving` immediately before us.
        let mut currently_serving = true;
        while let Some(event) = rx.recv().await {
            tracing::debug!(?event, consecutive_failures, "backend health event received");
            match event {
                BackendHealthEvent::Success => {
                    let prior_failures = consecutive_failures;
                    consecutive_failures = 0;
                    if !currently_serving {
                        tracing::info!(
                            recovered_after = prior_failures,
                            "backend recovered; flipping readiness back to SERVING"
                        );
                        health::set_serving(&mut reporter).await;
                        currently_serving = true;
                    }
                }
                BackendHealthEvent::Failure => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if currently_serving && consecutive_failures >= threshold {
                        tracing::warn!(
                            consecutive_failures,
                            threshold,
                            "backend exceeded failure threshold; flipping readiness to NOT_SERVING"
                        );
                        health::set_not_serving(&mut reporter).await;
                        currently_serving = false;
                    }
                }
            }
        }
        tracing::debug!("backend health-gate channel closed; task exiting");
    });
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
    // Parse early so --print-env-vars doesn't pull in JSON tracing.
    let args = Args::parse();
    if args.print_env_vars {
        print!("{}", config::env_var_help());
        return Ok(());
    }
    init_tracing();

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

    // Configure per-peer rate limiter for GetBackendInterfaces.
    // Disabled by default (max_per_window=0); production deployments
    // can set proxy.rate_limit_get_backend_interfaces to enable.
    server::rate_limit::configure(
        std::time::Duration::from_secs(config.proxy.rate_limit_window_secs),
        config.proxy.rate_limit_get_backend_interfaces,
    );

    let (svc, context_manager, registry_source) = build_service(&config, &backend).await?;

    // Loud one-time warning if TCP listener is running without auth
    // (the design's default for SaaS deployments behind external
    // network protection). Stays visible in operator log scans.
    if let Some(tcp) = config.listener.remote.as_ref()
        && matches!(tcp.auth, config::TcpAuthMode::None)
        && tcp.allow_insecure_tcp
    {
        tracing::warn!(
            bind = %tcp.bind,
            "listening on tcp without authentication; relying on external network \
             protection (k8s NetworkPolicy / VPC). do not use in untrusted networks."
        );
    }

    // Wire backend-health gating: spawn_backend reports each outcome
    // through an unbounded channel; this task counts consecutive
    // transport-level failures and flips tonic-health to NOT_SERVING
    // once `proxy.backend_health_consecutive_failures` is exceeded.
    let (health_tx, health_rx) = tokio::sync::mpsc::unbounded_channel();
    server::grpc_service::service_utils::configure_backend_health_events(health_tx);
    spawn_backend_health_gate(
        health_rx,
        health_reporter.clone(),
        config.proxy.backend_health_consecutive_failures,
    );

    // Install SIGHUP handler so operators can reload the mechanism
    // registry without restarting the daemon. Reload failure retains
    // the current registry and logs an error rather than crashing.
    #[cfg(unix)]
    spawn_sighup_handler(registry_source.clone());
    let addr = resolve_bind_address(&config)?;

    // Bind the TCP listener *before* flipping Health/SERVING. The
    // consumer matrix surfaced a race where shim consumers saw the daemon's gRPC
    // health probe report SERVING but their TCP connect was refused
    // because tonic hadn't yet bound the listener. Binding here makes
    // the SERVING flip below truthful: by the time external probes
    // can see it, accept() is already running.
    let tcp_listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = tcp_listener.local_addr().unwrap_or(addr);

    health::set_serving(&mut health_reporter).await;
    spawn_eviction_task(
        context_manager,
        backend.clone(),
        config.proxy.eviction_interval_secs,
        config.proxy.max_contexts,
        config.proxy.max_concurrent_backend_calls,
    );

    tracing::info!(addr = %local_addr,
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
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(tcp_listener);
    builder
        .layer(server::trace_id::TraceIdLayer)
        .add_service(health_service)
        .add_service(svc)
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
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
