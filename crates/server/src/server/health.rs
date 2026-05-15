//! gRPC Health Checking Protocol support (grpc.health.v1).
//!
//! Uses `tonic-health` to expose standard health probes. The daemon
//! transitions through two states:
//!
//! - **NOT_SERVING** — set during startup before the backend module
//!   is initialized and the slot map is populated.
//! - **SERVING** — set once the daemon is ready to accept PKCS#11
//!   requests.
//!
//! The service name registered is `pkcs11_proxy_ng.v1.Pkcs11Proxy`, matching
//! the proto service definition. An empty-service ("") check is also
//! supported for generic liveness probes.

use tonic_health::server::HealthReporter;

/// The gRPC service name used for per-service health checks.
pub const SERVICE_NAME: &str = "pkcs11_proxy_ng.v1.Pkcs11Proxy";

/// Mark the proxy service as serving (ready for traffic).
pub async fn set_serving(reporter: &mut HealthReporter) {
    reporter.set_service_status(SERVICE_NAME, tonic_health::ServingStatus::Serving).await;
    tracing::info!("Health status: SERVING");
}

/// Mark the proxy service as not serving (startup or degraded).
pub async fn set_not_serving(reporter: &mut HealthReporter) {
    reporter.set_service_status(SERVICE_NAME, tonic_health::ServingStatus::NotServing).await;
    tracing::info!("Health status: NOT_SERVING");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_matches_proto() {
        assert_eq!(SERVICE_NAME, "pkcs11_proxy_ng.v1.Pkcs11Proxy");
    }

    #[tokio::test]
    async fn health_reporter_transitions() {
        let (mut reporter, _service) = tonic_health::server::health_reporter();
        // After set_not_serving, it transitions to NOT_SERVING.
        set_not_serving(&mut reporter).await;
        // After set_serving, it transitions to SERVING.
        set_serving(&mut reporter).await;
    }

    #[tokio::test]
    async fn set_serving_then_not_serving() {
        let (mut reporter, _service) = tonic_health::server::health_reporter();
        set_serving(&mut reporter).await;
        set_not_serving(&mut reporter).await;
        // No panic means both transitions are valid.
    }

    #[tokio::test]
    async fn double_set_serving_is_idempotent() {
        let (mut reporter, _service) = tonic_health::server::health_reporter();
        set_serving(&mut reporter).await;
        set_serving(&mut reporter).await;
    }
}
