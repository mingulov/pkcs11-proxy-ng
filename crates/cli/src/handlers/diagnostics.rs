//! Passive daemon diagnostics (`diagnostics` subcommand).
//!
//! Health status plus the context-free `GetBackendInterfaces` report
//! (backend versions, NULL slots, ABI widths, registry revision).
//! Dispatched in `main` before the PKCS#11 client initializes, and
//! the collection path below never calls `initialize` — under
//! `max_contexts = 1` a diagnostics run must not consume the sole
//! admitted context (pinned by the `context_count` integration test).
//! Only allowlisted, non-secret fields are reported; unknown stays
//! explicit (`None` renders as "unknown"/null, never as zero).

use pkcs11_proxy_ng_client::tls::ClientTlsFiles;
use pkcs11_proxy_ng_client::{BackendProbe, Pkcs11Client};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;

/// How many NULL function names the text report lists per interface
/// before collapsing the rest into a count (JSON always keeps all).
const TEXT_NULL_LIST_CAP: usize = 12;

pub(crate) struct InterfaceReport {
    pub(crate) version: String,
    pub(crate) null_functions: Vec<String>,
}

pub(crate) struct DiagnosticReport {
    pub(crate) endpoint: String,
    pub(crate) service: String,
    pub(crate) health: String,
    pub(crate) discovery_ok: bool,
    pub(crate) interfaces: Vec<InterfaceReport>,
    pub(crate) backend_ulong_size: Option<u32>,
    pub(crate) backend_byte_order: Option<u32>,
    pub(crate) backend_attribute_stride: Option<u32>,
    pub(crate) registry_revision: Option<String>,
    pub(crate) registry_discovery_mode: Option<String>,
    pub(crate) effects_version: Option<u32>,
    pub(crate) transport_version: Option<u32>,
    pub(crate) pointer_safe_message_parameters: bool,
    pub(crate) pointer_safe_authenticated_parameters: bool,
}

impl DiagnosticReport {
    pub(crate) fn from_probe(
        endpoint: &str,
        service: &str,
        health: &str,
        probe: Option<&BackendProbe>,
    ) -> Self {
        let mut report = Self {
            endpoint: endpoint.to_string(),
            service: service.to_string(),
            health: health.to_string(),
            discovery_ok: probe.is_some(),
            interfaces: Vec::new(),
            backend_ulong_size: None,
            backend_byte_order: None,
            backend_attribute_stride: None,
            registry_revision: None,
            registry_discovery_mode: None,
            effects_version: None,
            transport_version: None,
            pointer_safe_message_parameters: false,
            pointer_safe_authenticated_parameters: false,
        };
        if let Some(probe) = probe {
            report.interfaces = probe
                .interfaces
                .iter()
                .map(|iface| InterfaceReport {
                    version: format!("{}.{}", iface.version_major, iface.version_minor),
                    null_functions: iface.null_functions.clone(),
                })
                .collect();
            report.backend_ulong_size = probe.backend_ulong_size;
            report.backend_byte_order = probe.backend_byte_order;
            report.backend_attribute_stride = probe.backend_attribute_stride;
            if let Some(registry) = probe.mechanism_registry.as_ref() {
                report.registry_revision = Some(registry.revision.clone());
                report.registry_discovery_mode = Some(registry.discovery_mode.clone());
            }
            report.effects_version = probe.exact_output_effects_version;
            report.transport_version = probe.mechanism_parameter_transport_version;
            report.pointer_safe_message_parameters = probe.pointer_safe_message_parameters;
            report.pointer_safe_authenticated_parameters =
                probe.pointer_safe_authenticated_parameters;
        }
        report
    }

    pub(crate) fn render_text(&self) -> String {
        let mut out =
            format!("endpoint: {}\nservice {}: {}\n", self.endpoint, self.service, self.health);
        if !self.discovery_ok {
            out.push_str("interfaces: unavailable (discovery failed)\n");
            return out;
        }
        out.push_str("interfaces:\n");
        for iface in &self.interfaces {
            if iface.null_functions.is_empty() {
                out.push_str(&format!("  {}\n", iface.version));
            } else if iface.null_functions.len() <= TEXT_NULL_LIST_CAP {
                out.push_str(&format!(
                    "  {} (null: {})\n",
                    iface.version,
                    iface.null_functions.join(", ")
                ));
            } else {
                out.push_str(&format!(
                    "  {} (null: {}, … (+{} more))\n",
                    iface.version,
                    iface.null_functions[..TEXT_NULL_LIST_CAP].join(", "),
                    iface.null_functions.len() - TEXT_NULL_LIST_CAP
                ));
            }
        }
        let ulong = self
            .backend_ulong_size
            .map_or_else(|| "unknown".to_string(), |size| format!("{size} bytes"));
        let stride = self
            .backend_attribute_stride
            .map_or_else(|| "unknown".to_string(), |stride| stride.to_string());
        out.push_str(&format!(
            "backend ulong: {ulong}, {}, attribute stride {stride}\n",
            byte_order_label(self.backend_byte_order)
        ));
        match (&self.registry_revision, &self.registry_discovery_mode) {
            (Some(revision), Some(mode)) => {
                out.push_str(&format!("mechanism registry: revision {revision} (mode: {mode})\n"));
            }
            _ => out.push_str("mechanism registry: unknown (legacy daemon)\n"),
        }
        out.push_str(&format!(
            "effects version: {}, transport version: {}\n",
            opt_u32(self.effects_version),
            opt_u32(self.transport_version)
        ));
        out.push_str(&format!(
            "pointer-safe parameters: message={} authenticated={}\n",
            self.pointer_safe_message_parameters, self.pointer_safe_authenticated_parameters
        ));
        out
    }

    pub(crate) fn render_json(&self) -> String {
        let interfaces: Vec<serde_json::Value> = self
            .interfaces
            .iter()
            .map(|iface| {
                serde_json::json!({
                    "version": iface.version,
                    "null_functions": iface.null_functions,
                })
            })
            .collect();
        let registry = match (&self.registry_revision, &self.registry_discovery_mode) {
            (Some(revision), Some(mode)) => {
                serde_json::json!({"revision": revision, "discovery_mode": mode})
            }
            _ => serde_json::Value::Null,
        };
        serde_json::json!({
            "endpoint": self.endpoint,
            "service": self.service,
            "health": self.health,
            "discovery_ok": self.discovery_ok,
            "interfaces": interfaces,
            "backend_ulong_size": self.backend_ulong_size,
            "backend_byte_order": self.backend_byte_order,
            "backend_attribute_stride": self.backend_attribute_stride,
            "mechanism_registry": registry,
            "exact_output_effects_version": self.effects_version,
            "mechanism_parameter_transport_version": self.transport_version,
            "pointer_safe_message_parameters": self.pointer_safe_message_parameters,
            "pointer_safe_authenticated_parameters": self.pointer_safe_authenticated_parameters,
        })
        .to_string()
    }
}

fn opt_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "unknown".to_string(), |v| v.to_string())
}

/// Human label for the ADR-0011 D6 byte-order advertisement (1 =
/// little, 2 = big). Anything else stays visibly unknown rather than
/// guessing an endianness.
pub(crate) fn byte_order_label(order: Option<u32>) -> String {
    match order {
        None => "unknown".to_string(),
        Some(1) => "little-endian".to_string(),
        Some(2) => "big-endian".to_string(),
        Some(other) => format!("unknown({other})"),
    }
}

pub(crate) fn status_label(status: ServingStatus) -> &'static str {
    match status {
        ServingStatus::Serving => "SERVING",
        ServingStatus::NotServing => "NOT_SERVING",
        ServingStatus::Unknown => "UNKNOWN",
        ServingStatus::ServiceUnknown => "SERVICE_UNKNOWN",
    }
}

struct ProbeFailure {
    message: String,
    code: i32,
}

/// Connect and check health, returning the shared channel for
/// discovery. Never initializes a PKCS#11 context.
async fn connect_and_check(
    endpoint: &str,
    tls_files: Option<ClientTlsFiles>,
    service: &str,
) -> Result<(ServingStatus, tonic::transport::Channel), ProbeFailure> {
    let fail = |message: String| ProbeFailure { message, code: 2 };
    let built = crate::build_health_endpoint(endpoint, tls_files)
        .map_err(|e| fail(format!("diagnostics setup failed: {e}")))?;
    let channel =
        built.connect().await.map_err(|e| fail(format!("diagnostics connection failed: {e}")))?;
    let mut health = HealthClient::new(channel.clone());
    let status = health
        .check(HealthCheckRequest { service: service.to_string() })
        .await
        .map(|response| response.into_inner())
        .map_err(|e| fail(format!("diagnostics health check failed: {e}")))?;
    let status = ServingStatus::try_from(status.status).unwrap_or(ServingStatus::Unknown);
    match status {
        ServingStatus::Serving | ServingStatus::NotServing => Ok((status, channel)),
        ServingStatus::Unknown | ServingStatus::ServiceUnknown => {
            Err(fail(format!("diagnostics indeterminate: {status:?}")))
        }
    }
}

/// Run the context-free discovery probe over an established channel.
/// Never initializes a PKCS#11 context.
async fn discover(channel: tonic::transport::Channel) -> Result<BackendProbe, ProbeFailure> {
    let mut client = Pkcs11Client::from_channel(channel);
    client.get_backend_interfaces().await.map_err(|e| ProbeFailure {
        message: format!("diagnostics discovery failed: {e}"),
        code: 2,
    })
}

/// Run the diagnostics probe and print the report; returns the
/// process exit code (0 SERVING, 1 NOT_SERVING, 2 probe failure).
/// The deadline covers connect plus health; discovery gets the
/// remainder. A confirmed NOT_SERVING verdict survives discovery
/// trouble (error or stall): the report prints with discovery
/// marked unavailable and the exit stays 1.
pub(crate) async fn run_diagnostics(
    endpoint: &str,
    tls_files: Option<ClientTlsFiles>,
    service: &str,
    format: &str,
    timeout_secs: u64,
) -> i32 {
    if format != "text" && format != "json" {
        eprintln!("diagnostics: --format must be 'text' or 'json', got {format:?}");
        return 2;
    }
    if timeout_secs == 0 {
        eprintln!("diagnostics: --timeout-secs must be positive");
        return 2;
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let (status, channel) =
        match tokio::time::timeout_at(deadline, connect_and_check(endpoint, tls_files, service))
            .await
        {
            Err(_) => {
                eprintln!("diagnostics timed out after {timeout_secs}s");
                return 2;
            }
            Ok(Err(failure)) => {
                eprintln!("{}", failure.message);
                return failure.code;
            }
            Ok(Ok(connected)) => connected,
        };
    // Discovery is best-effort evidence under NOT_SERVING, a gate
    // under SERVING — but either way it must not outlive the
    // deadline, and its timeout must not erase a health verdict.
    let probe = match tokio::time::timeout_at(deadline, discover(channel)).await {
        Ok(Ok(probe)) => Some(probe),
        Ok(Err(failure)) => {
            if status == ServingStatus::Serving {
                eprintln!("{}", failure.message);
                return failure.code;
            }
            None
        }
        Err(_) => {
            if status == ServingStatus::Serving {
                eprintln!("diagnostics discovery timed out after {timeout_secs}s");
                return 2;
            }
            None
        }
    };
    let report =
        DiagnosticReport::from_probe(endpoint, service, status_label(status), probe.as_ref());
    if format == "json" {
        println!("{}", report.render_json());
    } else {
        println!("{}", report.render_text());
    }
    crate::health_exit_code(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_fixture() -> BackendProbe {
        BackendProbe {
            exact_output_effects_version: Some(3),
            interfaces: vec![
                pkcs11_proxy_ng_client::BackendInterface {
                    version_major: 2,
                    version_minor: 40,
                    null_functions: vec!["C_X".to_string(), "C_Y".to_string()],
                },
                pkcs11_proxy_ng_client::BackendInterface {
                    version_major: 3,
                    version_minor: 2,
                    null_functions: Vec::new(),
                },
            ],
            mechanism_registry: None,
            backend_ulong_size: Some(8),
            backend_byte_order: Some(1),
            backend_attribute_stride: Some(32),
            pointer_safe_message_parameters: true,
            pointer_safe_authenticated_parameters: false,
            mechanism_parameter_transport_version: Some(2),
        }
    }

    #[test]
    fn report_maps_probe_fields() {
        let probe = probe_fixture();
        let report = DiagnosticReport::from_probe("http://x", "svc", "SERVING", Some(&probe));
        assert!(report.discovery_ok);
        assert_eq!(report.interfaces.len(), 2);
        assert_eq!(report.interfaces[0].version, "2.40");
        assert_eq!(report.interfaces[0].null_functions, vec!["C_X", "C_Y"]);
        assert_eq!(report.backend_ulong_size, Some(8));
        assert_eq!(report.effects_version, Some(3));
        assert!(report.registry_revision.is_none());
        assert!(report.pointer_safe_message_parameters);
        assert!(!report.pointer_safe_authenticated_parameters);
    }

    #[test]
    fn missing_probe_renders_unavailable() {
        let report = DiagnosticReport::from_probe("http://x", "svc", "NOT_SERVING", None);
        assert!(!report.discovery_ok);
        let text = report.render_text();
        assert!(text.contains("NOT_SERVING"), "{text}");
        assert!(text.contains("unavailable (discovery failed)"), "{text}");
        let json: serde_json::Value = serde_json::from_str(&report.render_json()).unwrap();
        assert_eq!(json["discovery_ok"], false);
        assert_eq!(json["interfaces"], serde_json::json!([]));
    }

    #[test]
    fn text_render_covers_full_probe() {
        let probe = probe_fixture();
        let report = DiagnosticReport::from_probe("http://x", "svc", "SERVING", Some(&probe));
        let text = report.render_text();
        for needle in [
            "endpoint: http://x",
            "service svc: SERVING",
            "2.40 (null: C_X, C_Y)",
            "3.2\n",
            "8 bytes, little-endian, attribute stride 32",
            "mechanism registry: unknown (legacy daemon)",
            "effects version: 3, transport version: 2",
            "message=true authenticated=false",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
    }

    #[test]
    fn text_render_collapses_long_null_lists() {
        let mut probe = probe_fixture();
        probe.interfaces[0].null_functions = (0..20).map(|n| format!("C_F{n:02}")).collect();
        let report = DiagnosticReport::from_probe("http://x", "svc", "SERVING", Some(&probe));
        let text = report.render_text();
        assert!(text.contains("(+8 more)"), "{text}");
        assert!(!text.contains("C_F19"), "{text}");
        let json: serde_json::Value = serde_json::from_str(&report.render_json()).unwrap();
        assert_eq!(json["interfaces"][0]["null_functions"].as_array().unwrap().len(), 20);
    }

    #[test]
    fn json_render_keeps_raw_numbers_and_nulls() {
        let mut probe = probe_fixture();
        probe.backend_byte_order = Some(7);
        probe.backend_attribute_stride = None;
        let report = DiagnosticReport::from_probe("http://x", "svc", "SERVING", Some(&probe));
        let json: serde_json::Value = serde_json::from_str(&report.render_json()).unwrap();
        assert_eq!(json["endpoint"], "http://x");
        assert_eq!(json["health"], "SERVING");
        assert_eq!(json["backend_ulong_size"], 8);
        assert_eq!(json["backend_byte_order"], 7);
        assert_eq!(json["backend_attribute_stride"], serde_json::Value::Null);
        assert_eq!(json["mechanism_registry"], serde_json::Value::Null);
        // Text labels the odd byte order instead of guessing.
        assert!(report.render_text().contains("unknown(7)"));
    }

    #[test]
    fn byte_order_labels_pin_all_cases() {
        assert_eq!(byte_order_label(None), "unknown");
        assert_eq!(byte_order_label(Some(1)), "little-endian");
        assert_eq!(byte_order_label(Some(2)), "big-endian");
        assert_eq!(byte_order_label(Some(9)), "unknown(9)");
    }

    #[test]
    fn status_labels_pin_all_statuses() {
        assert_eq!(status_label(ServingStatus::Serving), "SERVING");
        assert_eq!(status_label(ServingStatus::NotServing), "NOT_SERVING");
        assert_eq!(status_label(ServingStatus::Unknown), "UNKNOWN");
        assert_eq!(status_label(ServingStatus::ServiceUnknown), "SERVICE_UNKNOWN");
    }
}
