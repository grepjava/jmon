//! OTLP push export. Every catalog entry becomes an observable instrument
//! whose callback reads the latest sample, so the SDK's periodic reader
//! decides when to export and jmon never blocks on the network.

use crate::metrics::{CATALOG, Kind, Val};
use crate::model::HostInfo;
use crate::sample::Hub;
use anyhow::{Context, Result};
use clap::ValueEnum;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{AsyncInstrument, MeterProvider as _};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OtlpProtocol {
    #[value(name = "grpc")]
    Grpc,
    #[value(name = "http/protobuf")]
    HttpProtobuf,
    #[value(name = "http/json")]
    HttpJson,
}

pub struct OtelConfig {
    /// Explicit endpoint; None defers to OTEL_EXPORTER_OTLP_* variables.
    pub endpoint: Option<String>,
    pub protocol: OtlpProtocol,
    pub interval: Duration,
    /// PEM file of extra CA certificates to trust (self-signed collectors).
    pub ca_file: Option<PathBuf>,
}

/// True when the standard environment variables configure an endpoint.
pub fn env_configured() -> bool {
    ["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]
        .iter()
        .any(|v| std::env::var(v).is_ok_and(|s| !s.is_empty()))
}

/// HTTP endpoints set in code are used verbatim, so add the signal path
/// when the user gave only a base URL, matching OTEL_EXPORTER_OTLP_ENDPOINT.
fn http_metrics_url(endpoint: &str) -> String {
    let e = endpoint.trim_end_matches('/');
    let after_scheme = e.split_once("://").map_or(e, |(_, rest)| rest);
    if after_scheme.contains('/') { e.to_string() } else { format!("{e}/v1/metrics") }
}

pub fn resource(host: &HostInfo) -> Resource {
    // Resource::builder() also applies OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME.
    Resource::builder()
        .with_service_name("jmon")
        .with_attributes([
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("host.name", host.hostname.clone()),
            KeyValue::new("host.arch", host.machine.clone()),
            KeyValue::new("os.type", host.os_type.clone()),
            KeyValue::new("os.version", host.os_release.clone()),
        ])
        .build()
}

const TIMEOUT: Duration = Duration::from_secs(10);

pub fn init(cfg: &OtelConfig, hub: Arc<Hub>, host: &HostInfo, rt: &tokio::runtime::Runtime) -> Result<SdkMeterProvider> {
    let ca = match &cfg.ca_file {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("reading CA file {}", p.display()))?),
        None => None,
    };
    #[cfg(not(feature = "tls"))]
    if ca.is_some() {
        anyhow::bail!("--otlp-ca needs a build with the `tls` feature");
    }
    let exporter = match cfg.protocol {
        // tonic spawns its connection tasks on the ambient runtime, which must
        // outlive the provider.
        OtlpProtocol::Grpc => rt.block_on(async {
            let mut b = MetricExporter::builder().with_tonic().with_timeout(TIMEOUT);
            if let Some(e) = &cfg.endpoint {
                b = b.with_endpoint(e.clone());
            }
            #[cfg(feature = "tls")]
            {
                use opentelemetry_otlp::WithTonicConfig;
                use opentelemetry_otlp::tonic_types::transport::{Certificate, ClientTlsConfig};
                // Without --otlp-endpoint the exporter falls back to the standard variables.
                let endpoint = cfg.endpoint.clone().or_else(|| {
                    ["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"]
                        .iter()
                        .find_map(|k| std::env::var(k).ok())
                });
                let is_https = endpoint.is_some_and(|u| u.starts_with("https://"));
                if let Some(pem) = &ca {
                    let tls = ClientTlsConfig::new().with_native_roots().ca_certificate(Certificate::from_pem(pem));
                    b = b.with_tls_config(tls);
                } else if is_https {
                    b = b.with_tls_config(ClientTlsConfig::new().with_native_roots());
                }
            }
            b.build()
        }),
        // The reqwest blocking client must not be built inside a runtime.
        OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => {
            let proto = if cfg.protocol == OtlpProtocol::HttpJson { Protocol::HttpJson } else { Protocol::HttpBinary };
            let mut b = MetricExporter::builder().with_http().with_protocol(proto).with_timeout(TIMEOUT);
            if let Some(e) = &cfg.endpoint {
                b = b.with_endpoint(http_metrics_url(e));
            }
            #[cfg(feature = "tls")]
            if let Some(pem) = &ca {
                use opentelemetry_otlp::WithHttpConfig;
                let cert = reqwest::Certificate::from_pem(pem).context("parsing CA certificate")?;
                let client = reqwest::blocking::Client::builder()
                    .add_root_certificate(cert)
                    .timeout(TIMEOUT)
                    .build()
                    .context("building HTTP client")?;
                b = b.with_http_client(client);
            }
            b.build()
        }
    }
    .context("building OTLP metric exporter")?;

    let exporter = Counting { inner: exporter, hub: hub.clone() };
    let reader = PeriodicReader::builder(exporter).with_interval(cfg.interval).build();
    let provider = SdkMeterProvider::builder().with_resource(resource(host)).with_reader(reader).build();
    register(&provider, hub);
    Ok(provider)
}

/// Counts export outcomes for jmon's self-monitoring metrics.
struct Counting<E> {
    inner: E,
    hub: Arc<Hub>,
}

impl<E: PushMetricExporter> PushMetricExporter for Counting<E> {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let r = self.inner.export(metrics).await;
        let counter = if r.is_ok() { &self.hub.stats.export_ok } else { &self.hub.stats.export_failed };
        counter.fetch_add(1, Ordering::Relaxed);
        r
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn temporality(&self) -> Temporality {
        self.inner.temporality()
    }
}

fn to_kv(attrs: &[(&'static str, Val)]) -> Vec<KeyValue> {
    attrs
        .iter()
        .map(|(k, v)| match v {
            Val::Str(s) => KeyValue::new(*k, s.clone()),
            Val::Int(i) => KeyValue::new(*k, *i),
        })
        .collect()
}

fn observe(hub: &Hub, idx: usize, obs: &dyn AsyncInstrument<f64>) {
    if let Some(s) = hub.latest() {
        for p in &s.families(hub)[idx] {
            obs.observe(p.value, &to_kv(&p.attrs));
        }
    }
}

fn register(provider: &SdkMeterProvider, hub: Arc<Hub>) {
    let meter = provider.meter("jmon");
    for (idx, d) in CATALOG.iter().enumerate() {
        let hub = hub.clone();
        // Callbacks stay registered with the meter after the handle is dropped.
        match d.kind {
            Kind::Counter => {
                meter
                    .f64_observable_counter(d.name)
                    .with_unit(d.unit)
                    .with_description(d.help)
                    .with_callback(move |o| observe(&hub, idx, o))
                    .build();
            }
            Kind::UpDown => {
                meter
                    .f64_observable_up_down_counter(d.name)
                    .with_unit(d.unit)
                    .with_description(d.help)
                    .with_callback(move |o| observe(&hub, idx, o))
                    .build();
            }
            Kind::Gauge => {
                meter
                    .f64_observable_gauge(d.name)
                    .with_unit(d.unit)
                    .with_description(d.help)
                    .with_callback(move |o| observe(&hub, idx, o))
                    .build();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::http_metrics_url;

    #[test]
    fn appends_signal_path_only_to_base_urls() {
        assert_eq!(http_metrics_url("http://c:4318"), "http://c:4318/v1/metrics");
        assert_eq!(http_metrics_url("http://c:4318/"), "http://c:4318/v1/metrics");
        assert_eq!(http_metrics_url("http://c:4318/custom/path"), "http://c:4318/custom/path");
    }
}
