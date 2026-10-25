//! jmon: an nmon-style performance monitor for FreeBSD that also emits
//! OpenTelemetry metrics (OTLP gRPC/HTTP), a Prometheus endpoint, and
//! nmon-compatible capture files.

mod config;
mod logring;
mod metrics;
mod model;
mod otel;
mod platform;
mod prom;
mod record;
mod sample;
mod tui;

use anyhow::{Context, Result, bail};
use clap::Parser;
use logring::LogRing;
use otel::{OtelConfig, OtlpProtocol};
use record::Format;
use sample::{Hub, Sample, Sink};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, after_help = AFTER_HELP, args_override_self = true)]
pub struct Cli {
    /// Read options from this TOML file [default: /usr/local/etc/jmon.conf if it exists]
    #[arg(long, env = "JMON_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Seconds between samples (like nmon -s)
    #[arg(short = 's', long, default_value_t = 2.0)]
    interval: f64,

    /// Stop after this many samples (like nmon -c)
    #[arg(short = 'c', long)]
    count: Option<u64>,

    /// Run headless: no screen, just collect and export (for rc.d services)
    #[arg(short = 'd', long)]
    daemon: bool,

    /// Panels to open at start, as screen keys, e.g. "cmdn"
    #[arg(long, env = "JMON", default_value = "")]
    show: String,

    /// Record to <host>_<YYMMDD>_<HHMM>.nmon and run headless (like nmon -f)
    #[arg(short = 'f', long)]
    auto_record: bool,

    /// Record samples to this file ("-" for stdout)
    #[arg(short = 'F', long, value_name = "PATH")]
    record: Option<String>,

    /// Format for recorded samples
    #[arg(long, value_enum, default_value_t = Format::Nmon)]
    record_format: Format,

    /// Directory for -f recordings
    #[arg(long, value_name = "DIR", default_value = ".")]
    record_dir: PathBuf,

    /// With -f, start a new file every day at midnight
    #[arg(long)]
    rotate: bool,

    /// With --rotate, compress finished daily files with gzip
    #[arg(long)]
    record_compress: bool,

    /// With --rotate, delete this host's recordings older than DAYS
    #[arg(long, value_name = "DAYS")]
    record_keep: Option<u64>,

    /// OTLP endpoint, e.g. http://collector:4317 (gRPC) or http://collector:4318 (HTTP).
    /// Without this, OTLP is enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set.
    #[arg(long, value_name = "URL")]
    otlp_endpoint: Option<String>,

    /// OTLP transport
    #[arg(long, value_enum, env = "OTEL_EXPORTER_OTLP_PROTOCOL", default_value = "grpc")]
    otlp_protocol: OtlpProtocol,

    /// Seconds between OTLP exports
    #[arg(long, default_value_t = 10.0, value_name = "SECS")]
    otlp_interval: f64,

    /// Extra CA certificate (PEM) to trust for an https:// OTLP endpoint
    #[arg(long, env = "OTEL_EXPORTER_OTLP_CERTIFICATE", value_name = "PATH")]
    otlp_ca: Option<PathBuf>,

    /// Serve Prometheus metrics at this address, e.g. 0.0.0.0:9464
    #[arg(long, value_name = "ADDR")]
    prometheus: Option<SocketAddr>,

    /// Define a disk group, NAME=disk1,disk2 (repeatable; like nmon -g)
    #[arg(long = "disk-group", value_name = "NAME=DISKS")]
    disk_groups: Vec<model::DiskGroup>,

    /// Also export per-process metrics for the N busiest processes
    #[arg(long, default_value_t = 0, value_name = "N")]
    export_top: usize,

    /// Print one sample as JSON and exit
    #[arg(long)]
    once: bool,

    /// Write log messages to this file
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    /// Write log messages to syslog (daemon facility)
    #[arg(long)]
    syslog: bool,
}

const AFTER_HELP: &str = "\
Examples:
  jmon                                     interactive screen
  jmon --show cmdnt                        screen with CPU, memory, disk, network, top open
  jmon -d --otlp-endpoint http://otel:4317 headless agent pushing OTLP/gRPC
  jmon -d --prometheus 0.0.0.0:9464        headless agent with a scrape endpoint
  jmon -f -s 60 --rotate --record-keep 30  daily .nmon files, kept for 30 days

Options can also be set in a TOML config file using the long option names,
e.g. otlp-endpoint = \"http://otel:4317\"; command-line options win.

Standard OTEL_* variables (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS,
OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME, ...) are honoured.";

fn main() -> Result<()> {
    let cli = Cli::parse_from(config::args()?);
    if [cli.interval, cli.otlp_interval].iter().any(|v| !v.is_finite() || *v <= 0.0) {
        bail!("intervals must be positive");
    }
    let headless = cli.daemon || cli.auto_record || cli.record.as_deref() == Some("-");
    let screen = !headless && !cli.once;

    let ring = LogRing::default();
    init_logging(screen, cli.syslog, cli.log_file.as_ref(), &ring)?;

    let collector = platform::Collector::new().context("initialising collector")?;
    let host = collector.host();

    if cli.once {
        return once(collector);
    }

    let interval = Duration::from_secs_f64(cli.interval);
    let hub = Hub::new(interval, cli.export_top);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("jmon-io")
        .enable_all()
        .build()?;

    let mut status = Vec::new();
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
    if cli.auto_record {
        let settings = record::RecordSettings {
            dir: cli.record_dir.clone(),
            format: cli.record_format,
            interval: cli.interval,
            count: cli.count,
            rotate: cli.rotate,
            compress: cli.record_compress,
            keep_days: cli.record_keep,
            groups: cli.disk_groups.clone(),
        };
        let rec = record::Recorder::new(settings, host.clone())?;
        info!("recording to {}", rec.path().display());
        status.push(format!("rec {}", cli.record_dir.display()));
        sinks.push(Box::new(rec));
    } else if let Some(path) = &cli.record {
        let out = record::open(path).with_context(|| format!("opening {path}"))?;
        sinks.push(match cli.record_format {
            Format::Nmon => Box::new(record::Nmon::new(out, cli.interval, cli.count, cli.disk_groups.clone())),
            Format::Jsonl => Box::new(record::JsonLines::new(out)),
        });
        info!("recording to {path}");
        status.push(format!("rec {path}"));
    }

    let provider = if cli.otlp_endpoint.is_some() || otel::env_configured() {
        let cfg = OtelConfig {
            endpoint: cli.otlp_endpoint.clone(),
            protocol: cli.otlp_protocol,
            interval: Duration::from_secs_f64(cli.otlp_interval),
            ca_file: cli.otlp_ca.clone(),
        };
        let p = otel::init(&cfg, hub.clone(), &host, &rt)?;
        let target = cli.otlp_endpoint.clone().unwrap_or_else(|| "$OTEL_EXPORTER_OTLP_ENDPOINT".into());
        info!("exporting OTLP ({:?}) to {target} every {}s", cli.otlp_protocol, cli.otlp_interval);
        status.push(format!("otlp {target}"));
        Some(p)
    } else {
        None
    };

    if let Some(addr) = cli.prometheus {
        let hub = hub.clone();
        rt.spawn(async move {
            if let Err(e) = prom::serve(addr, hub).await {
                warn!("prometheus endpoint {addr}: {e}");
            }
        });
        status.push(format!("prom {addr}"));
    }

    let sampler = sample::spawn(hub.clone(), collector, sinks, cli.count);

    if screen {
        // Signals stop the screen through the hub so it can restore the terminal.
        rt.spawn(wait_for_shutdown(hub.clone(), false));
        tui::run(
            hub.clone(),
            &cli.show,
            status,
            ring,
            cli.disk_groups.clone(),
            cli.record_dir.clone(),
            cli.record_format,
        )?;
    } else {
        info!("jmon {} running headless, interval {}s", env!("CARGO_PKG_VERSION"), cli.interval);
        rt.block_on(wait_for_shutdown(hub.clone(), true));
    }

    hub.request_stop();
    let _ = sampler.join();
    if let Some(p) = provider {
        // Final export so the last interval isn't lost.
        if let Err(e) = p.shutdown() {
            warn!("OTLP shutdown: {e}");
        }
    }
    rt.shutdown_timeout(Duration::from_secs(2));
    Ok(())
}

fn once(mut collector: platform::Collector) -> Result<()> {
    let host = collector.host();
    let first = collector.collect();
    std::thread::sleep(Duration::from_secs(1));
    let started = std::time::Instant::now();
    let snap = collector.collect();
    let mut s = Sample::derive(1, host, Some(&first), snap);
    s.collect_secs = started.elapsed().as_secs_f64();
    serde_json::to_writer_pretty(std::io::stdout().lock(), &s)?;
    println!();
    Ok(())
}

/// Reloads runtime-adjustable settings (interval, export-top) from the config file on SIGHUP.
#[cfg(unix)]
fn reload_config(hub: &Hub) {
    match config::args().and_then(|a| Cli::try_parse_from(a).map_err(Into::into)) {
        Ok(cli) if cli.interval.is_finite() && cli.interval > 0.0 => {
            hub.set_interval(Duration::from_secs_f64(cli.interval));
            hub.set_top_procs(cli.export_top);
            info!("SIGHUP: reloaded config (interval={}s, export-top={})", cli.interval, cli.export_top);
        }
        Ok(_) => warn!("SIGHUP: ignoring non-positive interval in config"),
        Err(e) => warn!("SIGHUP: config reload failed: {e:#}"),
    }
}

/// Waits for SIGINT, SIGTERM, SIGHUP, or the sampler finishing, then asks
/// everything to stop. Headless (`reload_on_hup`), SIGHUP instead reloads the
/// configuration file; with the screen up it means the terminal went away.
#[cfg_attr(not(unix), allow(unused_variables))]
async fn wait_for_shutdown(hub: Arc<Hub>, reload_on_hup: bool) {
    let stopped = {
        let hub = hub.clone();
        async move {
            while !hub.stopped() {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    };
    #[cfg(unix)]
    let signals = {
        let hub = hub.clone();
        async move {
            use tokio::signal::unix::{SignalKind, signal};
            match (signal(SignalKind::terminate()), signal(SignalKind::hangup())) {
                (Ok(mut term), Ok(mut hup)) => loop {
                    tokio::select! {
                        _ = term.recv() => break "SIGTERM",
                        _ = hup.recv() => {
                            if !reload_on_hup {
                                break "SIGHUP";
                            }
                            reload_config(&hub);
                        }
                    }
                },
                _ => std::future::pending().await,
            }
        }
    };
    #[cfg(not(unix))]
    let signals = std::future::pending::<&str>();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("interrupted, shutting down"),
        sig = signals => info!("{sig}, shutting down"),
        _ = stopped => info!("stopping"),
    }
    hub.request_stop();
}

fn init_logging(screen: bool, syslog: bool, file: Option<&PathBuf>, ring: &LogRing) -> Result<()> {
    let filter = EnvFilter::try_from_env("JMON_LOG").unwrap_or_else(|_| EnvFilter::new("warn,jmon=info"));
    if syslog {
        #[cfg(unix)]
        {
            use tracing_subscriber::prelude::*;
            tracing_subscriber::registry().with(filter).with(logring::Syslog::open()).init();
            return Ok(());
        }
        #[cfg(not(unix))]
        bail!("--syslog is only available on Unix");
    }
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if let Some(path) = file {
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        builder.with_ansi(false).with_writer(Mutex::new(f)).init();
    } else if screen {
        // Anything on stderr would corrupt the display; show it in the footer.
        builder.with_ansi(false).without_time().with_target(false).with_writer(ring.clone()).init();
    } else {
        // Under daemon(8) stderr goes to syslog, where colour codes are noise.
        let ansi = std::io::IsTerminal::is_terminal(&std::io::stderr());
        builder.with_ansi(ansi).with_writer(std::io::stderr).init();
    }
    Ok(())
}
