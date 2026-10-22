//! Minimal Prometheus text-format endpoint rendered from the metric catalog.

use crate::metrics::{CATALOG, Kind, Val};
use crate::sample::{Hub, Sample};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

/// Prometheus naming: dots to underscores, unit suffix, `_total` for counters.
pub fn prom_name(name: &str, unit: &str, kind: Kind) -> String {
    let mut n = name.replace(['.', '-'], "_");
    let suffix = match unit {
        "s" => "_seconds",
        "By" => "_bytes",
        "Cel" => "_celsius",
        "Hz" => "_hertz",
        "1" if kind == Kind::Gauge => "_ratio",
        _ => "",
    };
    if !n.ends_with(suffix) {
        n.push_str(suffix);
    }
    if kind == Kind::Counter {
        n.push_str("_total");
    }
    n
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

pub fn render(s: &Sample, hub: &Hub) -> String {
    let fams = s.families(hub);
    let mut out = String::with_capacity(16 * 1024);
    for (d, points) in CATALOG.iter().zip(fams.iter()) {
        if points.is_empty() {
            continue;
        }
        let name = prom_name(d.name, d.unit, d.kind);
        let ty = if d.kind == Kind::Counter { "counter" } else { "gauge" };
        let _ = writeln!(out, "# HELP {name} {}", d.help);
        let _ = writeln!(out, "# TYPE {name} {ty}");
        for p in points {
            out.push_str(&name);
            if !p.attrs.is_empty() {
                out.push('{');
                for (i, (k, v)) in p.attrs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let v = match v {
                        Val::Str(s) => escape(s),
                        Val::Int(i) => i.to_string(),
                    };
                    let _ = write!(out, "{}=\"{v}\"", k.replace('.', "_"));
                }
                out.push('}');
            }
            let _ = writeln!(out, " {}", p.value);
        }
    }
    out
}

pub async fn serve(addr: SocketAddr, hub: Arc<Hub>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("serving Prometheus metrics on http://{addr}/metrics");
    loop {
        let (mut sock, peer) = listener.accept().await?;
        let hub = hub.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut n = 0;
            // Read just the request head; bodies aren't expected.
            while n < buf.len() {
                match sock.read(&mut buf[n..]).await {
                    Ok(0) => break,
                    Ok(k) => n += k,
                    Err(e) => {
                        debug!("prometheus {peer}: {e}");
                        return;
                    }
                }
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf[..n]);
            let path = head.split_whitespace().nth(1).unwrap_or("/");
            let (status, ctype, body) = match path.split('?').next().unwrap_or("/") {
                "/metrics" => match hub.latest() {
                    Some(s) => {
                        hub.stats.scrapes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        ("200 OK", "text/plain; version=0.0.4; charset=utf-8", render(&s, &hub))
                    }
                    None => ("503 Service Unavailable", "text/plain", "no sample yet\n".into()),
                },
                "/" => (
                    "200 OK",
                    "text/html",
                    "<html><body><h1>jmon</h1><a href=\"/metrics\">metrics</a></body></html>\n".into(),
                ),
                _ => ("404 Not Found", "text/plain", "not found\n".into()),
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(e) = sock.write_all(resp.as_bytes()).await {
                warn!("prometheus {peer}: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(prom_name("system.cpu.time", "s", Kind::Counter), "system_cpu_time_seconds_total");
        assert_eq!(prom_name("system.memory.usage", "By", Kind::UpDown), "system_memory_usage_bytes");
        assert_eq!(prom_name("system.cpu.utilization", "1", Kind::Gauge), "system_cpu_utilization_ratio");
        assert_eq!(prom_name("system.disk.io_time", "s", Kind::Counter), "system_disk_io_time_seconds_total");
        assert_eq!(prom_name("freebsd.kernel.syscalls", "{call}", Kind::Counter), "freebsd_kernel_syscalls_total");
    }
}
