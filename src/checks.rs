//! The checks behind the Checks panel and incident capture: each statistic
//! with an ok, warning or danger verdict, like nmon's verbose mode.

use crate::model::Availability;
use crate::sample::Sample;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warning,
    Danger,
}

/// Yellow within 30 °C and red within 15 °C of the throttle point (or 65 and
/// 80 °C when the CPU doesn't say), as the Sensors panel colours them.
pub fn temp_level(c: f64, tjmax: Option<f64>) -> Level {
    let (danger, warn) = match tjmax {
        Some(tj) => (tj - 15.0, tj - 30.0),
        None => (80.0, 65.0),
    };
    if c >= danger {
        Level::Danger
    } else if c >= warn {
        Level::Warning
    } else {
        Level::Ok
    }
}

/// Every check for a sample, problems first; `None` before rates exist.
pub fn evaluate(s: &Sample) -> Option<Vec<(Level, String)>> {
    let r = s.rates.as_ref()?;
    let snap = &s.snap;
    let level = |v: f64, warn: f64, danger: f64| {
        if v >= danger {
            Level::Danger
        } else if v >= warn {
            Level::Warning
        } else {
            Level::Ok
        }
    };
    let mut out: Vec<(Level, String)> = Vec::new();
    let busy = 1.0 - r.cpu_total.idle;
    out.push((level(busy, 0.8, 0.95), format!("CPU busy {:.0}% (warn 80, danger 95)", busy * 100.0)));
    let ncpu = s.host.ncpu.max(1) as f64;
    if snap.usable("runq") {
        let rq = snap.runq.runnable as f64;
        out.push((level(rq / ncpu, 1.0, 2.0), format!("Run queue {} for {} CPUs (warn > 1x, danger > 2x)", rq, ncpu)));
    }
    let m = &snap.memory;
    if m.total > 0 {
        let avail = (m.free + m.inactive) as f64 / m.total as f64;
        out.push((level(1.0 - avail, 0.9, 0.95), format!("Memory available {:.1}% (free + inactive; warn < 10, danger < 5)", avail * 100.0)));
    }
    let (st, su): (u64, u64) = snap.swap.iter().fold((0, 0), |a, d| (a.0 + d.total, a.1 + d.used));
    if st > 0 {
        let used = su as f64 / st as f64;
        out.push((level(used, 0.2, 0.5), format!("Swap used {:.1}% (warn 20, danger 50)", used * 100.0)));
    }
    if r.vm.swap_pages_out > 0.0 {
        out.push((Level::Warning, format!("Swapping out {:.0} pages/s", r.vm.swap_pages_out)));
    }
    for (d, dr) in snap.disks.iter().zip(&r.disks) {
        out.push((level(dr.busy, 0.7, 0.9), format!("Disk {} busy {:.0}% (warn 70, danger 90)", d.name, dr.busy * 100.0)));
        let lat = dr.read_ms.max(dr.write_ms);
        if lat > 0.0 {
            out.push((level(lat, 20.0, 50.0), format!("Disk {} latency {:.1} ms (warn 20, danger 50)", d.name, lat)));
        }
    }
    for f in &snap.filesystems {
        let total = (f.used() + f.avail).max(1) as f64;
        let used = f.used() as f64 / total;
        out.push((level(used, 0.85, 0.95), format!("Filesystem {} {:.0}% full (warn 85, danger 95)", f.mountpoint, used * 100.0)));
    }
    for (n, nr) in snap.nets.iter().zip(&r.nets) {
        if nr.errors_ps > 0.0 || nr.drops_ps > 0.0 {
            out.push((Level::Warning, format!("Interface {}: {:.1} errors/s, {:.1} drops/s", n.name, nr.errors_ps, nr.drops_ps)));
        }
    }
    if let Some(t) = r.tcp
        && t.segs_sent >= 10.0
    {
        let pct = t.retransmits / t.segs_sent;
        out.push((level(pct, 0.01, 0.05), format!("TCP retransmits {:.2}% of segments sent (warn 1, danger 5)", pct * 100.0)));
        if t.listen_drops > 0.0 {
            out.push((Level::Warning, format!("TCP listen-queue overflows {:.1}/s", t.listen_drops)));
        }
    }
    let sn = &snap.sensors;
    if let Some(hot) = sn.cpu_temps.iter().copied().reduce(f64::max) {
        let lv = temp_level(hot, sn.cpu_tjmax);
        out.push((lv, format!("CPU temperature {hot:.0} °C")));
    }
    if let Some(b) = &sn.battery
        && !b.ac_online
    {
        out.push((level(1.0 - b.life / 100.0, 0.8, 0.9), format!("Battery {:.0}% and discharging", b.life)));
    }
    if let Some(z) = &snap.zfs {
        for p in &z.pools {
            let lv = if p.health == "ONLINE" { Level::Ok } else { Level::Danger };
            out.push((lv, format!("ZFS pool {} {}", p.name, p.health)));
            if p.size > 0 {
                let cap = p.allocated as f64 / p.size as f64;
                out.push((level(cap, 0.8, 0.9), format!("ZFS pool {} {:.0}% allocated (warn 80, danger 90)", p.name, cap * 100.0)));
            }
            let Some(st) = &p.status else { continue };
            if st.data_errors > 0 {
                out.push((Level::Danger, format!("ZFS pool {} has {} permanent data errors", p.name, st.data_errors)));
            }
            for v in &st.vdevs {
                if !v.healthy() {
                    out.push((Level::Danger, format!("ZFS device {} ({}) {}", v.name, p.name, v.state)));
                } else if v.errors() > 0 {
                    out.push((
                        Level::Warning,
                        format!(
                            "ZFS device {} ({}): {} read, {} write, {} checksum errors",
                            v.name, p.name, v.read_errors, v.write_errors, v.checksum_errors
                        ),
                    ));
                }
            }
            // Leaf devices only: a mirror's or raidz's line averages its disks.
            for io in p.iostat.iter().flatten() {
                if !st.vdevs.iter().any(|v| v.name == io.name && v.slow_ios.is_some()) || io.read_ops + io.write_ops < 1.0 {
                    continue;
                }
                let (total, disk) = if io.read_wait.unwrap_or(0.0) >= io.write_wait.unwrap_or(0.0) {
                    (io.read_wait.unwrap_or(0.0), io.read_disk_wait.unwrap_or(0.0))
                } else {
                    (io.write_wait.unwrap_or(0.0), io.write_disk_wait.unwrap_or(0.0))
                };
                let (total, disk) = (total * 1000.0, disk * 1000.0);
                out.push((
                    level(total, 20.0, 50.0),
                    format!(
                        "ZFS device {} ({}) wait {:.1} ms: {:.1} on the device, {:.1} queued (warn 20, danger 50)",
                        io.name,
                        p.name,
                        total,
                        disk,
                        (total - disk).max(0.0)
                    ),
                ));
            }
            if let Some(sc) = &st.scan {
                if sc.state == "scanning" && sc.function == "resilver" {
                    out.push((Level::Warning, format!("ZFS pool {} resilvering, {:.1}% done", p.name, sc.progress() * 100.0)));
                } else if sc.errors > 0 {
                    out.push((Level::Warning, format!("ZFS pool {} {} found {} errors", p.name, sc.function, sc.errors)));
                }
            }
        }
    }
    for j in &snap.jails {
        for rule in &j.rules {
            if let Some(used) = rule.used(j) {
                out.push((
                    level(used, 0.8, 0.95),
                    format!("Jail {} {} {:.0}% of its {} limit (warn 80, danger 95)", j.name, rule.resource, used * 100.0, rule.action),
                ));
            }
        }
    }
    for l in &snap.limits {
        let used = l.used as f64 / l.limit.max(1) as f64;
        out.push((
            level(used, 0.8, 0.95),
            format!("Kernel {} {:.0}% of {} (warn 80, danger 95)", l.name, used * 100.0, l.sysctl),
        ));
    }
    for (z, zr) in snap.zones.iter().zip(&r.zones) {
        if z.limit == 0 || z.routinely_full() {
            continue;
        }
        let used = z.used as f64 / z.limit as f64;
        if zr.fails > 0.0 || zr.sleeps > 0.0 {
            out.push((
                Level::Danger,
                format!(
                    "Kernel zone {} at {:.0}% of its limit: {:.1} failed and {:.1} waiting allocations/s",
                    z.name,
                    used * 100.0,
                    zr.fails,
                    zr.sleeps
                ),
            ));
        } else if used >= 0.5 {
            out.push((level(used, 0.8, 0.95), format!("Kernel zone {} {:.0}% of its limit (warn 80, danger 95)", z.name, used * 100.0)));
        }
    }
    if let Some(n) = &r.nfs
        && (n.client_retries > 0.0 || n.client_timeouts > 0.0)
    {
        out.push((Level::Warning, format!("NFS client: {:.1} retries/s, {:.1} timeouts/s", n.client_retries, n.client_timeouts)));
    }
    for c in &snap.collectors {
        let what = match c.state {
            Availability::Denied => "permission denied",
            Availability::Failed => "failed",
            Availability::Stale => "stale",
            _ => continue,
        };
        let detail = c.detail.as_deref().map(|d| format!(": {d}")).unwrap_or_default();
        out.push((Level::Warning, format!("Collector {} {what}{detail}", c.name)));
    }
    out.sort_by_key(|(lv, _)| std::cmp::Reverse(*lv));
    Some(out)
}
