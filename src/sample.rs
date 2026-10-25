//! Turns consecutive snapshots into rates, and shares the latest result
//! between the sampler thread, the screen and the exporters.

use crate::metrics::{self, Families};
use crate::model::*;
use crate::platform::Collector;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::warn;

/// CPU time split as fractions of the interval (0.0..=1.0).
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CpuUtil {
    pub user: f64,
    pub nice: f64,
    pub system: f64,
    pub interrupt: f64,
    pub idle: f64,
}

impl CpuUtil {
    fn from_delta(d: &CpuTicks) -> CpuUtil {
        let t = d.total() as f64;
        if t == 0.0 {
            return CpuUtil { idle: 1.0, ..Default::default() };
        }
        CpuUtil {
            user: d.user as f64 / t,
            nice: d.nice as f64 / t,
            system: d.system as f64 / t,
            interrupt: d.interrupt as f64 / t,
            idle: d.idle as f64 / t,
        }
    }

    pub fn modes(&self) -> [(&'static str, f64); 5] {
        [
            ("user", self.user),
            ("nice", self.nice),
            ("system", self.system),
            ("interrupt", self.interrupt),
            ("idle", self.idle),
        ]
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct DiskRate {
    pub read_bps: f64,
    pub write_bps: f64,
    pub read_iops: f64,
    pub write_iops: f64,
    /// Fraction of the interval the device had I/O outstanding.
    pub busy: f64,
    /// Average milliseconds per completed read / write over the interval.
    pub read_ms: f64,
    pub write_ms: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct NetRate {
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub errors_ps: f64,
    pub drops_ps: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct VmRates {
    pub context_switches: f64,
    pub interrupts: f64,
    pub syscalls: f64,
    pub traps: f64,
    pub forks: f64,
    pub faults: f64,
    pub swap_pages_in: f64,
    pub swap_pages_out: f64,
    pub swap_ins: f64,
    pub swap_outs: f64,
    pub vnode_ins: f64,
    pub vnode_outs: f64,
    pub vnode_pages_in: f64,
    pub vnode_pages_out: f64,
    pub zero_fill_faults: f64,
    pub cow_faults: f64,
    pub intransit_faults: f64,
    pub reactivated: f64,
    pub pages_freed: f64,
    pub pageout_wakeups: f64,
    pub pageout_scanned: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SuperpageRates {
    pub mappings: f64,
    pub promotions: f64,
    pub demotions: f64,
    pub failures: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NfsRates {
    /// Per operation, busiest first.
    pub client_ops: Vec<(String, f64)>,
    pub client_total: f64,
    pub client_retries: f64,
    pub client_timeouts: f64,
    pub server_ops: Vec<(String, f64)>,
    pub server_total: f64,
}

/// Per-second rates over the last interval. Vectors are index-aligned with
/// the corresponding vectors in the current snapshot.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Rates {
    pub interval: f64,
    pub cpu_total: CpuUtil,
    pub cpus: Vec<CpuUtil>,
    pub disks: Vec<DiskRate>,
    /// Aligned with `snap.partitions`.
    pub partitions: Vec<DiskRate>,
    pub nets: Vec<NetRate>,
    pub vm: VmRates,
    pub superpages: Option<SuperpageRates>,
    pub nfs: Option<NfsRates>,
    /// Percent of one CPU, like top(1); can exceed 100 for threaded processes.
    pub proc_cpu: Vec<f64>,
    /// User-mode CPU percent per process.
    pub proc_user_cpu: Vec<f64>,
    /// System-mode CPU percent per process.
    pub proc_sys_cpu: Vec<f64>,
    /// Block I/O operations per second (reads + writes), aligned with processes.
    pub proc_io: Vec<f64>,
    /// (minor, major) page faults per second, aligned with processes.
    pub proc_faults: Vec<(f64, f64)>,
    /// Per-jail totals; jid 0 (the host) is not included.
    pub jails: Vec<GroupRate>,
    /// bhyve virtual machines, found by their `bhyve: <name>` process titles.
    pub vms: Vec<GroupRate>,
    pub tcp: Option<TcpRates>,
    pub udp: Option<UdpRates>,
    pub zfs: Option<ZfsRates>,
}

/// Resource use summed over a group of processes (a jail or a VM).
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupRate {
    pub id: i64,
    pub name: String,
    pub processes: usize,
    /// Percent of one CPU.
    pub cpu: f64,
    pub rss: u64,
    pub io: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct TcpRates {
    pub segs_sent: f64,
    pub segs_received: f64,
    pub retransmits: f64,
    pub listen_drops: f64,
    pub accepts: f64,
    pub conn_attempts: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct UdpRates {
    pub datagrams_in: f64,
    pub datagrams_out: f64,
    pub in_errors: f64,
    pub no_ports: f64,
    pub full_socket_buffers: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ZfsRates {
    /// ARC hit ratio over the interval, if there were any lookups.
    pub arc_hit_ratio: Option<f64>,
    pub arc_lookups: f64,
    /// Aligned with `snap.zfs.pools`.
    pub pools: Vec<PoolRate>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct PoolRate {
    pub read_bps: f64,
    pub write_bps: f64,
    pub read_iops: f64,
    pub write_iops: f64,
}

#[derive(Debug, Serialize)]
pub struct Sample {
    pub seq: u64,
    pub host: Arc<HostInfo>,
    pub snap: Snapshot,
    pub rates: Option<Rates>,
    /// Seconds the collector took to produce this snapshot.
    pub collect_secs: f64,
    #[serde(skip)]
    families: OnceLock<Arc<Families>>,
}

fn per_sec(cur: u64, prev: u64, secs: f64) -> f64 {
    cur.saturating_sub(prev) as f64 / secs
}

impl Sample {
    pub fn derive(seq: u64, host: Arc<HostInfo>, prev: Option<&Snapshot>, snap: Snapshot) -> Sample {
        let rates = prev.and_then(|p| rates(p, &snap));
        Sample { seq, host, snap, rates, collect_secs: 0.0, families: OnceLock::new() }
    }

    /// Metric families for exporters, computed once per sample while refreshing
    /// jmon's own scrape/export counters on every call.
    pub fn families(&self, hub: &Hub) -> Arc<Families> {
        let base = self
            .families
            .get_or_init(|| Arc::new(metrics::collect(self, hub.top_procs(), &hub.stats)))
            .clone();
        metrics::with_live_self_stats(base, &hub.stats)
    }

    /// Process indices ordered by CPU usage, busiest first.
    pub fn procs_by_cpu(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.snap.processes.len()).collect();
        if let Some(r) = &self.rates {
            idx.sort_by(|&a, &b| r.proc_cpu[b].total_cmp(&r.proc_cpu[a]));
        }
        idx
    }
}

fn rates(prev: &Snapshot, cur: &Snapshot) -> Option<Rates> {
    let secs = cur.taken.duration_since(prev.taken).as_secs_f64();
    if secs <= 0.0 {
        return None;
    }

    let cpus = cur
        .cpus
        .iter()
        .enumerate()
        .map(|(i, c)| prev.cpus.get(i).map(|p| CpuUtil::from_delta(&c.delta(p))).unwrap_or_default())
        .collect();
    let cpu_total = CpuUtil::from_delta(&cur.cpu_total().delta(&prev.cpu_total()));

    let disks = disk_rates(&prev.disks, &cur.disks, secs);
    let partitions = disk_rates(&prev.partitions, &cur.partitions, secs);

    let prev_nets: HashMap<&str, &NetIf> = prev.nets.iter().map(|n| (n.name.as_str(), n)).collect();
    let nets = cur
        .nets
        .iter()
        .map(|n| match prev_nets.get(n.name.as_str()) {
            Some(p) => NetRate {
                rx_bps: per_sec(n.rx_bytes, p.rx_bytes, secs),
                tx_bps: per_sec(n.tx_bytes, p.tx_bytes, secs),
                rx_pps: per_sec(n.rx_packets, p.rx_packets, secs),
                tx_pps: per_sec(n.tx_packets, p.tx_packets, secs),
                errors_ps: per_sec(n.rx_errors + n.tx_errors, p.rx_errors + p.tx_errors, secs),
                drops_ps: per_sec(n.rx_drops + n.tx_drops, p.rx_drops + p.tx_drops, secs),
            },
            None => NetRate::default(),
        })
        .collect();

    let (v, pv) = (&cur.vm, &prev.vm);
    let vm = VmRates {
        context_switches: per_sec(v.context_switches, pv.context_switches, secs),
        interrupts: per_sec(v.interrupts, pv.interrupts, secs),
        syscalls: per_sec(v.syscalls, pv.syscalls, secs),
        traps: per_sec(v.traps, pv.traps, secs),
        forks: per_sec(v.forks, pv.forks, secs),
        faults: per_sec(v.faults, pv.faults, secs),
        swap_pages_in: per_sec(v.swap_pages_in, pv.swap_pages_in, secs),
        swap_pages_out: per_sec(v.swap_pages_out, pv.swap_pages_out, secs),
        swap_ins: per_sec(v.swap_ins, pv.swap_ins, secs),
        swap_outs: per_sec(v.swap_outs, pv.swap_outs, secs),
        vnode_ins: per_sec(v.vnode_ins, pv.vnode_ins, secs),
        vnode_outs: per_sec(v.vnode_outs, pv.vnode_outs, secs),
        vnode_pages_in: per_sec(v.vnode_pages_in, pv.vnode_pages_in, secs),
        vnode_pages_out: per_sec(v.vnode_pages_out, pv.vnode_pages_out, secs),
        zero_fill_faults: per_sec(v.zero_fill_faults, pv.zero_fill_faults, secs),
        cow_faults: per_sec(v.cow_faults, pv.cow_faults, secs),
        intransit_faults: per_sec(v.intransit_faults, pv.intransit_faults, secs),
        reactivated: per_sec(v.reactivated, pv.reactivated, secs),
        pages_freed: per_sec(v.pages_freed, pv.pages_freed, secs),
        pageout_wakeups: per_sec(v.pageout_wakeups, pv.pageout_wakeups, secs),
        pageout_scanned: per_sec(v.pageout_scanned, pv.pageout_scanned, secs),
    };

    let superpages = match (&cur.superpages, &prev.superpages) {
        (Some(c), Some(p)) => Some(SuperpageRates {
            mappings: per_sec(c.mappings, p.mappings, secs),
            promotions: per_sec(c.promotions, p.promotions, secs),
            demotions: per_sec(c.demotions, p.demotions, secs),
            failures: per_sec(c.failures, p.failures, secs),
        }),
        _ => None,
    };

    let nfs = match (&cur.nfs, &prev.nfs) {
        (Some(c), Some(p)) => {
            let ops = |cur: &[(String, u64)], prev: &[(String, u64)]| {
                let mut v: Vec<(String, f64)> = cur
                    .iter()
                    .map(|(name, n)| {
                        let before = prev.iter().find(|(o, _)| o == name).map_or(*n, |(_, b)| *b);
                        (name.clone(), per_sec(*n, before, secs))
                    })
                    .collect();
                v.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                v
            };
            let client_ops = ops(&c.client_ops, &p.client_ops);
            let server_ops = ops(&c.server_ops, &p.server_ops);
            Some(NfsRates {
                client_total: client_ops.iter().map(|o| o.1).sum(),
                server_total: server_ops.iter().map(|o| o.1).sum(),
                client_ops,
                server_ops,
                client_retries: per_sec(c.client_retries, p.client_retries, secs),
                client_timeouts: per_sec(c.client_timeouts, p.client_timeouts, secs),
            })
        }
        _ => None,
    };

    let prev_procs: HashMap<(i32, i64), &Process> =
        prev.processes.iter().map(|p| ((p.pid, p.start_time), p)).collect();
    let mut proc_cpu = Vec::with_capacity(cur.processes.len());
    let mut proc_user_cpu = Vec::with_capacity(cur.processes.len());
    let mut proc_sys_cpu = Vec::with_capacity(cur.processes.len());
    let mut proc_io = Vec::with_capacity(cur.processes.len());
    let mut proc_faults = Vec::with_capacity(cur.processes.len());
    for p in &cur.processes {
        match prev_procs.get(&(p.pid, p.start_time)) {
            Some(q) => {
                let total = p.cpu_time_us.saturating_sub(q.cpu_time_us) as f64 / (secs * 1e4);
                let u_us = p.user_time_us.saturating_sub(q.user_time_us);
                let s_us = p.sys_time_us.saturating_sub(q.sys_time_us);
                let (usr, sys) = if u_us + s_us > 0 {
                    let sum = (u_us + s_us) as f64;
                    (total * (u_us as f64 / sum), total * (s_us as f64 / sum))
                } else {
                    (total, 0.0)
                };
                proc_cpu.push(total);
                proc_user_cpu.push(usr);
                proc_sys_cpu.push(sys);
                proc_io.push(per_sec(p.read_ops + p.write_ops, q.read_ops + q.write_ops, secs));
                proc_faults.push((
                    per_sec(p.minor_faults, q.minor_faults, secs),
                    per_sec(p.major_faults, q.major_faults, secs),
                ));
            }
            None => {
                proc_cpu.push(0.0);
                proc_user_cpu.push(0.0);
                proc_sys_cpu.push(0.0);
                proc_io.push(0.0);
                proc_faults.push((0.0, 0.0));
            }
        }
    }

    let group = |key: &dyn Fn(&Process) -> Option<(i64, String)>| -> Vec<GroupRate> {
        let mut groups: Vec<GroupRate> = Vec::new();
        for (i, p) in cur.processes.iter().enumerate() {
            let Some((id, name)) = key(p) else { continue };
            let g = match groups.iter().position(|g| g.id == id) {
                Some(k) => &mut groups[k],
                None => {
                    groups.push(GroupRate { id, name, ..Default::default() });
                    groups.last_mut().unwrap()
                }
            };
            g.processes += 1;
            g.cpu += proc_cpu[i];
            g.io += proc_io[i];
            g.rss += p.rss;
        }
        groups
    };
    let mut jails = group(&|p| {
        (p.jid > 0).then(|| {
            let name = cur.jails.iter().find(|j| j.jid == p.jid).map(|j| j.name.clone());
            (p.jid as i64, name.unwrap_or_else(|| p.jid.to_string()))
        })
    });
    // Jails with no processes still exist; list them with zero usage.
    for j in &cur.jails {
        if !jails.iter().any(|g| g.id == j.jid as i64) {
            jails.push(GroupRate { id: j.jid as i64, name: j.name.clone(), ..Default::default() });
        }
    }
    jails.sort_by_key(|g| g.id);
    let mut vms = group(&|p| {
        let name = p.args.strip_prefix("bhyve: ")?;
        (p.command == "bhyve").then(|| (p.pid as i64, name.split_whitespace().next().unwrap_or(name).to_string()))
    });
    vms.sort_by(|a, b| a.name.cmp(&b.name));

    let tcp = match (&cur.tcp, &prev.tcp) {
        (Some(t), Some(q)) => Some(TcpRates {
            segs_sent: per_sec(t.segs_sent, q.segs_sent, secs),
            segs_received: per_sec(t.segs_received, q.segs_received, secs),
            retransmits: per_sec(t.retransmits, q.retransmits, secs),
            listen_drops: per_sec(t.listen_drops, q.listen_drops, secs),
            accepts: per_sec(t.accepts, q.accepts, secs),
            conn_attempts: per_sec(t.conn_attempts, q.conn_attempts, secs),
        }),
        _ => None,
    };

    let udp = match (&cur.udp, &prev.udp) {
        (Some(u), Some(q)) => Some(UdpRates {
            datagrams_in: per_sec(u.datagrams_in, q.datagrams_in, secs),
            datagrams_out: per_sec(u.datagrams_out, q.datagrams_out, secs),
            in_errors: per_sec(u.in_errors, q.in_errors, secs),
            no_ports: per_sec(u.no_ports, q.no_ports, secs),
            full_socket_buffers: per_sec(u.full_socket_buffers, q.full_socket_buffers, secs),
        }),
        _ => None,
    };

    let zfs = match (&cur.zfs, &prev.zfs) {
        (Some(z), Some(q)) => {
            let hits = z.arc_hits.saturating_sub(q.arc_hits) as f64;
            let misses = z.arc_misses.saturating_sub(q.arc_misses) as f64;
            let pools = z
                .pools
                .iter()
                .map(|p| match q.pools.iter().find(|o| o.name == p.name) {
                    Some(o) => PoolRate {
                        read_bps: per_sec(p.read_bytes, o.read_bytes, secs),
                        write_bps: per_sec(p.write_bytes, o.write_bytes, secs),
                        read_iops: per_sec(p.read_ops, o.read_ops, secs),
                        write_iops: per_sec(p.write_ops, o.write_ops, secs),
                    },
                    None => PoolRate::default(),
                })
                .collect();
            Some(ZfsRates {
                arc_hit_ratio: (hits + misses > 0.0).then(|| hits / (hits + misses)),
                arc_lookups: (hits + misses) / secs,
                pools,
            })
        }
        _ => None,
    };

    Some(Rates {
        interval: secs,
        cpu_total,
        cpus,
        disks,
        partitions,
        nets,
        vm,
        superpages,
        nfs,
        proc_cpu,
        proc_user_cpu,
        proc_sys_cpu,
        proc_io,
        proc_faults,
        jails,
        vms,
        tcp,
        udp,
        zfs,
    })
}

/// Totals for each disk group: summed throughput and operations, and the
/// members' average busy time. Members may be disks or GEOM providers.
pub fn group_rates(groups: &[DiskGroup], snap: &Snapshot, r: &Rates) -> Vec<DiskRate> {
    let find = |name: &str| -> Option<DiskRate> {
        let pos = |list: &[Disk]| list.iter().position(|d| d.name == name);
        pos(&snap.disks).map(|i| r.disks[i]).or_else(|| pos(&snap.partitions).map(|i| r.partitions[i]))
    };
    groups
        .iter()
        .map(|g| {
            let members: Vec<DiskRate> = g.members.iter().filter_map(|m| find(m)).collect();
            let mut t = DiskRate::default();
            for m in &members {
                t.read_bps += m.read_bps;
                t.write_bps += m.write_bps;
                t.read_iops += m.read_iops;
                t.write_iops += m.write_iops;
                t.busy += m.busy;
            }
            if !members.is_empty() {
                t.busy /= members.len() as f64;
            }
            t
        })
        .collect()
}

/// Per-device rates, matched to the previous snapshot by name.
fn disk_rates(prev: &[Disk], cur: &[Disk], secs: f64) -> Vec<DiskRate> {
    let prev: HashMap<&str, &Disk> = prev.iter().map(|d| (d.name.as_str(), d)).collect();
    let latency = |secs: f64, psecs: f64, ops: u64, pops: u64| {
        let n = ops.saturating_sub(pops);
        if n == 0 { 0.0 } else { (secs - psecs).max(0.0) * 1000.0 / n as f64 }
    };
    cur.iter()
        .map(|d| match prev.get(d.name.as_str()) {
            Some(p) => DiskRate {
                read_bps: per_sec(d.read_bytes, p.read_bytes, secs),
                write_bps: per_sec(d.write_bytes, p.write_bytes, secs),
                read_iops: per_sec(d.read_ops, p.read_ops, secs),
                write_iops: per_sec(d.write_ops, p.write_ops, secs),
                busy: ((d.busy_secs - p.busy_secs) / secs).clamp(0.0, 1.0),
                read_ms: latency(d.read_secs, p.read_secs, d.read_ops, p.read_ops),
                write_ms: latency(d.write_secs, p.write_secs, d.write_ops, p.write_ops),
            },
            None => DiskRate::default(),
        })
        .collect()
}

// ---------------------------------------------------------------------------

/// jmon's own health counters, exported alongside system metrics.
#[derive(Default)]
pub struct SelfStats {
    pub export_ok: AtomicU64,
    pub export_failed: AtomicU64,
    pub scrapes: AtomicU64,
}

/// Shared state between the sampler, the screen, and the exporters.
pub struct Hub {
    pub stats: SelfStats,
    latest: RwLock<Option<Arc<Sample>>>,
    interval_ms: AtomicU64,
    stop: Mutex<bool>,
    wake: Condvar,
    top_procs: AtomicUsize,
    live_sink: Mutex<Option<(PathBuf, Box<dyn Sink>)>>,
}

impl Hub {
    pub fn new(interval: Duration, top_procs: usize) -> Arc<Hub> {
        Arc::new(Hub {
            latest: RwLock::new(None),
            interval_ms: AtomicU64::new(interval.as_millis().max(100) as u64),
            stop: Mutex::new(false),
            wake: Condvar::new(),
            top_procs: AtomicUsize::new(top_procs),
            live_sink: Mutex::new(None),
            stats: SelfStats::default(),
        })
    }

    pub fn top_procs(&self) -> usize {
        self.top_procs.load(Ordering::Relaxed)
    }

    pub fn set_top_procs(&self, top_procs: usize) {
        self.top_procs.store(top_procs, Ordering::Relaxed);
    }

    pub fn recording_path(&self) -> Option<PathBuf> {
        self.live_sink.lock().unwrap().as_ref().map(|(p, _)| p.clone())
    }

    pub fn set_live_sink(&self, sink: Option<(PathBuf, Box<dyn Sink>)>) {
        *self.live_sink.lock().unwrap() = sink;
    }

    pub fn latest(&self) -> Option<Arc<Sample>> {
        self.latest.read().unwrap().clone()
    }

    fn publish(&self, s: Arc<Sample>) {
        *self.latest.write().unwrap() = Some(s);
    }

    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.load(Ordering::Relaxed))
    }

    /// Changes the sampling interval and wakes the sampler so it applies now.
    pub fn set_interval(&self, d: Duration) {
        self.interval_ms.store(d.as_millis().clamp(100, 3_600_000) as u64, Ordering::Relaxed);
        self.wake.notify_all();
    }

    pub fn request_stop(&self) {
        *self.stop.lock().unwrap() = true;
        self.wake.notify_all();
    }

    pub fn stopped(&self) -> bool {
        *self.stop.lock().unwrap()
    }

    /// Sleeps until `deadline`, an interval change, or stop. Returns true if stopping.
    fn sleep_until(&self, deadline: Instant, interval_ms: u64) -> bool {
        let mut stop = self.stop.lock().unwrap();
        loop {
            if *stop {
                return true;
            }
            let now = Instant::now();
            if now >= deadline || self.interval_ms.load(Ordering::Relaxed) != interval_ms {
                return false;
            }
            stop = self.wake.wait_timeout(stop, deadline - now).unwrap().0;
        }
    }
}

/// Receives every sample with rates, in order (used by recorders).
pub trait Sink: Send {
    fn write(&mut self, s: &Sample) -> std::io::Result<()>;
}

/// Runs the collection loop on its own thread. After `count` samples with
/// rates have been produced, asks everything to stop (nmon's -c).
pub fn spawn(hub: Arc<Hub>, mut collector: Collector, mut sinks: Vec<Box<dyn Sink>>, count: Option<u64>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("sampler".into())
        .spawn(move || {
            let host = collector.host();
            let mut prev = collector.collect();
            hub.publish(Arc::new(Sample::derive(0, host.clone(), None, prev.clone())));
            // First real sample comes quickly so the screen isn't blank for a full interval.
            let mut interval_ms = hub.interval_ms.load(Ordering::Relaxed);
            let mut deadline = Instant::now() + Duration::from_millis(interval_ms.min(1000));
            let mut seq = 0u64;
            loop {
                if hub.sleep_until(deadline, interval_ms) {
                    break;
                }
                let now_ms = hub.interval_ms.load(Ordering::Relaxed);
                if now_ms != interval_ms {
                    // Interval changed: restart the schedule from now.
                    interval_ms = now_ms;
                    deadline = Instant::now() + Duration::from_millis(interval_ms);
                    continue;
                }
                let started = Instant::now();
                let snap = collector.collect();
                seq += 1;
                let mut sample = Sample::derive(seq, host.clone(), Some(&prev), snap.clone());
                sample.collect_secs = started.elapsed().as_secs_f64();
                let sample = Arc::new(sample);
                prev = snap;
                hub.publish(sample.clone());
                for s in &mut sinks {
                    if let Err(e) = s.write(&sample) {
                        warn!("recording sample: {e}");
                    }
                }
                if let Some((_, ref mut s)) = *hub.live_sink.lock().unwrap()
                    && let Err(e) = s.write(&sample)
                {
                    warn!("recording sample: {e}");
                }
                if count.is_some_and(|c| seq >= c) {
                    hub.request_stop();
                    break;
                }
                // Fixed-rate schedule; skip missed ticks rather than bursting.
                deadline += Duration::from_millis(interval_ms);
                let now = Instant::now();
                if deadline < now {
                    deadline = now + Duration::from_millis(interval_ms);
                }
            }
        })
        .expect("spawn sampler thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::M;

    fn test_host() -> Arc<HostInfo> {
        Arc::new(HostInfo {
            hostname: "h".into(),
            os_type: "freebsd".into(),
            os_release: "14.3".into(),
            machine: "amd64".into(),
            cpu_model: "cpu".into(),
            ncpu: 2,
            physmem: 1 << 30,
            pagesize: 4096,
            demo: true,
        })
    }

    #[test]
    fn pid_reuse_does_not_inherit_previous_process_counters() {
        let mut prev = Snapshot::empty();
        prev.processes.push(Process {
            pid: 100,
            start_time: 1000,
            cpu_time_us: 500_000,
            user_time_us: 400_000,
            sys_time_us: 100_000,
            ..Default::default()
        });
        let mut cur = Snapshot::empty();
        cur.taken = prev.taken + Duration::from_secs(1);
        // Same PID (100), different start_time (2000): recycled PID.
        cur.processes.push(Process {
            pid: 100,
            start_time: 2000,
            cpu_time_us: 900_000,
            user_time_us: 800_000,
            sys_time_us: 100_000,
            ..Default::default()
        });
        let s = Sample::derive(1, test_host(), Some(&prev), cur);
        let r = s.rates.as_ref().unwrap();
        assert_eq!(r.proc_cpu[0], 0.0);

        // Matching start_time computes user/sys split accurately.
        let mut cur2 = Snapshot::empty();
        cur2.taken = prev.taken + Duration::from_secs(1);
        cur2.processes.push(Process {
            pid: 100,
            start_time: 1000,
            cpu_time_us: 1_000_000,
            user_time_us: 800_000,
            sys_time_us: 200_000,
            ..Default::default()
        });
        let s2 = Sample::derive(2, test_host(), Some(&prev), cur2);
        let r2 = s2.rates.as_ref().unwrap();
        assert!((r2.proc_cpu[0] - 50.0).abs() < 1e-6);
        assert!((r2.proc_user_cpu[0] - 40.0).abs() < 1e-6);
        assert!((r2.proc_sys_cpu[0] - 10.0).abs() < 1e-6);
    }

    #[test]
    fn families_refresh_live_self_stats() {
        let hub = Hub::new(Duration::from_secs(1), 0);
        let s = Sample::derive(1, test_host(), None, Snapshot::empty());
        assert!(s.families(&hub)[M::SelfScrapes as usize].is_empty());
        hub.stats.scrapes.fetch_add(3, Ordering::Relaxed);
        assert_eq!(s.families(&hub)[M::SelfScrapes as usize][0].value, 3.0);
        hub.set_top_procs(5);
        assert_eq!(hub.top_procs(), 5);
    }
}
