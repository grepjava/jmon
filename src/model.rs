//! Platform-neutral snapshot of raw system counters.
//!
//! Collectors fill these with cumulative values exactly as the kernel reports
//! them; rates and percentages are derived later in `sample`.

use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_type: String,
    pub os_release: String,
    pub machine: String,
    pub cpu_model: String,
    pub ncpu: usize,
    pub physmem: u64,
    pub pagesize: u64,
    /// True when the data is synthetic (non-FreeBSD development builds).
    pub demo: bool,
}

/// Cumulative CPU ticks for one logical CPU, in `kern.cp_times` order.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CpuTicks {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub interrupt: u64,
    pub idle: u64,
}

impl CpuTicks {
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.interrupt + self.idle
    }

    pub fn delta(&self, prev: &CpuTicks) -> CpuTicks {
        CpuTicks {
            user: self.user.saturating_sub(prev.user),
            nice: self.nice.saturating_sub(prev.nice),
            system: self.system.saturating_sub(prev.system),
            interrupt: self.interrupt.saturating_sub(prev.interrupt),
            idle: self.idle.saturating_sub(prev.idle),
        }
    }

    pub fn modes(&self) -> [(&'static str, u64); 5] {
        [
            ("user", self.user),
            ("nice", self.nice),
            ("system", self.system),
            ("interrupt", self.interrupt),
            ("idle", self.idle),
        ]
    }
}

/// Physical memory by FreeBSD page queue, in bytes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Memory {
    pub total: u64,
    pub active: u64,
    pub inactive: u64,
    pub laundry: u64,
    pub wired: u64,
    pub free: u64,
    /// ZFS ARC size (part of wired), when ZFS is loaded.
    pub arc: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SwapDev {
    pub name: String,
    pub total: u64,
    pub used: u64,
}

/// Cumulative kernel event counters from `vm.stats`.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct VmCounters {
    pub context_switches: u64,
    pub interrupts: u64,
    pub syscalls: u64,
    pub traps: u64,
    pub forks: u64,
    pub faults: u64,
    pub swap_pages_in: u64,
    pub swap_pages_out: u64,
    /// Swap pager operations (each may move several pages).
    pub swap_ins: u64,
    pub swap_outs: u64,
    /// Vnode pager (file-backed) operations and pages.
    pub vnode_ins: u64,
    pub vnode_outs: u64,
    pub vnode_pages_in: u64,
    pub vnode_pages_out: u64,
    pub zero_fill_faults: u64,
    pub cow_faults: u64,
    pub intransit_faults: u64,
    pub reactivated: u64,
    pub pages_freed: u64,
    pub pageout_wakeups: u64,
    pub pageout_scanned: u64,
}

/// Thread counts by scheduling state from vm.vmtotal (vmstat's r/b/w).
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct RunQueue {
    pub runnable: u64,
    pub disk_wait: u64,
    pub page_wait: u64,
    pub sleeping: u64,
}

/// Superpage (2 MB page) activity from vm.pmap.pde.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Superpages {
    pub enabled: bool,
    pub mappings: u64,
    pub promotions: u64,
    pub demotions: u64,
    pub failures: u64,
}

/// Cumulative NFS operation counts, from nfsstat(1).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Nfs {
    pub client_ops: Vec<(String, u64)>,
    pub client_requests: u64,
    pub client_retries: u64,
    pub client_timeouts: u64,
    pub server_ops: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Disk {
    pub name: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub busy_secs: f64,
    pub read_secs: f64,
    pub write_secs: f64,
    /// Requests issued but not yet completed.
    pub queue: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NetIf {
    pub name: String,
    pub up: bool,
    pub mtu: u32,
    pub baudrate: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Filesystem {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    pub total: u64,
    pub free: u64,
    /// Space available to unprivileged users (free minus reserved).
    pub avail: u64,
}

impl Filesystem {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub user: String,
    pub command: String,
    /// Full command line, when readable.
    pub args: String,
    /// Jail ID; 0 for the host.
    pub jid: i32,
    pub state: &'static str,
    pub threads: u32,
    /// Process start time in microseconds since the Unix epoch (disambiguates recycled PIDs).
    pub start_time: i64,
    /// Cumulative CPU time in microseconds.
    pub cpu_time_us: u64,
    /// Cumulative user CPU time in microseconds (rusage).
    pub user_time_us: u64,
    /// Cumulative system CPU time in microseconds (rusage).
    pub sys_time_us: u64,
    pub rss: u64,
    pub vsize: u64,
    /// Cumulative block input and output operations (rusage).
    pub read_ops: u64,
    pub write_ops: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    #[serde(skip)]
    pub taken: Instant,
    /// Wall clock, seconds since the Unix epoch.
    pub timestamp: f64,
    pub uptime: f64,
    /// Statistics clock rate: CPU ticks per second.
    pub stathz: u32,
    pub cpus: Vec<CpuTicks>,
    pub load: [f64; 3],
    pub memory: Memory,
    pub swap: Vec<SwapDev>,
    pub vm: VmCounters,
    pub runq: RunQueue,
    pub superpages: Option<Superpages>,
    pub disks: Vec<Disk>,
    /// GEOM providers other than whole disks (partitions, labels, mirrors).
    pub partitions: Vec<Disk>,
    pub nets: Vec<NetIf>,
    pub filesystems: Vec<Filesystem>,
    pub processes: Vec<Process>,
    pub sensors: Sensors,
    pub tcp: Option<Tcp>,
    pub udp: Option<Udp>,
    pub jails: Vec<Jail>,
    pub zfs: Option<Zfs>,
    /// Present only while NFS is in use (an NFS mount or a running nfsd).
    pub nfs: Option<Nfs>,
    /// Kernel tables with fixed limits: open files, sockets, vnodes, ...
    pub limits: Vec<KernelLimit>,
    /// The kernel's UMA allocator zones, as vmstat -z lists them.
    pub zones: Vec<UmaZone>,
    /// How each collector fared this sample, so a zero or an empty list can be
    /// told apart from data that could not be read.
    pub collectors: Vec<CollectorStatus>,
}

/// A kernel table and its limit.
#[derive(Debug, Clone, Serialize)]
pub struct KernelLimit {
    pub name: &'static str,
    /// The sysctl that sets the limit.
    pub sysctl: &'static str,
    pub used: u64,
    pub limit: u64,
    /// Whether the numbers are bytes rather than items.
    pub bytes: bool,
}

/// One UMA zone, the kernel allocator for one kind of object.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UmaZone {
    pub name: String,
    pub size: u64,
    /// Most items it may hand out; 0 for no limit.
    pub limit: u64,
    pub used: u64,
    /// Cumulative allocations, failed ones, and ones that slept at the limit.
    pub requests: u64,
    pub fails: u64,
    pub sleeps: u64,
}

impl UmaZone {
    /// UMA's own bucket and page caches fail non-blocking allocations by
    /// design and fall back to slower paths.
    pub fn fails_by_design(&self) -> bool {
        self.name.ends_with(" Bucket") || self.name == "vm pgcache"
    }

    /// Physical buffer pools have small limits and fill up in ordinary I/O.
    pub fn routinely_full(&self) -> bool {
        self.name.ends_with("pbuf") || matches!(self.name.as_str(), "swrbuf" | "swwbuf")
    }
}

/// Whether a collector's data in this snapshot can be trusted.
// Only the FreeBSD collector can fail; the demo source is always ok.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Ok,
    /// Read, but some fields were unavailable and hold zero (see `detail`).
    Partial,
    /// The refresh failed; the values are from the last successful read.
    Stale,
    /// The kernel or system lacks it (no such sysctl, module or command).
    Unsupported,
    /// Not readable with jmon's privileges.
    Denied,
    Failed,
}

impl Availability {
    pub fn as_str(self) -> &'static str {
        match self {
            Availability::Ok => "ok",
            Availability::Partial => "partial",
            Availability::Stale => "stale",
            Availability::Unsupported => "unsupported",
            Availability::Denied => "denied",
            Availability::Failed => "failed",
        }
    }

    /// Whether the collector's values reflect the system, if not fully or freshly.
    pub fn usable(self) -> bool {
        matches!(self, Availability::Ok | Availability::Partial | Availability::Stale)
    }

    /// Classifies a collection error by the OS error underneath it.
    #[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
    pub fn of(e: &anyhow::Error) -> Availability {
        use std::io::ErrorKind;
        match e.chain().find_map(|c| c.downcast_ref::<std::io::Error>()).map(|e| e.kind()) {
            Some(ErrorKind::NotFound | ErrorKind::Unsupported) => Availability::Unsupported,
            Some(ErrorKind::PermissionDenied) => Availability::Denied,
            _ => Availability::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectorStatus {
    pub name: &'static str,
    pub state: Availability,
    /// The error, or for `partial` the fields that were unavailable.
    pub detail: Option<String>,
    /// Wall clock of the last successful read, seconds since the Unix epoch.
    pub last_ok: Option<f64>,
    /// Seconds this collector took in this sample.
    pub duration: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Sensors {
    /// Per-CPU temperature in Celsius (needs coretemp or amdtemp loaded).
    pub cpu_temps: Vec<f64>,
    /// Temperature at which the CPU throttles (coretemp's tjmax), Celsius.
    pub cpu_tjmax: Option<f64>,
    pub cpu_freq_mhz: Option<u64>,
    /// Per-CPU clock where the driver reports one.
    pub cpu_freqs_mhz: Vec<u64>,
    /// ACPI thermal zones: (name, Celsius).
    pub thermal_zones: Vec<(String, f64)>,
    pub battery: Option<Battery>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Battery {
    /// Remaining charge, percent.
    pub life: f64,
    /// Minutes remaining while discharging.
    pub minutes_left: Option<u64>,
    pub state: &'static str,
    pub ac_online: bool,
}

/// Cumulative TCP counters from net.inet.tcp.stats plus current
/// connection counts by state.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Tcp {
    pub conn_attempts: u64,
    pub accepts: u64,
    pub drops: u64,
    pub segs_sent: u64,
    pub segs_received: u64,
    pub retransmits: u64,
    pub listen_drops: u64,
    pub bad_checksums: u64,
    pub states: Vec<(&'static str, u64)>,
}

/// Cumulative UDP counters from net.inet.udp.stats.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Udp {
    pub datagrams_in: u64,
    pub datagrams_out: u64,
    pub in_errors: u64,
    pub no_ports: u64,
    pub full_socket_buffers: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Jail {
    pub jid: i32,
    pub name: String,
    pub hostname: String,
    /// The kernel's resource accounting (RACCT) for the jail, as rctl -u
    /// shows it; `None` when it could not be read (see the rctl collector).
    pub racct: Option<Vec<(String, u64)>>,
    /// rctl rules on the jail.
    pub rules: Vec<RctlRule>,
}

impl Jail {
    pub fn usage(&self, resource: &str) -> Option<u64> {
        self.racct.as_ref()?.iter().find(|(r, _)| r == resource).map(|(_, v)| *v)
    }
}

/// One rctl rule: `jail:<name>:<resource>:<action>=<amount>[/<per>]`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RctlRule {
    pub resource: String,
    /// deny, log, devctl, sigkill, throttle, ...
    pub action: String,
    pub amount: u64,
    /// What the amount applies to: "jail" for the jail as a whole, or
    /// "process" or "user" for each one in it.
    pub per: String,
}

impl RctlRule {
    /// Fraction of a jail-wide limit in use; `None` for per-process or
    /// per-user rules, which jail totals cannot be compared with.
    pub fn used(&self, jail: &Jail) -> Option<f64> {
        (self.per == "jail" && self.amount > 0).then(|| jail.usage(&self.resource).map(|u| u as f64 / self.amount as f64))?
    }
}

/// How an RACCT resource is counted, for display.
pub fn racct_unit(resource: &str) -> LimitUnit {
    match resource {
        "cputime" | "wallclock" => LimitUnit::Seconds,
        "datasize" | "stacksize" | "coredumpsize" | "memoryuse" | "memorylocked" | "vmemoryuse" | "swapuse" | "shmsize"
        | "msgqsize" | "readbps" | "writebps" => LimitUnit::Bytes,
        _ => LimitUnit::Count,
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Zfs {
    pub arc_size: u64,
    pub arc_target: u64,
    pub arc_max: u64,
    pub arc_hits: u64,
    pub arc_misses: u64,
    pub l2_size: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub pools: Vec<ZPool>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ZPool {
    pub name: String,
    pub health: String,
    pub size: u64,
    pub allocated: u64,
    pub free: u64,
    pub fragmentation: Option<u64>,
    /// Cumulative logical I/O summed over the pool's datasets.
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    /// Devices, errors and scrub or resilver state from `zpool status`;
    /// `None` when that could not be read (see the zpool_status collector).
    pub status: Option<PoolStatus>,
    /// Per-device latency and queues from `zpool iostat`, pool totals first;
    /// `None` until its first report (see the zpool_iostat collector).
    pub iostat: Option<Vec<VdevIo>>,
}

/// One line of a `zpool iostat -vlq` report: averages over its interval.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VdevIo {
    pub name: String,
    /// Operations and bytes per second.
    pub read_ops: f64,
    pub write_ops: f64,
    pub read_bytes: f64,
    pub write_bytes: f64,
    /// Mean seconds from queueing to completion, and the part spent on the
    /// device; the rest was waiting in ZFS's queues. `None` without I/O.
    pub read_wait: Option<f64>,
    pub write_wait: Option<f64>,
    pub read_disk_wait: Option<f64>,
    pub write_disk_wait: Option<f64>,
    /// ZFS I/O queues: (name, pending, active).
    pub queues: Vec<(&'static str, u64, u64)>,
}

impl VdevIo {
    /// I/Os waiting in ZFS's queues, and issued to the device.
    pub fn pending(&self) -> u64 {
        self.queues.iter().map(|q| q.1).sum()
    }

    pub fn active(&self) -> u64 {
        self.queues.iter().map(|q| q.2).sum()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PoolStatus {
    /// zpool status's explanation of a problem, and what to do about it.
    pub message: Option<String>,
    pub action: Option<String>,
    /// Permanent errors: data ZFS could not repair.
    pub data_errors: u64,
    /// The last or current scrub or resilver, if there has been one.
    pub scan: Option<PoolScan>,
    /// Devices depth first; top-level vdevs have depth 0.
    pub vdevs: Vec<Vdev>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PoolScan {
    /// "scrub", "resilver" or "error scrub".
    pub function: String,
    /// "scanning", "finished" or "canceled".
    pub state: String,
    pub paused: bool,
    /// Unix times; `end_time` is 0 while scanning.
    pub start_time: u64,
    pub end_time: u64,
    pub to_examine: u64,
    pub issued: u64,
    /// Bytes rewritten from good copies.
    pub repaired: u64,
    /// Errors it could not repair.
    pub errors: u64,
    /// Bytes issued in this pass, when the pass started, and seconds it has
    /// spent paused, for the current rate.
    pub pass_issued: u64,
    pub pass_start: u64,
    pub pass_paused_secs: u64,
}

impl PoolScan {
    /// Fraction done, as zpool status counts it (bytes issued of the total).
    pub fn progress(&self) -> f64 {
        if self.to_examine == 0 { 0.0 } else { (self.issued as f64 / self.to_examine as f64).min(1.0) }
    }

    /// Bytes per second issued in this pass, at Unix time `now`.
    pub fn rate(&self, now: f64) -> Option<f64> {
        let secs = now - self.pass_start as f64 - self.pass_paused_secs as f64;
        (self.state == "scanning" && secs >= 1.0).then(|| self.pass_issued as f64 / secs)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Vdev {
    pub name: String,
    /// mirror, raidz2, disk, file, ...
    pub kind: String,
    /// Empty for the main devices, else special, dedup, logs, cache or spares.
    pub group: &'static str,
    pub depth: u8,
    pub state: String,
    pub read_errors: u64,
    pub write_errors: u64,
    pub checksum_errors: u64,
    /// Leaf devices only: I/Os slower than zio_slow_io_ms.
    pub slow_ios: Option<u64>,
    /// Why the device is not usable ("cannot open"), or the path it had.
    pub note: Option<String>,
}

impl Vdev {
    pub fn errors(&self) -> u64 {
        self.read_errors + self.write_errors + self.checksum_errors
    }

    /// Whether the device is working as it should. Spares wait as AVAIL.
    pub fn healthy(&self) -> bool {
        matches!(self.state.as_str(), "ONLINE" | "AVAIL")
    }
}

/// Why part of a process's detail could not be read.
#[derive(Debug, Clone)]
pub struct Unavailable {
    pub state: Availability,
    pub detail: String,
}

impl Unavailable {
    #[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
    pub fn of(e: &anyhow::Error) -> Unavailable {
        Unavailable { state: Availability::of(e), detail: format!("{e:#}") }
    }
}

/// One process looked at closely: read on demand for the detail screen, never
/// part of a sample.
#[derive(Debug, Clone)]
pub struct ProcDetail {
    /// Wall clock of the read, seconds since the Unix epoch.
    pub taken: f64,
    pub threads: Result<Vec<Thread>, Unavailable>,
    pub files: Result<OpenFiles, Unavailable>,
    pub limits: Result<Vec<Limit>, Unavailable>,
}

#[derive(Debug, Clone, Default)]
pub struct Thread {
    pub tid: i32,
    pub name: String,
    pub state: &'static str,
    /// What a sleeping thread waits on (its wait message), or `*lock` when
    /// blocked on a kernel lock.
    pub wait: String,
    pub last_cpu: i32,
    pub priority: u8,
    /// Cumulative CPU time in microseconds.
    pub runtime_us: u64,
    /// Cumulative voluntary and involuntary context switches.
    pub voluntary_switches: u64,
    pub involuntary_switches: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}

#[derive(Debug, Clone, Default)]
pub struct OpenFiles {
    /// Descriptors by type (vnode, socket, pipe, ...), most common first.
    pub by_type: Vec<(&'static str, u64)>,
    pub cwd: Option<String>,
    pub executable: Option<String>,
}

impl OpenFiles {
    pub fn total(&self) -> u64 {
        self.by_type.iter().map(|(_, n)| n).sum()
    }
}

#[derive(Debug, Clone)]
pub struct Limit {
    pub name: &'static str,
    pub unit: LimitUnit,
    /// `None` is unlimited.
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitUnit {
    Seconds,
    Bytes,
    Count,
}

impl Snapshot {
    /// A snapshot with nothing in it, for tests to fill in.
    #[cfg(test)]
    pub fn empty() -> Snapshot {
        Snapshot {
            taken: Instant::now(),
            timestamp: 0.0,
            uptime: 0.0,
            stathz: 128,
            cpus: vec![],
            load: [0.0; 3],
            memory: Default::default(),
            swap: vec![],
            vm: Default::default(),
            runq: Default::default(),
            superpages: None,
            disks: vec![],
            partitions: vec![],
            nets: vec![],
            filesystems: vec![],
            processes: vec![],
            sensors: Default::default(),
            tcp: None,
            udp: None,
            jails: vec![],
            zfs: None,
            nfs: None,
            limits: vec![],
            zones: vec![],
            collectors: vec![],
        }
    }

    /// Whether the named collector's data can be used. Collectors that did not
    /// report (such as NFS while it is idle) count as usable.
    pub fn usable(&self, collector: &str) -> bool {
        self.collectors.iter().find(|c| c.name == collector).is_none_or(|c| c.state.usable())
    }

    pub fn cpu_total(&self) -> CpuTicks {
        self.cpus.iter().fold(CpuTicks::default(), |a, c| CpuTicks {
            user: a.user + c.user,
            nice: a.nice + c.nice,
            system: a.system + c.system,
            interrupt: a.interrupt + c.interrupt,
            idle: a.idle + c.idle,
        })
    }
}

pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// A named set of disks shown and recorded as one (nmon's -g disk groups).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskGroup {
    pub name: String,
    pub members: Vec<String>,
}

impl std::str::FromStr for DiskGroup {
    type Err = String;

    /// Parses `NAME=disk1,disk2`.
    fn from_str(s: &str) -> Result<Self, String> {
        let (name, members) = s.split_once('=').ok_or("expected NAME=disk1,disk2")?;
        let members: Vec<String> =
            members.split(',').map(str::trim).filter(|m| !m.is_empty()).map(String::from).collect();
        if name.trim().is_empty() || members.is_empty() {
            return Err("expected NAME=disk1,disk2".into());
        }
        Ok(DiskGroup { name: name.trim().to_string(), members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn io(kind: std::io::ErrorKind) -> anyhow::Error {
        Err::<(), _>(std::io::Error::from(kind)).context("kern.example").unwrap_err()
    }

    #[test]
    fn errors_classify_by_the_os_error_underneath() {
        use std::io::ErrorKind;
        assert_eq!(Availability::of(&io(ErrorKind::NotFound)), Availability::Unsupported);
        assert_eq!(Availability::of(&io(ErrorKind::PermissionDenied)), Availability::Denied);
        assert_eq!(Availability::of(&io(ErrorKind::InvalidData)), Availability::Failed);
        assert_eq!(Availability::of(&anyhow::anyhow!("zpool list exited with 1")), Availability::Failed);
    }

    #[test]
    fn unreported_collectors_count_as_usable() {
        let mut s = Snapshot::empty();
        s.collectors.push(CollectorStatus {
            name: "runq",
            state: Availability::Denied,
            detail: None,
            last_ok: None,
            duration: 0.0,
        });
        assert!(!s.usable("runq"));
        assert!(s.usable("nfs"));
    }
}
