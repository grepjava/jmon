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
        }
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
