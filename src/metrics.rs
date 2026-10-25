//! The metric catalog: one definition that both the OTLP exporter and the
//! Prometheus endpoint render. Names follow the OpenTelemetry system/process
//! semantic conventions; FreeBSD-only signals live under `freebsd.*`.

use crate::sample::{Sample, SelfStats};
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Monotonic cumulative sum.
    Counter,
    /// Non-monotonic cumulative sum (a level that can go up and down).
    UpDown,
    Gauge,
}

#[derive(Debug)]
pub struct Desc {
    pub name: &'static str,
    pub unit: &'static str,
    pub kind: Kind,
    pub help: &'static str,
}

#[derive(Debug, Clone)]
pub enum Val {
    Str(String),
    Int(i64),
}

impl From<&str> for Val {
    fn from(s: &str) -> Val {
        Val::Str(s.to_string())
    }
}
impl From<String> for Val {
    fn from(s: String) -> Val {
        Val::Str(s)
    }
}
impl From<i64> for Val {
    fn from(i: i64) -> Val {
        Val::Int(i)
    }
}

pub type Attrs = Vec<(&'static str, Val)>;

#[derive(Debug, Clone)]
pub struct Point {
    pub attrs: Attrs,
    pub value: f64,
}

/// Points for each catalog entry, index-aligned with `CATALOG`.
pub type Families = Vec<Vec<Point>>;

macro_rules! catalog {
    ($($id:ident => $name:literal, $unit:literal, $kind:ident, $help:literal;)*) => {
        #[derive(Debug, Clone, Copy)]
        #[repr(usize)]
        pub enum M { $($id),* }
        pub const CATALOG: &[Desc] = &[
            $(Desc { name: $name, unit: $unit, kind: Kind::$kind, help: $help }),*
        ];
    };
}

catalog! {
    CpuTime => "system.cpu.time", "s", Counter, "Seconds each logical CPU spent in each mode.";
    CpuUtilization => "system.cpu.utilization", "1", Gauge, "Fraction of the last interval each logical CPU spent in each mode.";
    CpuCount => "system.cpu.logical.count", "{cpu}", UpDown, "Number of logical CPUs.";
    Load1 => "system.cpu.load_average.1m", "{thread}", Gauge, "1 minute load average.";
    Load5 => "system.cpu.load_average.5m", "{thread}", Gauge, "5 minute load average.";
    Load15 => "system.cpu.load_average.15m", "{thread}", Gauge, "15 minute load average.";
    MemUsage => "system.memory.usage", "By", UpDown, "Physical memory by page queue.";
    MemLimit => "system.memory.limit", "By", UpDown, "Total physical memory managed by the VM system.";
    MemUtilization => "system.memory.utilization", "1", Gauge, "Fraction of physical memory by page queue.";
    ZfsArc => "freebsd.zfs.arc.size", "By", UpDown, "ZFS ARC size (included in wired memory).";
    PagingUsage => "system.paging.usage", "By", UpDown, "Swap space used and free per device.";
    PagingUtilization => "system.paging.utilization", "1", Gauge, "Fraction of swap space used and free per device.";
    PagingOps => "system.paging.operations", "{operation}", Counter, "Pages swapped in and out.";
    ContextSwitches => "freebsd.kernel.context_switches", "{switch}", Counter, "Context switches.";
    Interrupts => "freebsd.kernel.interrupts", "{interrupt}", Counter, "Device interrupts.";
    Syscalls => "freebsd.kernel.syscalls", "{call}", Counter, "System calls.";
    Traps => "freebsd.kernel.traps", "{trap}", Counter, "Traps.";
    PageFaults => "freebsd.vm.page_faults", "{fault}", Counter, "Address-space page faults.";
    ProcCreated => "system.process.created", "{process}", Counter, "Processes created (fork, vfork, rfork).";
    ProcCount => "system.process.count", "{process}", UpDown, "Processes by state.";
    DiskIo => "system.disk.io", "By", Counter, "Bytes read from and written to each disk.";
    DiskOps => "system.disk.operations", "{operation}", Counter, "Read and write operations per disk.";
    DiskIoTime => "system.disk.io_time", "s", Counter, "Time each disk had I/O outstanding.";
    DiskOpTime => "system.disk.operation_time", "s", Counter, "Sum of read and write operation durations per disk.";
    DiskBusy => "freebsd.disk.busy", "1", Gauge, "Fraction of the last interval each disk was busy.";
    DiskPending => "system.disk.pending_operations", "{operation}", UpDown, "Requests issued to each disk but not yet completed.";
    DiskLatency => "freebsd.disk.latency", "s", Gauge, "Average time per completed read or write over the last interval.";
    NetIo => "system.network.io", "By", Counter, "Bytes received and transmitted per interface.";
    NetPackets => "system.network.packets", "{packet}", Counter, "Packets received and transmitted per interface.";
    NetErrors => "system.network.errors", "{error}", Counter, "Receive and transmit errors per interface.";
    NetDropped => "system.network.dropped", "{packet}", Counter, "Packets dropped on input and output queues per interface.";
    FsUsage => "system.filesystem.usage", "By", UpDown, "Filesystem space used, free and reserved.";
    FsUtilization => "system.filesystem.utilization", "1", Gauge, "Fraction of filesystem space used.";
    Uptime => "system.uptime", "s", Gauge, "Seconds since boot.";
    ProcCpu => "process.cpu.utilization", "1", Gauge, "CPU used by the busiest processes, as a fraction of one CPU.";
    ProcCpuTime => "process.cpu.time", "s", Counter, "User and system CPU time of the busiest processes.";
    ProcMem => "process.memory.usage", "By", UpDown, "Resident set size of the busiest processes.";
    ProcVirt => "process.memory.virtual", "By", UpDown, "Virtual size of the busiest processes.";
    ProcDiskOps => "process.disk.operations", "{operation}", Counter, "Block I/O operations of the busiest processes.";
    TcpConnections => "system.network.connections", "{connection}", UpDown, "TCP connections by state.";
    TcpSegments => "freebsd.tcp.segments", "{segment}", Counter, "TCP segments sent and received.";
    TcpRetransmits => "freebsd.tcp.retransmitted_segments", "{segment}", Counter, "TCP data segments retransmitted.";
    TcpListenDrops => "freebsd.tcp.listen_queue_overflows", "{connection}", Counter, "Connections dropped because a listen queue was full.";
    TcpAccepts => "freebsd.tcp.accepts", "{connection}", Counter, "Inbound TCP connections accepted.";
    TcpConnAttempts => "freebsd.tcp.connect_attempts", "{connection}", Counter, "Outbound TCP connections initiated.";
    UdpDatagrams => "freebsd.udp.datagrams", "{datagram}", Counter, "UDP datagrams sent and received.";
    UdpErrors => "freebsd.udp.errors", "{error}", Counter, "UDP packets dropped due to header or checksum errors.";
    UdpDropped => "freebsd.udp.dropped", "{datagram}", Counter, "UDP datagrams dropped (no socket or full buffer).";
    CpuTemp => "hw.temperature", "Cel", Gauge, "Temperature of each CPU core and ACPI thermal zone.";
    CpuFreq => "system.cpu.frequency", "Hz", Gauge, "Current clock frequency of each CPU that reports one.";
    Threads => "freebsd.threads.count", "{thread}", UpDown, "Threads by scheduling state (vmstat's r/b/w).";
    VmFaults => "freebsd.vm.faults", "{fault}", Counter, "Page faults by type.";
    VmPagerOps => "freebsd.vm.pager.operations", "{operation}", Counter, "Swap and vnode pager operations.";
    VmPagerPages => "freebsd.vm.pager.pages", "{page}", Counter, "Pages moved by the swap and vnode pagers.";
    VmReactivated => "freebsd.vm.reactivated_pages", "{page}", Counter, "Pages reactivated from the inactive queue.";
    VmFreed => "freebsd.vm.freed_pages", "{page}", Counter, "Pages freed.";
    VmPageoutScanned => "freebsd.vm.pageout.scanned_pages", "{page}", Counter, "Pages examined by the page daemon.";
    VmPageoutWakeups => "freebsd.vm.pageout.wakeups", "{wakeup}", Counter, "Page daemon wakeups.";
    Superpages => "freebsd.vm.superpage.operations", "{operation}", Counter, "Superpage mappings, promotions, demotions and failed promotions.";
    NfsClientOps => "freebsd.nfs.client.operations", "{operation}", Counter, "NFS client operations by type.";
    NfsServerOps => "freebsd.nfs.server.operations", "{operation}", Counter, "NFS server operations by type.";
    NfsRetries => "freebsd.nfs.client.rpc.retries", "{retry}", Counter, "NFS client RPC retries.";
    NfsTimeouts => "freebsd.nfs.client.rpc.timeouts", "{timeout}", Counter, "NFS client RPC timeouts.";
    ProcFaults => "process.paging.faults", "{fault}", Counter, "Page faults of the busiest processes.";
    BatteryCharge => "hw.battery.charge", "1", Gauge, "Remaining battery charge.";
    BatteryTime => "hw.battery.time_left", "s", Gauge, "Estimated battery time remaining while discharging.";
    JailCpu => "freebsd.jail.cpu.utilization", "1", Gauge, "CPU used by each jail's processes, as a fraction of one CPU.";
    JailMem => "freebsd.jail.memory.usage", "By", UpDown, "Resident memory of each jail's processes.";
    JailProcs => "freebsd.jail.process.count", "{process}", UpDown, "Processes in each jail.";
    JailIo => "freebsd.jail.io.operations", "{operation}", Gauge, "Block I/O operations per second of each jail's processes.";
    VmCpu => "freebsd.bhyve.cpu.utilization", "1", Gauge, "CPU used by each bhyve VM, as a fraction of one CPU.";
    VmMem => "freebsd.bhyve.memory.usage", "By", UpDown, "Resident memory of each bhyve VM process.";
    ArcTarget => "freebsd.zfs.arc.target_size", "By", UpDown, "ZFS ARC target size (c).";
    ArcHits => "freebsd.zfs.arc.hits", "{hit}", Counter, "ZFS ARC hits.";
    ArcMisses => "freebsd.zfs.arc.misses", "{miss}", Counter, "ZFS ARC misses.";
    ArcHitRatio => "freebsd.zfs.arc.hit_ratio", "1", Gauge, "ZFS ARC hit ratio over the last interval.";
    L2Size => "freebsd.zfs.l2arc.size", "By", UpDown, "ZFS L2ARC size.";
    PoolUsage => "freebsd.zfs.pool.usage", "By", UpDown, "ZFS pool space allocated and free.";
    PoolFrag => "freebsd.zfs.pool.fragmentation", "1", Gauge, "ZFS pool free-space fragmentation.";
    PoolHealth => "freebsd.zfs.pool.health", "1", UpDown, "1 for each pool, labelled with its health state.";
    PoolIo => "freebsd.zfs.pool.io", "By", Counter, "Logical bytes read and written per pool.";
    PoolOps => "freebsd.zfs.pool.operations", "{operation}", Counter, "Logical read and write operations per pool.";
    SelfCollect => "jmon.collection.duration", "s", Gauge, "Time jmon took to collect the last sample.";
    SelfExports => "jmon.otlp.exports", "{export}", Counter, "OTLP export attempts by result.";
    SelfScrapes => "jmon.prometheus.scrapes", "{scrape}", Counter, "Prometheus scrapes served.";
}

struct Builder(Families);

impl Builder {
    fn add(&mut self, m: M, attrs: Attrs, value: f64) {
        self.0[m as usize].push(Point { attrs, value });
    }
}

/// Builds every family from one sample. Rate-based gauges are empty until a
/// second snapshot exists. `top_procs` > 0 adds per-process series.
pub fn collect(s: &Sample, top_procs: usize, stats: &SelfStats) -> Families {
    let mut b = Builder(vec![Vec::new(); CATALOG.len()]);
    let snap = &s.snap;
    let hz = snap.stathz.max(1) as f64;

    for (i, c) in snap.cpus.iter().enumerate() {
        for (mode, ticks) in c.modes() {
            let attrs = vec![("cpu.logical_number", Val::Int(i as i64)), ("cpu.mode", mode.into())];
            b.add(M::CpuTime, attrs, ticks as f64 / hz);
        }
    }
    b.add(M::CpuCount, vec![], snap.cpus.len() as f64);
    b.add(M::Load1, vec![], snap.load[0]);
    b.add(M::Load5, vec![], snap.load[1]);
    b.add(M::Load15, vec![], snap.load[2]);

    let mem = &snap.memory;
    let total = mem.total.max(1) as f64;
    for (state, v) in [
        ("active", mem.active),
        ("inactive", mem.inactive),
        ("laundry", mem.laundry),
        ("wired", mem.wired),
        ("free", mem.free),
    ] {
        b.add(M::MemUsage, vec![("system.memory.state", state.into())], v as f64);
        b.add(M::MemUtilization, vec![("system.memory.state", state.into())], v as f64 / total);
    }
    b.add(M::MemLimit, vec![], mem.total as f64);
    if let Some(arc) = mem.arc {
        b.add(M::ZfsArc, vec![], arc as f64);
    }

    for sw in &snap.swap {
        let free = sw.total.saturating_sub(sw.used);
        for (state, v) in [("used", sw.used), ("free", free)] {
            let attrs = || vec![("system.device", sw.name.clone().into()), ("system.paging.state", state.into())];
            b.add(M::PagingUsage, attrs(), v as f64);
            if sw.total > 0 {
                b.add(M::PagingUtilization, attrs(), v as f64 / sw.total as f64);
            }
        }
    }
    let vm = &snap.vm;
    b.add(M::PagingOps, vec![("system.paging.direction", "in".into())], vm.swap_pages_in as f64);
    b.add(M::PagingOps, vec![("system.paging.direction", "out".into())], vm.swap_pages_out as f64);
    b.add(M::ContextSwitches, vec![], vm.context_switches as f64);
    b.add(M::Interrupts, vec![], vm.interrupts as f64);
    b.add(M::Syscalls, vec![], vm.syscalls as f64);
    b.add(M::Traps, vec![], vm.traps as f64);
    b.add(M::PageFaults, vec![], vm.faults as f64);
    b.add(M::ProcCreated, vec![], vm.forks as f64);
    let rq = &snap.runq;
    for (state, n) in [("runnable", rq.runnable), ("disk_wait", rq.disk_wait), ("page_wait", rq.page_wait), ("sleeping", rq.sleeping)] {
        b.add(M::Threads, vec![("freebsd.thread.state", state.into())], n as f64);
    }
    for (kind, n) in [("zero_fill", vm.zero_fill_faults), ("copy_on_write", vm.cow_faults), ("in_transit", vm.intransit_faults)] {
        b.add(M::VmFaults, vec![("freebsd.vm.fault_type", kind.into())], n as f64);
    }
    for (pager, dir, ops, pages) in [
        ("swap", "in", vm.swap_ins, vm.swap_pages_in),
        ("swap", "out", vm.swap_outs, vm.swap_pages_out),
        ("vnode", "in", vm.vnode_ins, vm.vnode_pages_in),
        ("vnode", "out", vm.vnode_outs, vm.vnode_pages_out),
    ] {
        let attrs = || vec![("freebsd.vm.pager", Val::from(pager)), ("system.paging.direction", Val::from(dir))];
        b.add(M::VmPagerOps, attrs(), ops as f64);
        b.add(M::VmPagerPages, attrs(), pages as f64);
    }
    b.add(M::VmReactivated, vec![], vm.reactivated as f64);
    b.add(M::VmFreed, vec![], vm.pages_freed as f64);
    b.add(M::VmPageoutScanned, vec![], vm.pageout_scanned as f64);
    b.add(M::VmPageoutWakeups, vec![], vm.pageout_wakeups as f64);
    if let Some(sp) = &snap.superpages {
        for (op, n) in [("mapping", sp.mappings), ("promotion", sp.promotions), ("demotion", sp.demotions), ("failed_promotion", sp.failures)] {
            b.add(M::Superpages, vec![("freebsd.vm.superpage.operation", op.into())], n as f64);
        }
    }
    if let Some(nfs) = &snap.nfs {
        for (op, n) in &nfs.client_ops {
            b.add(M::NfsClientOps, vec![("nfs.operation", Val::from(op.clone()))], *n as f64);
        }
        for (op, n) in &nfs.server_ops {
            b.add(M::NfsServerOps, vec![("nfs.operation", Val::from(op.clone()))], *n as f64);
        }
        b.add(M::NfsRetries, vec![], nfs.client_retries as f64);
        b.add(M::NfsTimeouts, vec![], nfs.client_timeouts as f64);
    }

    let mut states: Vec<(&'static str, u64)> = Vec::new();
    for p in &snap.processes {
        match states.iter_mut().find(|(s, _)| *s == p.state) {
            Some((_, n)) => *n += 1,
            None => states.push((p.state, 1)),
        }
    }
    for (state, n) in states {
        b.add(M::ProcCount, vec![("process.state", state.into())], n as f64);
    }

    for d in &snap.disks {
        let dev = || ("system.device", Val::from(d.name.clone()));
        b.add(M::DiskPending, vec![dev()], d.queue as f64);
        let dir = |x: &str| ("disk.io.direction", Val::from(x));
        b.add(M::DiskIo, vec![dev(), dir("read")], d.read_bytes as f64);
        b.add(M::DiskIo, vec![dev(), dir("write")], d.write_bytes as f64);
        b.add(M::DiskOps, vec![dev(), dir("read")], d.read_ops as f64);
        b.add(M::DiskOps, vec![dev(), dir("write")], d.write_ops as f64);
        b.add(M::DiskOpTime, vec![dev(), dir("read")], d.read_secs);
        b.add(M::DiskOpTime, vec![dev(), dir("write")], d.write_secs);
        b.add(M::DiskIoTime, vec![dev()], d.busy_secs);
    }

    for n in &snap.nets {
        let ifc = || ("network.interface.name", Val::from(n.name.clone()));
        let rx = || ("network.io.direction", Val::from("receive"));
        let tx = || ("network.io.direction", Val::from("transmit"));
        b.add(M::NetIo, vec![ifc(), rx()], n.rx_bytes as f64);
        b.add(M::NetIo, vec![ifc(), tx()], n.tx_bytes as f64);
        b.add(M::NetPackets, vec![ifc(), rx()], n.rx_packets as f64);
        b.add(M::NetPackets, vec![ifc(), tx()], n.tx_packets as f64);
        b.add(M::NetErrors, vec![ifc(), rx()], n.rx_errors as f64);
        b.add(M::NetErrors, vec![ifc(), tx()], n.tx_errors as f64);
        b.add(M::NetDropped, vec![ifc(), rx()], n.rx_drops as f64);
        b.add(M::NetDropped, vec![ifc(), tx()], n.tx_drops as f64);
    }

    for f in &snap.filesystems {
        let attrs = |state: &str| {
            vec![
                ("system.device", Val::from(f.device.clone())),
                ("system.filesystem.mountpoint", Val::from(f.mountpoint.clone())),
                ("system.filesystem.type", Val::from(f.fstype.clone())),
                ("system.filesystem.state", Val::from(state)),
            ]
        };
        let reserved = f.free.saturating_sub(f.avail);
        b.add(M::FsUsage, attrs("used"), f.used() as f64);
        b.add(M::FsUsage, attrs("free"), f.avail as f64);
        b.add(M::FsUsage, attrs("reserved"), reserved as f64);
        if f.total > 0 {
            let mut a = attrs("used");
            a.pop();
            b.add(M::FsUtilization, a, f.used() as f64 / f.total as f64);
        }
    }

    b.add(M::Uptime, vec![], snap.uptime);

    if let Some(t) = &snap.tcp {
        let tcp = || ("network.transport", Val::from("tcp"));
        for (state, n) in &t.states {
            b.add(M::TcpConnections, vec![tcp(), ("network.connection.state", (*state).into())], *n as f64);
        }
        b.add(M::TcpSegments, vec![("network.io.direction", "transmit".into())], t.segs_sent as f64);
        b.add(M::TcpSegments, vec![("network.io.direction", "receive".into())], t.segs_received as f64);
        b.add(M::TcpRetransmits, vec![], t.retransmits as f64);
        b.add(M::TcpListenDrops, vec![], t.listen_drops as f64);
        b.add(M::TcpAccepts, vec![], t.accepts as f64);
        b.add(M::TcpConnAttempts, vec![], t.conn_attempts as f64);
    }

    if let Some(u) = &snap.udp {
        b.add(M::UdpDatagrams, vec![("network.io.direction", "receive".into())], u.datagrams_in as f64);
        b.add(M::UdpDatagrams, vec![("network.io.direction", "transmit".into())], u.datagrams_out as f64);
        b.add(M::UdpErrors, vec![], u.in_errors as f64);
        b.add(M::UdpDropped, vec![("freebsd.udp.drop_reason", "no_port".into())], u.no_ports as f64);
        b.add(M::UdpDropped, vec![("freebsd.udp.drop_reason", "full_buffer".into())], u.full_socket_buffers as f64);
    }

    let sensors = &snap.sensors;
    for (i, mhz) in sensors.cpu_freqs_mhz.iter().enumerate() {
        b.add(M::CpuFreq, vec![("cpu.logical_number", Val::Int(i as i64))], *mhz as f64 * 1e6);
    }
    for (i, t) in sensors.cpu_temps.iter().enumerate() {
        let attrs = vec![("hw.id", Val::from(format!("cpu{i}"))), ("hw.type", "cpu".into())];
        b.add(M::CpuTemp, attrs, *t);
    }
    for (name, t) in &sensors.thermal_zones {
        b.add(M::CpuTemp, vec![("hw.id", Val::from(name.clone())), ("hw.type", "thermal_zone".into())], *t);
    }
    if let Some(mhz) = sensors.cpu_freq_mhz
        && sensors.cpu_freqs_mhz.is_empty()
    {
        b.add(M::CpuFreq, vec![], mhz as f64 * 1e6);
    }
    if let Some(bat) = &sensors.battery {
        let attrs = || vec![("hw.id", Val::from("battery0")), ("hw.battery.state", Val::from(bat.state))];
        b.add(M::BatteryCharge, attrs(), bat.life / 100.0);
        if let Some(m) = bat.minutes_left {
            b.add(M::BatteryTime, attrs(), m as f64 * 60.0);
        }
    }

    if let Some(z) = &snap.zfs {
        b.add(M::ArcTarget, vec![], z.arc_target as f64);
        b.add(M::ArcHits, vec![], z.arc_hits as f64);
        b.add(M::ArcMisses, vec![], z.arc_misses as f64);
        if z.l2_size > 0 {
            b.add(M::L2Size, vec![], z.l2_size as f64);
        }
        for p in &z.pools {
            let pool = || ("zfs.pool.name", Val::from(p.name.clone()));
            b.add(M::PoolUsage, vec![pool(), ("zfs.pool.state", "allocated".into())], p.allocated as f64);
            b.add(M::PoolUsage, vec![pool(), ("zfs.pool.state", "free".into())], p.free as f64);
            if let Some(f) = p.fragmentation {
                b.add(M::PoolFrag, vec![pool()], f as f64 / 100.0);
            }
            b.add(M::PoolHealth, vec![pool(), ("zfs.pool.health", Val::from(p.health.clone()))], 1.0);
            let dir = |d: &str| ("disk.io.direction", Val::from(d));
            b.add(M::PoolIo, vec![pool(), dir("read")], p.read_bytes as f64);
            b.add(M::PoolIo, vec![pool(), dir("write")], p.write_bytes as f64);
            b.add(M::PoolOps, vec![pool(), dir("read")], p.read_ops as f64);
            b.add(M::PoolOps, vec![pool(), dir("write")], p.write_ops as f64);
        }
    }

    b.add(M::SelfCollect, vec![], s.collect_secs);
    let ok = stats.export_ok.load(Ordering::Relaxed);
    let failed = stats.export_failed.load(Ordering::Relaxed);
    if ok + failed > 0 {
        b.add(M::SelfExports, vec![("result", "success".into())], ok as f64);
        b.add(M::SelfExports, vec![("result", "failure".into())], failed as f64);
    }
    let scrapes = stats.scrapes.load(Ordering::Relaxed);
    if scrapes > 0 {
        b.add(M::SelfScrapes, vec![], scrapes as f64);
    }

    if let Some(r) = &s.rates {
        for (i, u) in r.cpus.iter().enumerate() {
            for (mode, v) in u.modes() {
                let attrs = vec![("cpu.logical_number", Val::Int(i as i64)), ("cpu.mode", mode.into())];
                b.add(M::CpuUtilization, attrs, v);
            }
        }
        for (d, rate) in snap.disks.iter().zip(&r.disks) {
            b.add(M::DiskBusy, vec![("system.device", d.name.clone().into())], rate.busy);
            for (dir, ms) in [("read", rate.read_ms), ("write", rate.write_ms)] {
                let attrs = vec![("system.device", d.name.clone().into()), ("disk.io.direction", dir.into())];
                b.add(M::DiskLatency, attrs, ms / 1000.0);
            }
        }
        for j in &r.jails {
            let attrs = || vec![("freebsd.jail.id", Val::Int(j.id)), ("freebsd.jail.name", Val::from(j.name.clone()))];
            b.add(M::JailCpu, attrs(), j.cpu / 100.0);
            b.add(M::JailMem, attrs(), j.rss as f64);
            b.add(M::JailProcs, attrs(), j.processes as f64);
            b.add(M::JailIo, attrs(), j.io);
        }
        for v in &r.vms {
            let attrs = || vec![("freebsd.bhyve.vm.name", Val::from(v.name.clone()))];
            b.add(M::VmCpu, attrs(), v.cpu / 100.0);
            b.add(M::VmMem, attrs(), v.rss as f64);
        }
        if let Some(ratio) = r.zfs.as_ref().and_then(|z| z.arc_hit_ratio) {
            b.add(M::ArcHitRatio, vec![], ratio);
        }
        if top_procs > 0 {
            for i in s.procs_by_cpu().into_iter().take(top_procs) {
                let p = &snap.processes[i];
                let attrs = || {
                    vec![
                        ("process.pid", Val::Int(p.pid as i64)),
                        ("process.executable.name", Val::from(p.command.clone())),
                        ("process.owner", Val::from(p.user.clone())),
                    ]
                };
                b.add(M::ProcCpu, attrs(), r.proc_cpu[i] / 100.0);
                for (mode, us) in [("user", p.user_time_us), ("system", p.sys_time_us)] {
                    let mut a = attrs();
                    a.push(("cpu.mode", mode.into()));
                    b.add(M::ProcCpuTime, a, us as f64 / 1e6);
                }
                b.add(M::ProcMem, attrs(), p.rss as f64);
                b.add(M::ProcVirt, attrs(), p.vsize as f64);
                let mut a = attrs();
                a.push(("disk.io.direction", "read".into()));
                b.add(M::ProcDiskOps, a, p.read_ops as f64);
                let mut a = attrs();
                a.push(("disk.io.direction", "write".into()));
                b.add(M::ProcDiskOps, a, p.write_ops as f64);
                for (kind, n) in [("minor", p.minor_faults), ("major", p.major_faults)] {
                    let mut a = attrs();
                    a.push(("process.paging.fault_type", kind.into()));
                    b.add(M::ProcFaults, a, n as f64);
                }
            }
        }
    }
    b.0
}

/// Returns `base` with `SelfExports` and `SelfScrapes` updated from live atomics.
pub fn with_live_self_stats(base: Arc<Families>, stats: &SelfStats) -> Arc<Families> {
    let ok = stats.export_ok.load(Ordering::Relaxed);
    let failed = stats.export_failed.load(Ordering::Relaxed);
    let scrapes = stats.scrapes.load(Ordering::Relaxed);
    let cur_scrapes = base[M::SelfScrapes as usize].first().map_or(0, |p| p.value as u64);
    let cur_ok = base[M::SelfExports as usize].first().map_or(0, |p| p.value as u64);
    let cur_failed = base[M::SelfExports as usize].get(1).map_or(0, |p| p.value as u64);
    if scrapes == cur_scrapes && ok == cur_ok && failed == cur_failed {
        return base;
    }
    let mut fams = (*base).clone();
    fams[M::SelfExports as usize].clear();
    if ok + failed > 0 {
        fams[M::SelfExports as usize].push(Point { attrs: vec![("result", "success".into())], value: ok as f64 });
        fams[M::SelfExports as usize].push(Point { attrs: vec![("result", "failure".into())], value: failed as f64 });
    }
    fams[M::SelfScrapes as usize].clear();
    if scrapes > 0 {
        fams[M::SelfScrapes as usize].push(Point { attrs: vec![], value: scrapes as f64 });
    }
    Arc::new(fams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_names_unique() {
        let mut names: Vec<_> = CATALOG.iter().map(|d| d.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), CATALOG.len());
    }

    #[test]
    fn enum_matches_catalog() {
        assert_eq!(CATALOG[M::CpuTime as usize].name, "system.cpu.time");
        assert_eq!(CATALOG[M::ProcVirt as usize].name, "process.memory.virtual");
    }
}
