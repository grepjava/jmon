//! Synthetic data for non-FreeBSD builds. Counters advance smoothly with a
//! little noise so every panel and exporter has something plausible to show.

use crate::model::*;
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

const NCPU: usize = 4;
const GIB: u64 = 1 << 30;
const STATHZ: u32 = 127;

pub struct Collector {
    host: Arc<HostInfo>,
    start: Instant,
    last: Instant,
    rng: u64,
    cpus: Vec<CpuTicks>,
    vm: VmCounters,
    disks: Vec<Disk>,
    nets: Vec<NetIf>,
    procs: Vec<Process>,
    tcp: Tcp,
    zfs: Zfs,
    superpages: Superpages,
    nfs: Nfs,
}

impl Collector {
    pub fn new() -> Result<Self> {
        let host = HostInfo {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "demo".into()),
            os_type: "freebsd".into(),
            os_release: "14.3-RELEASE (demo)".into(),
            machine: "amd64".into(),
            cpu_model: "Synthetic CPU @ 3.00GHz".into(),
            ncpu: NCPU,
            physmem: 16 * GIB,
            pagesize: 4096,
            demo: true,
        };
        let disk = |n: &str| Disk { name: n.into(), ..Default::default() };
        let net = |n: &str, mtu| NetIf { name: n.into(), up: true, mtu, baudrate: 1_000_000_000, ..Default::default() };
        let procs = [
            (1, 0, "init", 0, "/sbin/init"),
            (12, 0, "intr", 0, "[intr]"),
            (450, 0, "syslogd", 0, "/usr/sbin/syslogd -s"),
            (812, 0, "sshd", 0, "sshd: /usr/sbin/sshd [listener]"),
            (1201, 80, "nginx", 1, "nginx: worker process"),
            (1202, 80, "nginx", 1, "nginx: worker process"),
            (2210, 770, "postgres", 2, "postgres: checkpointer"),
            (2211, 770, "postgres", 2, "postgres: app appdb 10.0.0.5(51234) idle"),
            (3300, 1001, "cc1plus", 0, "/usr/local/libexec/gcc13/cc1plus -quiet main.cpp -O2"),
            (3301, 1001, "make", 0, "make -j8 buildworld"),
            (4100, 0, "zfskern", 0, "[zfskern]"),
            (5200, 0, "bhyve", 0, "bhyve: debian12"),
        ]
        .into_iter()
        .map(|(pid, uid, cmd, jid, args)| Process {
            pid,
            ppid: 1,
            uid,
            jid,
            args: args.into(),
            user: match uid {
                0 => "root",
                80 => "www",
                770 => "postgres",
                _ => "grepjava",
            }
            .into(),
            command: cmd.into(),
            state: "sleeping",
            threads: 1,
            ..Default::default()
        })
        .collect();
        let now = Instant::now();
        Ok(Collector {
            host: Arc::new(host),
            start: now,
            last: now,
            rng: 0x2545_f491_4f6c_dd1d,
            cpus: vec![CpuTicks::default(); NCPU],
            vm: VmCounters::default(),
            disks: vec![disk("nda0"), disk("ada0"), disk("da0")],
            nets: vec![net("em0", 1500), net("lo0", 16384)],
            procs,
            tcp: Tcp::default(),
            superpages: Superpages { enabled: true, ..Default::default() },
            nfs: Nfs {
                client_ops: ["getattr", "lookup", "read", "write", "access", "readdir"]
                    .iter()
                    .map(|o| (o.to_string(), 0))
                    .collect(),
                server_ops: ["getattr", "read", "write"].iter().map(|o| (o.to_string(), 0)).collect(),
                ..Default::default()
            },
            zfs: Zfs {
                arc_max: 8 * GIB,
                l2_size: 0,
                pools: vec![ZPool {
                    name: "zroot".into(),
                    health: "ONLINE".into(),
                    size: 460 * GIB,
                    allocated: 140 * GIB,
                    free: 320 * GIB,
                    fragmentation: Some(12),
                    ..Default::default()
                }],
                ..Default::default()
            },
        })
    }

    pub fn host(&self) -> Arc<HostInfo> {
        self.host.clone()
    }

    fn noise(&mut self) -> f64 {
        // xorshift64*: deterministic, dependency-free jitter in [0, 1).
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn collect(&mut self) -> Snapshot {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        let t = now.duration_since(self.start).as_secs_f64();
        self.last = now;
        let ticks = dt * STATHZ as f64;

        for i in 0..NCPU {
            let wave = 0.5 + 0.45 * ((t / 20.0) + i as f64).sin();
            let busy = (wave * 0.8 + self.noise() * 0.2).clamp(0.0, 1.0);
            let c = &mut self.cpus[i];
            c.user += (ticks * busy * 0.65) as u64;
            c.nice += (ticks * busy * 0.05) as u64;
            c.system += (ticks * busy * 0.25) as u64;
            c.interrupt += (ticks * busy * 0.05) as u64;
            c.idle += (ticks * (1.0 - busy)) as u64;
        }

        let rate = |base: f64, n: f64| (base * dt * (0.5 + n)) as u64;
        let n = self.noise();
        self.vm.context_switches += rate(25_000.0, n);
        self.vm.interrupts += rate(9_000.0, n);
        self.vm.syscalls += rate(60_000.0, n);
        self.vm.traps += rate(4_000.0, n);
        self.vm.forks += rate(12.0, n);
        self.vm.faults += rate(3_000.0, n);
        self.vm.zero_fill_faults += rate(1_800.0, n);
        self.vm.cow_faults += rate(400.0, n);
        self.vm.vnode_ins += rate(30.0, n);
        self.vm.vnode_pages_in += rate(240.0, n);
        self.vm.vnode_outs += rate(5.0, n);
        self.vm.vnode_pages_out += rate(40.0, n);
        self.vm.reactivated += rate(60.0, n);
        self.vm.pages_freed += rate(2_000.0, n);
        self.vm.pageout_scanned += rate(500.0, n);
        self.superpages.mappings += rate(20.0, n);
        self.superpages.promotions += rate(8.0, n);
        self.superpages.demotions += rate(6.0, n);
        self.superpages.failures += rate(15.0, n);
        for (_, v) in &mut self.nfs.client_ops {
            *v += rate(40.0, n);
        }
        self.nfs.client_requests += rate(320.0, n);
        for (_, v) in &mut self.nfs.server_ops {
            *v += rate(10.0, n);
        }

        for i in 0..self.disks.len() {
            let n = self.noise();
            let scale = [80e6, 20e6, 2e6][i];
            let d = &mut self.disks[i];
            let rb = (scale * dt * n) as u64;
            let wb = (scale * 0.6 * dt * (1.0 - n)) as u64;
            d.read_bytes += rb;
            d.write_bytes += wb;
            d.read_ops += rb / 65536 + 1;
            d.write_ops += wb / 32768 + 1;
            let busy = (n * 0.9).min(1.0) * dt;
            d.busy_secs += busy;
            d.read_secs += busy * 0.6;
            d.write_secs += busy * 0.5;
            d.queue = (n * 6.0) as u64;
        }
        for i in 0..self.nets.len() {
            let n = self.noise();
            let scale = [12e6, 1e6][i];
            let d = &mut self.nets[i];
            let rx = (scale * dt * n) as u64;
            let tx = (scale * 0.4 * dt * (0.5 + n)) as u64;
            d.rx_bytes += rx;
            d.tx_bytes += tx;
            d.rx_packets += rx / 900;
            d.tx_packets += tx / 700;
        }
        for i in 0..self.procs.len() {
            let n = self.noise();
            let weight = [0.001, 0.02, 0.001, 0.005, 0.1, 0.08, 0.3, 0.25, 0.9, 0.05, 0.04, 0.6][i];
            let p = &mut self.procs[i];
            p.cpu_time_us += (dt * 1e6 * weight * (0.5 + n)) as u64;
            p.read_ops += (dt * 200.0 * weight * n) as u64;
            p.write_ops += (dt * 120.0 * weight * (1.0 - n)) as u64;
            p.minor_faults += (dt * 900.0 * weight * n) as u64;
            p.major_faults += (dt * 4.0 * weight * n) as u64;
            p.rss = ((weight * 900.0 + 8.0) * 1048576.0) as u64;
            p.vsize = p.rss * 3;
            p.state = if weight * (0.5 + n) > 0.2 { "running" } else { "sleeping" };
        }

        let n = self.noise();
        let tcp = &mut self.tcp;
        tcp.conn_attempts += rate(5.0, n);
        tcp.accepts += rate(40.0, n);
        tcp.segs_sent += rate(9_000.0, n);
        tcp.segs_received += rate(11_000.0, n);
        tcp.retransmits += rate(12.0, n);
        tcp.listen_drops += if n > 0.95 { 1 } else { 0 };
        tcp.states = vec![("listen", 12), ("established", 140 + (n * 20.0) as u64), ("time_wait", 35), ("close_wait", 2)];

        let z = &mut self.zfs;
        z.arc_hits += rate(20_000.0, n);
        z.arc_misses += rate(600.0, 1.0 - n);
        for pool in &mut z.pools {
            pool.read_bytes += rate(40e6, n);
            pool.write_bytes += rate(15e6, n);
            pool.read_ops += rate(900.0, n);
            pool.write_ops += rate(300.0, n);
        }

        let arc = 5 * GIB + (GIB as f64 * (t / 60.0).sin().abs()) as u64;
        let total = self.host.physmem;
        let wired = 2 * GIB + arc;
        let active = 3 * GIB + (GIB as f64 * (t / 30.0).sin().abs()) as u64;
        let inactive = 2 * GIB;
        let laundry = 128 << 20;
        Snapshot {
            taken: now,
            timestamp: unix_now(),
            uptime: 86_400.0 * 3.0 + t,
            stathz: STATHZ,
            cpus: self.cpus.clone(),
            load: [1.2 + (t / 30.0).sin().abs(), 1.1, 0.9],
            memory: Memory {
                total,
                active,
                inactive,
                laundry,
                wired,
                free: total.saturating_sub(active + inactive + laundry + wired),
                arc: Some(arc),
            },
            swap: vec![SwapDev { name: "/dev/nda0p3".into(), total: 4 * GIB, used: 96 << 20 }],
            vm: self.vm,
            runq: RunQueue { runnable: 3 + (n * 4.0) as u64, disk_wait: (n * 2.0) as u64, page_wait: 0, sleeping: 54 },
            superpages: Some(self.superpages),
            partitions: self
                .disks
                .iter()
                .take(2)
                .flat_map(|d| {
                    (1..=2).map(move |i| Disk {
                        name: format!("{}p{i}", d.name),
                        read_bytes: d.read_bytes / (i * 2),
                        write_bytes: d.write_bytes / (i * 2),
                        read_ops: d.read_ops / (i * 2),
                        write_ops: d.write_ops / (i * 2),
                        busy_secs: d.busy_secs / i as f64,
                        read_secs: d.read_secs / i as f64,
                        write_secs: d.write_secs / i as f64,
                        queue: d.queue / i,
                    })
                })
                .collect(),
            disks: self.disks.clone(),
            nets: self.nets.clone(),
            filesystems: vec![
                Filesystem {
                    device: "zroot/ROOT/default".into(),
                    mountpoint: "/".into(),
                    fstype: "zfs".into(),
                    total: 400 * GIB,
                    free: 260 * GIB,
                    avail: 260 * GIB,
                },
                Filesystem {
                    device: "/dev/ada0p1".into(),
                    mountpoint: "/data".into(),
                    fstype: "ufs".into(),
                    total: 900 * GIB,
                    free: 120 * GIB,
                    avail: 48 * GIB,
                },
            ],
            processes: self.procs.clone(),
            sensors: Sensors {
                cpu_temps: (0..NCPU).map(|i| 48.0 + 6.0 * ((t / 15.0) + i as f64).sin()).collect(),
                cpu_tjmax: Some(100.0),
                cpu_freq_mhz: Some(2400 + (600.0 * (t / 10.0).sin()) as u64),
                cpu_freqs_mhz: (0..NCPU).map(|i| 2400 + (600.0 * ((t / 10.0) + i as f64).sin()) as u64).collect(),
                thermal_zones: vec![("tz0".into(), 41.0)],
                battery: Some(Battery { life: 87.0, minutes_left: Some(212), state: "discharging", ac_online: false }),
            },
            tcp: Some(self.tcp.clone()),
            jails: vec![
                Jail { jid: 1, name: "www".into(), hostname: "www.example.org".into() },
                Jail { jid: 2, name: "db".into(), hostname: "db.example.org".into() },
            ],
            zfs: Some(Zfs { arc_size: arc, arc_target: arc + GIB / 2, ..self.zfs.clone() }),
            nfs: Some(self.nfs.clone()),
        }
    }
}
