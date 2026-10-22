//! Capture files: nmon's CSV format (readable by nmon analyser / nmonchart)
//! and JSON Lines for everything else.

use crate::model::{DiskGroup, HostInfo};
use crate::sample::{Sample, Sink, group_rates};
use chrono::{DateTime, Local, NaiveDate, TimeZone};
use clap::ValueEnum;
use std::collections::HashSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Nmon,
    Jsonl,
}

pub fn open(path: &str) -> io::Result<Box<dyn Write + Send>> {
    if path == "-" {
        Ok(Box::new(io::LineWriter::new(io::stdout())))
    } else {
        Ok(Box::new(io::BufWriter::new(std::fs::File::create(path)?)))
    }
}

impl Format {
    fn ext(self) -> &'static str {
        match self {
            Format::Nmon => "nmon",
            Format::Jsonl => "jsonl",
        }
    }
}

fn short_host(host: &HostInfo) -> &str {
    host.hostname.split('.').next().unwrap_or("host")
}

/// nmon -f style name: <host>_<YYMMDD>_<HHMM>.<ext>
pub fn auto_name(host: &HostInfo, format: Format) -> String {
    format!("{}_{}.{}", short_host(host), Local::now().format("%y%m%d_%H%M"), format.ext())
}

/// Settings for `-f` recordings.
pub struct RecordSettings {
    pub dir: PathBuf,
    pub format: Format,
    pub interval: f64,
    pub count: Option<u64>,
    pub rotate: bool,
    pub keep_days: Option<u64>,
    pub groups: Vec<DiskGroup>,
}

/// `-f` recording: auto-named files in a directory, optionally rotated at
/// local midnight with old files pruned.
pub struct Recorder {
    cfg: RecordSettings,
    host: Arc<HostInfo>,
    day: NaiveDate,
    path: PathBuf,
    inner: Box<dyn Sink>,
}

impl Recorder {
    pub fn new(cfg: RecordSettings, host: Arc<HostInfo>) -> io::Result<Self> {
        std::fs::create_dir_all(&cfg.dir)?;
        let (path, inner) = Self::open_new(&cfg, &host)?;
        let r = Recorder {
            cfg,
            host,
            day: Local::now().date_naive(),
            path,
            inner,
        };
        r.prune();
        Ok(r)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_new(cfg: &RecordSettings, host: &HostInfo) -> io::Result<(PathBuf, Box<dyn Sink>)> {
        let path = cfg.dir.join(auto_name(host, cfg.format));
        let out = io::BufWriter::new(std::fs::File::create(&path)?);
        let sink: Box<dyn Sink> = match cfg.format {
            Format::Nmon => Box::new(Nmon::new(out, cfg.interval, cfg.count, cfg.groups.clone())),
            Format::Jsonl => Box::new(JsonLines::new(out)),
        };
        Ok((path, sink))
    }

    /// Deletes this host's recordings older than `keep_days`.
    fn prune(&self) {
        let (Some(days), true) = (self.cfg.keep_days, self.cfg.rotate) else { return };
        let prefix = format!("{}_", short_host(&self.host));
        let suffix = format!(".{}", self.cfg.format.ext());
        let cutoff = SystemTime::now() - Duration::from_secs(days * 86_400);
        let Ok(entries) = std::fs::read_dir(&self.cfg.dir) else { return };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&prefix) || !name.ends_with(&suffix) || e.path() == self.path {
                continue;
            }
            if e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < cutoff) {
                match std::fs::remove_file(e.path()) {
                    Ok(()) => info!("removed old recording {}", e.path().display()),
                    Err(err) => warn!("removing {}: {err}", e.path().display()),
                }
            }
        }
    }
}

impl Sink for Recorder {
    fn write(&mut self, s: &Sample) -> io::Result<()> {
        let today = Local::now().date_naive();
        if self.cfg.rotate && today != self.day {
            let (path, inner) = Self::open_new(&self.cfg, &self.host)?;
            info!("rotated recording to {}", path.display());
            self.day = today;
            self.path = path;
            self.inner = inner;
            self.prune();
        }
        self.inner.write(s)
    }
}

pub struct JsonLines<W: Write> {
    out: W,
}

impl<W: Write> JsonLines<W> {
    pub fn new(out: W) -> Self {
        JsonLines { out }
    }
}

impl<W: Write + Send> Sink for JsonLines<W> {
    fn write(&mut self, s: &Sample) -> io::Result<()> {
        serde_json::to_writer(&mut self.out, s)?;
        self.out.write_all(b"\n")?;
        self.out.flush()
    }
}

/// Writes nmon CSV. Device columns are fixed by the first sample, as in nmon;
/// devices that appear later are not recorded, missing ones read as zero.
pub struct Nmon<W: Write> {
    out: W,
    interval: f64,
    count: Option<u64>,
    command: String,
    disks: Vec<String>,
    nets: Vec<String>,
    mounts: Vec<String>,
    jails: Vec<String>,
    groups: Vec<DiskGroup>,
    nfs_client_ops: Vec<String>,
    nfs_server_ops: Vec<String>,
    /// PIDs already described in a UARG line.
    uarg_seen: HashSet<i32>,
    hooks: Hooks,
    started: bool,
}

/// nmon's external data collector hooks: shell commands named by
/// NMON_START / NMON_SNAP / NMON_END (or the JMON_ equivalents), run at the
/// start, after every snapshot (with the snapshot tag, e.g. T0001, as $1),
/// and at the end. Their standard output is appended to the recording, so
/// they can add their own CSV sections.
#[derive(Default)]
struct Hooks {
    start: Option<String>,
    snap: Option<String>,
    end: Option<String>,
}

impl Hooks {
    fn from_env() -> Hooks {
        let get = |name: &str| {
            std::env::var(format!("JMON_{name}"))
                .or_else(|_| std::env::var(format!("NMON_{name}")))
                .ok()
                .filter(|c| !c.trim().is_empty())
        };
        Hooks { start: get("START"), snap: get("SNAP"), end: get("END") }
    }
}

#[cfg(unix)]
fn run_hook(cmd: &str, tag: &str) -> Vec<u8> {
    match std::process::Command::new("/bin/sh").args(["-c", cmd, "jmon", tag]).env("JMON_TAG", tag).output() {
        Ok(out) => {
            if !out.status.success() {
                warn!("recording hook `{cmd}` exited with {}", out.status);
            }
            out.stdout
        }
        Err(e) => {
            warn!("running recording hook `{cmd}`: {e}");
            Vec::new()
        }
    }
}

#[cfg(not(unix))]
fn run_hook(cmd: &str, _tag: &str) -> Vec<u8> {
    warn!("recording hook `{cmd}` ignored: hooks need a Unix shell");
    Vec::new()
}

/// System details for the BBBP section: (label, command), run once at the
/// start of a recording, like nmon's configuration capture.
#[cfg(target_os = "freebsd")]
const BBBP_COMMANDS: &[(&str, &str)] = &[
    ("uname", "uname -a"),
    ("sysctl", "sysctl hw.model hw.ncpu hw.physmem hw.realmem kern.osrelease kern.hz kern.version"),
    ("geom disk", "geom disk list"),
    ("ifconfig", "ifconfig -a"),
    ("df", "df -k"),
    ("mount", "mount -p"),
    ("swapinfo", "swapinfo -k"),
    ("zpool", "zpool status"),
    ("jls", "jls"),
    ("kldstat", "kldstat"),
];
#[cfg(not(target_os = "freebsd"))]
const BBBP_COMMANDS: &[(&str, &str)] = &[];

fn run_capture(cmd: &str) -> String {
    let mut parts = cmd.split_whitespace();
    let Some(prog) = parts.next() else { return String::new() };
    std::process::Command::new(prog)
        .args(parts)
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn local(ts: f64) -> DateTime<Local> {
    Local.timestamp_opt(ts as i64, 0).single().unwrap_or_else(Local::now)
}

fn nmon_date(t: &DateTime<Local>) -> String {
    t.format("%d-%b-%Y").to_string().to_uppercase()
}

impl<W: Write> Nmon<W> {
    pub fn new(out: W, interval: f64, count: Option<u64>, groups: Vec<DiskGroup>) -> Self {
        Nmon {
            out,
            interval,
            count,
            command: std::env::args().collect::<Vec<_>>().join(" "),
            disks: vec![],
            nets: vec![],
            mounts: vec![],
            jails: vec![],
            groups,
            nfs_client_ops: vec![],
            nfs_server_ops: vec![],
            uarg_seen: HashSet::new(),
            hooks: Hooks::from_env(),
            started: false,
        }
    }

    fn header(&mut self, s: &Sample) -> io::Result<()> {
        let h = &s.host;
        let host = &h.hostname;
        let t = local(s.snap.timestamp);
        self.disks = s.snap.disks.iter().map(|d| d.name.clone()).collect();
        self.nets = s.snap.nets.iter().map(|n| n.name.clone()).collect();
        self.mounts = s.snap.filesystems.iter().map(|f| f.mountpoint.clone()).collect();
        self.jails = s.snap.jails.iter().map(|j| j.name.clone()).collect();
        if let Some(nfs) = &s.snap.nfs {
            self.nfs_client_ops = nfs.client_ops.iter().map(|o| o.0.clone()).collect();
            self.nfs_server_ops = nfs.server_ops.iter().map(|o| o.0.clone()).collect();
        }
        let o = &mut self.out;
        writeln!(o, "AAA,progname,jmon")?;
        writeln!(o, "AAA,command,{}", self.command.replace(',', " "))?;
        writeln!(o, "AAA,version,jmon-{}", env!("CARGO_PKG_VERSION"))?;
        writeln!(o, "AAA,disks_per_line,150")?;
        writeln!(o, "AAA,max_disks,256,set by -d option")?;
        writeln!(o, "AAA,host,{host}")?;
        writeln!(o, "AAA,user,{}", std::env::var("USER").unwrap_or_default())?;
        writeln!(o, "AAA,OS,FreeBSD,{},{}", h.os_release, h.machine)?;
        writeln!(o, "AAA,runname,{host}")?;
        writeln!(o, "AAA,time,{}", t.format("%H:%M.%S"))?;
        writeln!(o, "AAA,date,{}", nmon_date(&t))?;
        writeln!(o, "AAA,interval,{}", self.interval.round() as u64)?;
        writeln!(o, "AAA,snapshots,{}", self.count.unwrap_or(0))?;
        writeln!(o, "AAA,cpus,{},{}", h.ncpu, h.ncpu)?;
        writeln!(o, "AAA,proc_stat_variables,0")?;
        writeln!(o, "BBBP,000,uname,\"FreeBSD {} {} {}\"", host, h.os_release, h.machine)?;
        writeln!(o, "BBBP,001,cpu,\"{}\"", h.cpu_model.replace('"', "'"))?;
        let mut n = 2;
        for (label, cmd) in BBBP_COMMANDS {
            writeln!(o, "BBBP,{n:03},{label}")?;
            n += 1;
            for line in run_capture(cmd).lines() {
                writeln!(o, "BBBP,{n:03},{label},\"{}\"", line.replace('"', "'"))?;
                n += 1;
            }
        }
        if !self.groups.is_empty() {
            writeln!(o, "BBBG,000,Disk Group Configuration")?;
            for (i, g) in self.groups.iter().enumerate() {
                writeln!(o, "BBBG,{:03},{},{}", i + 1, g.name, g.members.join(","))?;
            }
        }

        for i in 0..s.snap.cpus.len() {
            writeln!(o, "CPU{:03},CPU {} {host},User%,Sys%,Wait%,Idle%", i + 1, i + 1)?;
        }
        writeln!(o, "CPU_ALL,CPU Total {host},User%,Sys%,Wait%,Idle%,Busy,CPUs")?;
        writeln!(
            o,
            "MEM,Memory MB {host},memtotal,hightotal,lowtotal,swaptotal,memfree,highfree,lowfree,swapfree,memshared,cached,active,bigfree,buffers,swapcached,inactive"
        )?;
        writeln!(o, "PROC,Processes {host},Runnable,Blocked,pswitch,syscall,read,write,fork,exec,sem,msg")?;
        let cols = |names: &[String], suffix: &str| names.iter().map(|n| format!("{n}{suffix}")).collect::<Vec<_>>().join(",");
        writeln!(o, "NET,Network I/O {host},{},{}", cols(&self.nets, "-read-KB/s"), cols(&self.nets, "-write-KB/s"))?;
        writeln!(o, "NETPACKET,Network Packets {host},{},{}", cols(&self.nets, "-read/s"), cols(&self.nets, "-write/s"))?;
        writeln!(o, "NETERROR,Network Errors {host},{}", cols(&self.nets, "-errors"))?;
        writeln!(o, "DISKBUSY,Disk %Busy {host},{}", self.disks.join(","))?;
        writeln!(o, "DISKREAD,Disk Read KB/s {host},{}", self.disks.join(","))?;
        writeln!(o, "DISKWRITE,Disk Write KB/s {host},{}", self.disks.join(","))?;
        writeln!(o, "DISKXFER,Disk transfers per second {host},{}", self.disks.join(","))?;
        writeln!(o, "DISKREADSERV,Disk Read Service Time msec/xfer {host},{}", self.disks.join(","))?;
        writeln!(o, "DISKWRITESERV,Disk Write Service Time msec/xfer {host},{}", self.disks.join(","))?;
        writeln!(o, "DISKWAITQ,Disk Queue Length {host},{}", self.disks.join(","))?;
        if !self.groups.is_empty() {
            let names = self.groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>().join(",");
            writeln!(o, "DGBUSY,Disk Group Busy {host},{names}")?;
            writeln!(o, "DGREAD,Disk Group Read KB/s {host},{names}")?;
            writeln!(o, "DGWRITE,Disk Group Write KB/s {host},{names}")?;
            writeln!(o, "DGXFER,Disk Group I/O per second {host},{names}")?;
        }
        if !self.nfs_client_ops.is_empty() {
            writeln!(o, "NFSCLIV3,NFS Client v3 {host},{}", self.nfs_client_ops.join(","))?;
        }
        if !self.nfs_server_ops.is_empty() {
            writeln!(o, "NFSSVRV3,NFS Server v3 {host},{}", self.nfs_server_ops.join(","))?;
        }
        writeln!(
            o,
            "VM,Paging and Virtual Memory {host},pgfault,pswpin,pswpout,pswitch,interrupts,syscalls,traps,forks"
        )?;
        if !self.jails.is_empty() {
            writeln!(o, "JAILCPU,Jail CPU% {host},{}", self.jails.join(","))?;
            writeln!(o, "JAILMEM,Jail Resident MB {host},{}", self.jails.join(","))?;
        }
        writeln!(o, "JFSFILE,JFS Filespace %Used {host},{}", self.mounts.join(","))?;
        writeln!(o, "TOP,%CPU Utilisation")?;
        writeln!(o, "TOP,+PID,Time,%CPU,%Usr,%Sys,Size,ResSet,ResText,ResData,ShdLib,MinorFault,MajorFault,Command")?;
        writeln!(o, "UARG,+Time,PID,PPID,COMM,THCOUNT,USER,GROUP,FullCommand")?;
        Ok(())
    }
}

impl<W: Write> Drop for Nmon<W> {
    fn drop(&mut self) {
        if self.started
            && let Some(cmd) = &self.hooks.end
        {
            let _ = self.out.write_all(&run_hook(cmd, "T9999"));
            let _ = self.out.flush();
        }
    }
}

impl<W: Write + Send> Sink for Nmon<W> {
    fn write(&mut self, s: &Sample) -> io::Result<()> {
        let Some(r) = &s.rates else { return Ok(()) };
        if !self.started {
            self.header(s)?;
            self.started = true;
            if let Some(cmd) = &self.hooks.start {
                self.out.write_all(&run_hook(cmd, "T0000"))?;
            }
        }
        let snap = &s.snap;
        let t = local(snap.timestamp);
        let tag = format!("T{:04}", s.seq);
        let o = &mut self.out;
        writeln!(o, "ZZZZ,{tag},{},{}", t.format("%H:%M:%S"), nmon_date(&t))?;

        let pct = |v: f64| format!("{:.1}", v * 100.0);
        for (i, c) in r.cpus.iter().enumerate() {
            let user = c.user + c.nice;
            let sys = c.system + c.interrupt;
            writeln!(o, "CPU{:03},{tag},{},{},0.0,{}", i + 1, pct(user), pct(sys), pct(c.idle))?;
        }
        let c = &r.cpu_total;
        writeln!(
            o,
            "CPU_ALL,{tag},{},{},0.0,{},,{}",
            pct(c.user + c.nice),
            pct(c.system + c.interrupt),
            pct(c.idle),
            r.cpus.len()
        )?;

        let mb = |b: u64| format!("{:.1}", b as f64 / 1048576.0);
        let m = &snap.memory;
        let swap_total: u64 = snap.swap.iter().map(|s| s.total).sum();
        let swap_used: u64 = snap.swap.iter().map(|s| s.used).sum();
        writeln!(
            o,
            "MEM,{tag},{},0.0,0.0,{},{},0.0,0.0,{},0.0,{},{},-1.0,0.0,0.0,{}",
            mb(m.total),
            mb(swap_total),
            mb(m.free),
            mb(swap_total - swap_used.min(swap_total)),
            mb(m.arc.unwrap_or(0)),
            mb(m.active),
            mb(m.inactive + m.laundry),
        )?;

        let v = &r.vm;
        writeln!(
            o,
            "PROC,{tag},{},{},{:.1},{:.1},0.0,0.0,{:.1},0.0,0.0,0.0",
            snap.runq.runnable,
            snap.runq.disk_wait,
            v.context_switches,
            v.syscalls,
            v.forks
        )?;

        let net_rate = |name: &str| {
            snap.nets.iter().position(|n| n.name == name).map(|i| r.nets[i]).unwrap_or_default()
        };
        let nets: Vec<_> = self.nets.iter().map(|n| net_rate(n)).collect();
        let join = |v: Vec<String>| v.join(",");
        writeln!(
            o,
            "NET,{tag},{},{}",
            join(nets.iter().map(|n| format!("{:.1}", n.rx_bps / 1024.0)).collect()),
            join(nets.iter().map(|n| format!("{:.1}", n.tx_bps / 1024.0)).collect())
        )?;
        writeln!(
            o,
            "NETPACKET,{tag},{},{}",
            join(nets.iter().map(|n| format!("{:.1}", n.rx_pps)).collect()),
            join(nets.iter().map(|n| format!("{:.1}", n.tx_pps)).collect())
        )?;
        writeln!(o, "NETERROR,{tag},{}", join(nets.iter().map(|n| format!("{:.1}", n.errors_ps)).collect()))?;

        let disks: Vec<_> = self
            .disks
            .iter()
            .map(|name| snap.disks.iter().position(|d| &d.name == name).map(|i| r.disks[i]).unwrap_or_default())
            .collect();
        writeln!(o, "DISKBUSY,{tag},{}", join(disks.iter().map(|d| format!("{:.1}", d.busy * 100.0)).collect()))?;
        writeln!(o, "DISKREAD,{tag},{}", join(disks.iter().map(|d| format!("{:.1}", d.read_bps / 1024.0)).collect()))?;
        writeln!(o, "DISKWRITE,{tag},{}", join(disks.iter().map(|d| format!("{:.1}", d.write_bps / 1024.0)).collect()))?;
        writeln!(
            o,
            "DISKXFER,{tag},{}",
            join(disks.iter().map(|d| format!("{:.1}", d.read_iops + d.write_iops)).collect())
        )?;
        writeln!(o, "DISKREADSERV,{tag},{}", join(disks.iter().map(|d| format!("{:.2}", d.read_ms)).collect()))?;
        writeln!(o, "DISKWRITESERV,{tag},{}", join(disks.iter().map(|d| format!("{:.2}", d.write_ms)).collect()))?;
        let queues: Vec<String> = self
            .disks
            .iter()
            .map(|name| snap.disks.iter().find(|d| &d.name == name).map_or(0, |d| d.queue).to_string())
            .collect();
        writeln!(o, "DISKWAITQ,{tag},{}", queues.join(","))?;
        if !self.groups.is_empty() {
            let g = group_rates(&self.groups, snap, r);
            let col = |f: &dyn Fn(&crate::sample::DiskRate) -> f64| g.iter().map(|d| format!("{:.1}", f(d))).collect::<Vec<_>>().join(",");
            writeln!(o, "DGBUSY,{tag},{}", col(&|d| d.busy * 100.0))?;
            writeln!(o, "DGREAD,{tag},{}", col(&|d| d.read_bps / 1024.0))?;
            writeln!(o, "DGWRITE,{tag},{}", col(&|d| d.write_bps / 1024.0))?;
            writeln!(o, "DGXFER,{tag},{}", col(&|d| d.read_iops + d.write_iops))?;
        }
        if let Some(n) = &r.nfs {
            let col = |names: &[String], ops: &[(String, f64)]| {
                names
                    .iter()
                    .map(|name| format!("{:.1}", ops.iter().find(|o| &o.0 == name).map_or(0.0, |o| o.1)))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            if !self.nfs_client_ops.is_empty() {
                writeln!(o, "NFSCLIV3,{tag},{}", col(&self.nfs_client_ops, &n.client_ops))?;
            }
            if !self.nfs_server_ops.is_empty() {
                writeln!(o, "NFSSVRV3,{tag},{}", col(&self.nfs_server_ops, &n.server_ops))?;
            }
        }
        writeln!(
            o,
            "VM,{tag},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1}",
            v.faults,
            v.swap_pages_in,
            v.swap_pages_out,
            v.context_switches,
            v.interrupts,
            v.syscalls,
            v.traps,
            v.forks
        )?;
        if !self.jails.is_empty() {
            let jail = |name: &String| r.jails.iter().find(|j| &j.name == name);
            let cpu: Vec<String> = self.jails.iter().map(|n| format!("{:.1}", jail(n).map_or(0.0, |j| j.cpu))).collect();
            let mem: Vec<String> =
                self.jails.iter().map(|n| format!("{:.1}", jail(n).map_or(0, |j| j.rss) as f64 / 1048576.0)).collect();
            writeln!(o, "JAILCPU,{tag},{}", cpu.join(","))?;
            writeln!(o, "JAILMEM,{tag},{}", mem.join(","))?;
        }

        let fs: Vec<String> = self
            .mounts
            .iter()
            .map(|mp| {
                snap.filesystems
                    .iter()
                    .find(|f| &f.mountpoint == mp && f.total > 0)
                    .map(|f| format!("{:.1}", f.used() as f64 * 100.0 / f.total as f64))
                    .unwrap_or_else(|| "0.0".into())
            })
            .collect();
        writeln!(o, "JFSFILE,{tag},{}", fs.join(","))?;

        for i in s.procs_by_cpu().into_iter().take(20) {
            let cpu = r.proc_cpu[i];
            if cpu < 0.1 {
                break;
            }
            let p = &snap.processes[i];
            writeln!(
                o,
                "TOP,{:07},{tag},{cpu:.2},{cpu:.2},0.00,{},{},0,0,0,{:.1},{:.1},{}",
                p.pid,
                p.vsize / 1024,
                p.rss / 1024,
                r.proc_faults[i].0,
                r.proc_faults[i].1,
                p.command.replace(',', "_")
            )?;
            // nmon writes each process's full command line once.
            if self.uarg_seen.insert(p.pid) {
                writeln!(
                    o,
                    "UARG,{tag},{:07},{},{},{},{},-,{}",
                    p.pid,
                    p.ppid,
                    p.command.replace(',', "_"),
                    p.threads,
                    p.user,
                    p.args.replace(',', " ")
                )?;
            }
        }
        if let Some(cmd) = &self.hooks.snap {
            o.write_all(&run_hook(cmd, &tag))?;
        }
        o.flush()
    }
}
