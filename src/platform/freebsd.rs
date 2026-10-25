//! FreeBSD collector: everything comes from sysctl(3), getifaddrs(3) and
//! getmntinfo(3), so jmon needs no special privileges or kvm access.

use crate::model::*;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

// ---------------------------------------------------------------------------
// sysctl helpers

fn sysctl_raw(name: &str) -> io::Result<Vec<u8>> {
    let cname = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
    // Tables like kern.proc grow between the size probe and the read, so
    // over-allocate and retry on ENOMEM.
    for _ in 0..5 {
        let mut len: libc::size_t = 0;
        let rc = unsafe {
            libc::sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null(), 0)
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        len += len / 8 + 64;
        let mut buf = vec![0u8; len];
        let rc = unsafe {
            libc::sysctlbyname(cname.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null(), 0)
        };
        if rc == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) {
            return Err(err);
        }
    }
    Err(io::Error::from_raw_os_error(libc::ENOMEM))
}

fn sysctl_mib_raw(mib: &[libc::c_int]) -> io::Result<Vec<u8>> {
    for _ in 0..5 {
        let mut len: libc::size_t = 0;
        let rc = unsafe {
            libc::sysctl(mib.as_ptr(), mib.len() as u32, std::ptr::null_mut(), &mut len, std::ptr::null(), 0)
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        len += len / 8 + 4096;
        let mut buf = vec![0u8; len];
        let rc = unsafe {
            libc::sysctl(mib.as_ptr(), mib.len() as u32, buf.as_mut_ptr().cast(), &mut len, std::ptr::null(), 0)
        };
        if rc == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) {
            return Err(err);
        }
    }
    Err(io::Error::from_raw_os_error(libc::ENOMEM))
}

/// An `int`, `u_int`, `long` or `uint64_t` sysctl, read in one syscall into a
/// stack buffer.
struct SysctlNum {
    buf: [u8; 8],
    len: usize,
}

impl SysctlNum {
    /// `call` runs sysctl(3) or sysctlbyname(3) on the buffer and its length.
    fn read(call: impl FnOnce(*mut libc::c_void, &mut libc::size_t) -> libc::c_int) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        let mut len: libc::size_t = buf.len();
        if call(buf.as_mut_ptr().cast(), &mut len) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SysctlNum { buf, len })
    }

    fn by_name(name: &str) -> io::Result<Self> {
        let cname = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        Self::read(|p, len| unsafe { libc::sysctlbyname(cname.as_ptr(), p, len, std::ptr::null(), 0) })
    }

    fn by_mib(mib: &[libc::c_int]) -> io::Result<Self> {
        if mib.is_empty() {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        Self::read(|p, len| unsafe { libc::sysctl(mib.as_ptr(), mib.len() as u32, p, len, std::ptr::null(), 0) })
    }

    fn unsigned(&self) -> io::Result<u64> {
        match self.len {
            4 => Ok(u32::from_ne_bytes(self.buf[..4].try_into().unwrap()) as u64),
            8 => Ok(u64::from_ne_bytes(self.buf)),
            n => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected size {n}"))),
        }
    }

    fn signed(&self) -> Option<i64> {
        match self.len {
            4 => Some(i32::from_ne_bytes(self.buf[..4].try_into().unwrap()) as i64),
            8 => Some(i64::from_ne_bytes(self.buf)),
            _ => None,
        }
    }
}

fn sysctl_uint(name: &str) -> io::Result<u64> {
    SysctlNum::by_name(name)?.unsigned().map_err(|e| io::Error::new(e.kind(), format!("{name}: {e}")))
}

fn sysctl_int(name: &str) -> Option<i64> {
    SysctlNum::by_name(name).ok()?.signed()
}

fn sysctl_mib_uint(mib: &[libc::c_int]) -> io::Result<u64> {
    SysctlNum::by_mib(mib)?.unsigned()
}

/// Temperature sysctls ("IK" format) are tenths of a kelvin; sysctl(8)
/// converts with a 273.1 offset, so match it.
fn deci_kelvin_to_celsius(raw: u64) -> Option<f64> {
    let v = raw as u32 as i32;
    (v > 0).then(|| (v - 2731) as f64 / 10.0)
}

/// Pre-resolved sysctl OID so hot-path reads skip ASCII name resolution in the kernel.
#[derive(Clone, Default)]
struct Mib(Vec<libc::c_int>);

impl Mib {
    fn lookup(name: &str) -> Self {
        let Ok(cname) = CString::new(name) else { return Mib::default() };
        let mut mib = [0 as libc::c_int; libc::CTL_MAXNAME as usize];
        let mut len: libc::size_t = mib.len();
        if unsafe { libc::sysctlnametomib(cname.as_ptr(), mib.as_mut_ptr(), &mut len) } == 0 {
            Mib(mib[..len].to_vec())
        } else {
            Mib::default()
        }
    }

    fn found(&self) -> bool {
        !self.0.is_empty()
    }

    fn uint(&self) -> io::Result<u64> {
        sysctl_mib_uint(&self.0)
    }

    fn uint_or_zero(&self) -> u64 {
        self.uint().unwrap_or(0)
    }

    fn int(&self) -> Option<i64> {
        SysctlNum::by_mib(&self.0).ok()?.signed()
    }

    fn celsius(&self) -> Option<f64> {
        deci_kelvin_to_celsius(self.uint().ok()?)
    }

    fn raw(&self) -> io::Result<Vec<u8>> {
        if self.0.is_empty() {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        sysctl_mib_raw(&self.0)
    }
}

fn sysctl_string(name: &str) -> io::Result<String> {
    let buf = sysctl_raw(name)?;
    Ok(cstr_bytes(&buf))
}

fn sysctl_struct<T: Copy>(name: &str) -> io::Result<T> {
    let buf = sysctl_raw(name)?;
    if buf.len() < size_of::<T>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name}: short read")));
    }
    Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<T>()) })
}

fn cstr_bytes(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn cchars(b: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = b.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Kernel structures that libc doesn't model in a read-safe way.

/// `struct devstat` (DEVSTAT_VERSION 6). libc models the flag fields as Rust
/// enums, and reading arbitrary bit combinations into those is UB, so this
/// mirrors the layout with plain integers.
#[repr(C)]
#[derive(Clone, Copy)]
struct DevStat {
    sequence0: u32,
    allocated: i32,
    start_count: u32,
    end_count: u32,
    busy_from: libc::bintime,
    dev_links: *mut libc::c_void,
    device_number: u32,
    device_name: [libc::c_char; 16],
    unit_number: i32,
    bytes: [u64; 4],
    operations: [u64; 4],
    duration: [libc::bintime; 4],
    busy_time: libc::bintime,
    creation_time: libc::bintime,
    block_size: u32,
    tag_types: [u64; 3],
    flags: u32,
    device_type: u32,
    priority: u32,
    id: *const libc::c_void,
    sequence1: u32,
}

const _: () = assert!(size_of::<DevStat>() == size_of::<libc::devstat>());

const DEVSTAT_READ: usize = 1;
const DEVSTAT_WRITE: usize = 2;
const DEVSTAT_TYPE_PASS: u32 = 0x100;

/// `struct xswdev` from <vm/vm_param.h>, returned by vm.swap_info.<n>.
#[repr(C)]
#[derive(Clone, Copy)]
struct XswDev {
    version: u32,
    dev: u64,
    flags: i32,
    nblks: i32,
    used: i32,
}

const NODEV: u64 = u64::MAX;

fn bintime_secs(bt: &libc::bintime) -> f64 {
    bt.sec as f64 + bt.frac as f64 / 18_446_744_073_709_551_616.0
}

// ---------------------------------------------------------------------------

pub struct Collector {
    host: Arc<HostInfo>,
    stathz: u32,
    mibs: Mibs,
    users: HashMap<u32, String>,
    /// Command lines keyed by pid, tagged with the process start time so a
    /// recycled pid is re-read.
    args: HashMap<i32, (i64, String)>,
    /// `zpool list` is a fork+exec, so pool capacity is refreshed slowly.
    zpools: Option<ZpoolCache>,
    /// Cached `vfs.nfs.nfsstats` bytes + parsed Nfs so idle NFS mounts do not spawn `nfsstat`.
    nfs_cache: Option<(Vec<u8>, Nfs)>,
    /// Battery sysctls run ACPI methods (~4 ms each), so read them rarely.
    battery: Option<(Instant, Option<Battery>)>,
    /// When the sensor OIDs were last resolved, so a driver loaded later is found.
    sensor_lookup: Instant,
    geom: Option<GeomStats>,
    warned: std::collections::HashSet<&'static str>,
}

struct Mibs {
    cp_times: Mib,
    devstat_all: Mib,
    vmtotal: Mib,
    tcp_stats: Mib,
    tcp_states: Mib,
    udp_stats: Mib,
    nfs_stats: Mib,
    // Memory pages
    v_page_count: Mib,
    v_active_count: Mib,
    v_inactive_count: Mib,
    v_laundry_count: Mib,
    v_wire_count: Mib,
    v_free_count: Mib,
    // VM & kernel counters
    v_swtch: Mib,
    v_intr: Mib,
    v_syscall: Mib,
    v_trap: Mib,
    v_forks: Mib,
    v_vforks: Mib,
    v_rforks: Mib,
    v_vm_faults: Mib,
    v_swappgsin: Mib,
    v_swappgsout: Mib,
    v_swapin: Mib,
    v_swapout: Mib,
    v_vnodein: Mib,
    v_vnodeout: Mib,
    v_vnodepgsin: Mib,
    v_vnodepgsout: Mib,
    v_zfod: Mib,
    v_cow_faults: Mib,
    v_intrans: Mib,
    v_reactivated: Mib,
    v_tfree: Mib,
    v_pdwakeups: Mib,
    v_pdpages: Mib,
    // Superpages
    pg_ps_enabled: Mib,
    pde_mappings: Mib,
    pde_promotions: Mib,
    pde_demotions: Mib,
    pde_failures: Mib,
    // ZFS ARC
    arc_size: Mib,
    arc_c: Mib,
    arc_c_max: Mib,
    arc_hits: Mib,
    arc_misses: Mib,
    arc_l2_size: Mib,
    arc_l2_hits: Mib,
    arc_l2_misses: Mib,
    // Per-CPU sensors
    cpu_temps: Vec<Mib>,
    cpu_freqs: Vec<Mib>,
    cpu_tjmax: Mib,
}

impl Mibs {
    fn new(ncpu: usize) -> Self {
        let mut mibs = Mibs {
            cp_times: Mib::lookup("kern.cp_times"),
            devstat_all: Mib::lookup("kern.devstat.all"),
            vmtotal: Mib::lookup("vm.vmtotal"),
            tcp_stats: Mib::lookup("net.inet.tcp.stats"),
            tcp_states: Mib::lookup("net.inet.tcp.states"),
            udp_stats: Mib::lookup("net.inet.udp.stats"),
            nfs_stats: Mib::lookup("vfs.nfs.nfsstats"),
            v_page_count: Mib::lookup("vm.stats.vm.v_page_count"),
            v_active_count: Mib::lookup("vm.stats.vm.v_active_count"),
            v_inactive_count: Mib::lookup("vm.stats.vm.v_inactive_count"),
            v_laundry_count: Mib::lookup("vm.stats.vm.v_laundry_count"),
            v_wire_count: Mib::lookup("vm.stats.vm.v_wire_count"),
            v_free_count: Mib::lookup("vm.stats.vm.v_free_count"),
            v_swtch: Mib::lookup("vm.stats.sys.v_swtch"),
            v_intr: Mib::lookup("vm.stats.sys.v_intr"),
            v_syscall: Mib::lookup("vm.stats.sys.v_syscall"),
            v_trap: Mib::lookup("vm.stats.sys.v_trap"),
            v_forks: Mib::lookup("vm.stats.vm.v_forks"),
            v_vforks: Mib::lookup("vm.stats.vm.v_vforks"),
            v_rforks: Mib::lookup("vm.stats.vm.v_rforks"),
            v_vm_faults: Mib::lookup("vm.stats.vm.v_vm_faults"),
            v_swappgsin: Mib::lookup("vm.stats.vm.v_swappgsin"),
            v_swappgsout: Mib::lookup("vm.stats.vm.v_swappgsout"),
            v_swapin: Mib::lookup("vm.stats.vm.v_swapin"),
            v_swapout: Mib::lookup("vm.stats.vm.v_swapout"),
            v_vnodein: Mib::lookup("vm.stats.vm.v_vnodein"),
            v_vnodeout: Mib::lookup("vm.stats.vm.v_vnodeout"),
            v_vnodepgsin: Mib::lookup("vm.stats.vm.v_vnodepgsin"),
            v_vnodepgsout: Mib::lookup("vm.stats.vm.v_vnodepgsout"),
            v_zfod: Mib::lookup("vm.stats.vm.v_zfod"),
            v_cow_faults: Mib::lookup("vm.stats.vm.v_cow_faults"),
            v_intrans: Mib::lookup("vm.stats.vm.v_intrans"),
            v_reactivated: Mib::lookup("vm.stats.vm.v_reactivated"),
            v_tfree: Mib::lookup("vm.stats.vm.v_tfree"),
            v_pdwakeups: Mib::lookup("vm.stats.vm.v_pdwakeups"),
            v_pdpages: Mib::lookup("vm.stats.vm.v_pdpages"),
            pg_ps_enabled: Mib::lookup("vm.pmap.pg_ps_enabled"),
            pde_mappings: Mib::lookup("vm.pmap.pde.mappings"),
            pde_promotions: Mib::lookup("vm.pmap.pde.promotions"),
            pde_demotions: Mib::lookup("vm.pmap.pde.demotions"),
            pde_failures: Mib::lookup("vm.pmap.pde.p_failures"),
            arc_size: Mib::lookup("kstat.zfs.misc.arcstats.size"),
            arc_c: Mib::lookup("kstat.zfs.misc.arcstats.c"),
            arc_c_max: Mib::lookup("kstat.zfs.misc.arcstats.c_max"),
            arc_hits: Mib::lookup("kstat.zfs.misc.arcstats.hits"),
            arc_misses: Mib::lookup("kstat.zfs.misc.arcstats.misses"),
            arc_l2_size: Mib::lookup("kstat.zfs.misc.arcstats.l2_size"),
            arc_l2_hits: Mib::lookup("kstat.zfs.misc.arcstats.l2_hits"),
            arc_l2_misses: Mib::lookup("kstat.zfs.misc.arcstats.l2_misses"),
            cpu_temps: Vec::new(),
            cpu_freqs: Vec::new(),
            cpu_tjmax: Mib::default(),
        };
        mibs.resolve_sensors(ncpu);
        mibs
    }

    /// (Re)resolves the per-CPU sensor OIDs, which only exist once coretemp(4)
    /// or cpufreq(4) is loaded.
    fn resolve_sensors(&mut self, ncpu: usize) {
        self.cpu_temps = (0..ncpu).map(|i| Mib::lookup(&format!("dev.cpu.{i}.temperature"))).collect();
        self.cpu_freqs = (0..ncpu).map(|i| Mib::lookup(&format!("dev.cpu.{i}.freq"))).collect();
        self.cpu_tjmax = Mib::lookup("dev.cpu.0.coretemp.tjmax");
    }

    fn sensors_missing(&self) -> bool {
        let first_missing = |v: &[Mib]| v.first().is_none_or(|m| !m.found());
        first_missing(&self.cpu_temps) || first_missing(&self.cpu_freqs)
    }
}

/// Pool capacity refresh: every 30s, or every 5s while the pools are being written.
const ZPOOL_REFRESH: Duration = Duration::from_secs(30);
const ZPOOL_REFRESH_BUSY: Duration = Duration::from_secs(5);
const BATTERY_REFRESH: Duration = Duration::from_secs(30);
const SENSOR_LOOKUP: Duration = Duration::from_secs(60);

struct ZpoolCache {
    at: Instant,
    pools: Vec<ZPool>,
    /// Per pool, the sysctl MIBs of each dataset's nread/nwritten/reads/writes
    /// counters, so samples read 4 values per dataset instead of walking the
    /// whole kstat tree.
    mibs: Vec<Vec<[Vec<libc::c_int>; 4]>>,
    /// Bytes written across all pools when `pools` was refreshed.
    written_at_refresh: u64,
}

impl Collector {
    pub fn new() -> Result<Self> {
        let clock: libc::clockinfo = sysctl_struct("kern.clockrate").context("kern.clockrate")?;
        let host = HostInfo {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
            os_type: "freebsd".into(),
            os_release: sysctl_string("kern.osrelease").unwrap_or_default(),
            machine: sysctl_string("hw.machine").unwrap_or_default(),
            cpu_model: sysctl_string("hw.model").unwrap_or_default(),
            ncpu: sysctl_uint("hw.ncpu").context("hw.ncpu")? as usize,
            physmem: sysctl_uint("hw.physmem").context("hw.physmem")?,
            pagesize: sysctl_uint("hw.pagesize").context("hw.pagesize")?,
            demo: false,
        };
        let mibs = Mibs::new(host.ncpu);
        Ok(Collector {
            host: Arc::new(host),
            stathz: if clock.stathz > 0 { clock.stathz as u32 } else { clock.hz as u32 },
            mibs,
            users: HashMap::new(),
            args: HashMap::new(),
            zpools: None,
            nfs_cache: None,
            battery: None,
            sensor_lookup: Instant::now(),
            geom: None,
            warned: Default::default(),
        })
    }

    pub fn host(&self) -> Arc<HostInfo> {
        self.host.clone()
    }

    pub fn collect(&mut self) -> Snapshot {
        let taken = Instant::now();
        let cpus = self.ok("cpu", cpu_ticks(&self.mibs)).unwrap_or_default();
        let memory = self.ok("memory", memory(&self.host, &self.mibs)).unwrap_or_default();
        let swap = self.ok("swap", swap(self.host.pagesize)).unwrap_or_default();
        let vm = vm_counters(&self.mibs);
        let disks = self.ok("disks", disks(&self.mibs)).unwrap_or_default();
        let nets = self.ok("network", nets()).unwrap_or_default();
        let filesystems = self.ok("filesystems", filesystems()).unwrap_or_default();
        let processes = match processes(self.host.pagesize) {
            Ok((mut procs, starts)) => {
                for (p, start) in procs.iter_mut().zip(starts) {
                    p.user = self.user_name(p.uid);
                    p.args = self.proc_args(p, start);
                }
                let live: std::collections::HashSet<i32> = procs.iter().map(|p| p.pid).collect();
                self.args.retain(|pid, _| live.contains(pid));
                procs
            }
            Err(e) => {
                self.warn_once("processes", &e);
                Vec::new()
            }
        };
        let partitions = self.partitions(&disks);
        let nfs_active = filesystems.iter().any(|f| f.fstype.starts_with("nfs"))
            || processes.iter().any(|p| p.command == "nfsd");
        let nfs = if nfs_active { self.collect_nfs() } else { None };
        let runq = self.mibs.vmtotal.raw().ok().and_then(|b| parse_vmtotal(&b)).unwrap_or_default();
        let superpages = superpages(&self.mibs);
        let tcp_snap = self.ok("tcp", tcp(&self.mibs)).flatten();
        let udp_snap = udp(&self.mibs);
        Snapshot {
            taken,
            timestamp: unix_now(),
            uptime: uptime(),
            stathz: self.stathz,
            cpus,
            load: loadavg(),
            memory,
            swap,
            vm,
            runq,
            superpages,
            disks,
            partitions,
            nets,
            filesystems,
            processes,
            sensors: self.sensors(),
            tcp: tcp_snap,
            udp: udp_snap,
            jails: self.ok("jails", jails()).unwrap_or_default(),
            zfs: self.zfs(),
            nfs,
        }
    }

    fn collect_nfs(&mut self) -> Option<Nfs> {
        let raw = self.mibs.nfs_stats.raw().ok();
        if let (Some(bytes), Some((prev_bytes, cached))) = (&raw, &self.nfs_cache)
            && bytes == prev_bytes
        {
            return Some(cached.clone());
        }
        let parsed = self.ok("nfs", nfs())?;
        if let Some(bytes) = raw {
            self.nfs_cache = Some((bytes, parsed.clone()));
        }
        Some(parsed)
    }

    fn partitions(&mut self, disks: &[Disk]) -> Vec<Disk> {
        if self.geom.is_none() {
            match GeomStats::open() {
                Ok(g) => self.geom = Some(g),
                Err(e) => {
                    self.warn_once("GEOM statistics", &e);
                    return Vec::new();
                }
            }
        }
        let geom = self.geom.as_mut().unwrap();
        let mut out = geom.read();
        // Whole disks are already in `disks` (from kern.devstat.all).
        out.retain(|p| !disks.iter().any(|d| d.name == p.name));
        out
    }

    fn sensors(&mut self) -> Sensors {
        if self.battery.as_ref().is_none_or(|(t, _)| t.elapsed() >= BATTERY_REFRESH) {
            self.battery = Some((Instant::now(), battery()));
        }
        if self.mibs.sensors_missing() && self.sensor_lookup.elapsed() >= SENSOR_LOOKUP {
            self.sensor_lookup = Instant::now();
            self.mibs.resolve_sensors(self.host.ncpu);
        }
        let mut s = sensors(&self.mibs);
        s.battery = self.battery.as_ref().and_then(|(_, b)| b.clone());
        s
    }

    fn proc_args(&mut self, p: &Process, start: i64) -> String {
        if let Some((s, a)) = self.args.get(&p.pid)
            && *s == start
        {
            return a.clone();
        }
        let a = proc_args(p.pid).filter(|a| !a.is_empty()).unwrap_or_else(|| format!("[{}]", p.command));
        self.args.insert(p.pid, (start, a.clone()));
        a
    }

    fn zfs(&mut self) -> Option<Zfs> {
        let size = self.mibs.arc_size.uint().ok()?;
        let written = |c: &ZpoolCache| -> u64 { c.mibs.iter().map(|m| pool_io(m)[1]).sum() };
        let stale = match &self.zpools {
            None => true,
            Some(c) => {
                let age = c.at.elapsed();
                age >= ZPOOL_REFRESH || (age >= ZPOOL_REFRESH_BUSY && written(c) != c.written_at_refresh)
            }
        };
        if stale {
            let pools = match zpool_list() {
                Ok(p) => p,
                Err(e) => {
                    self.warn_once("zpool list", &e);
                    Vec::new()
                }
            };
            let mibs = pools.iter().map(|p| dataset_mibs(&p.name)).collect();
            let mut cache = ZpoolCache { at: Instant::now(), pools, mibs, written_at_refresh: 0 };
            cache.written_at_refresh = written(&cache);
            self.zpools = Some(cache);
        }
        let cache = self.zpools.as_ref()?;
        let mut pools = cache.pools.clone();
        for (pool, mibs) in pools.iter_mut().zip(&cache.mibs) {
            [pool.read_bytes, pool.write_bytes, pool.read_ops, pool.write_ops] = pool_io(mibs);
            if let Ok(state) = sysctl_string(&format!("kstat.zfs.{}.misc.state", pool.name))
                && !state.is_empty()
            {
                pool.health = state;
            }
        }
        Some(Zfs {
            arc_size: size,
            arc_target: self.mibs.arc_c.uint_or_zero(),
            arc_max: self.mibs.arc_c_max.uint_or_zero(),
            arc_hits: self.mibs.arc_hits.uint_or_zero(),
            arc_misses: self.mibs.arc_misses.uint_or_zero(),
            l2_size: self.mibs.arc_l2_size.uint_or_zero(),
            l2_hits: self.mibs.arc_l2_hits.uint_or_zero(),
            l2_misses: self.mibs.arc_l2_misses.uint_or_zero(),
            pools,
        })
    }

    fn ok<T>(&mut self, what: &'static str, r: Result<T>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                self.warn_once(what, &e);
                None
            }
        }
    }

    fn warn_once(&mut self, what: &'static str, e: &anyhow::Error) {
        if self.warned.insert(what) {
            warn!("collecting {what}: {e:#}");
        }
    }

    fn user_name(&mut self, uid: u32) -> String {
        self.users.entry(uid).or_insert_with(|| lookup_user(uid)).clone()
    }
}

fn lookup_user(uid: u32) -> String {
    let mut pw = MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0 as libc::c_char; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, pw.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc == 0 && !result.is_null() {
        unsafe { CStr::from_ptr((*result).pw_name).to_string_lossy().into_owned() }
    } else {
        uid.to_string()
    }
}

fn cpu_ticks(mibs: &Mibs) -> Result<Vec<CpuTicks>> {
    Ok(parse_cp_times(&mibs.cp_times.raw()?))
}

/// kern.cp_times: CPUSTATES `long`s per CPU.
pub(crate) fn parse_cp_times(buf: &[u8]) -> Vec<CpuTicks> {
    // `long` is 32 bits on i386, so widen explicitly.
    #[allow(clippy::useless_conversion)]
    let longs: Vec<i64> = buf
        .as_chunks::<{ size_of::<libc::c_long>() }>()
        .0
        .iter()
        .map(|c| i64::from(libc::c_long::from_ne_bytes(*c)))
        .collect();
    // CPUSTATES = 5: user, nice, sys, intr, idle.
    longs
        .as_chunks::<5>()
        .0
        .iter()
        .map(|c| CpuTicks {
            user: c[0] as u64,
            nice: c[1] as u64,
            system: c[2] as u64,
            interrupt: c[3] as u64,
            idle: c[4] as u64,
        })
        .collect()
}

fn memory(host: &HostInfo, mibs: &Mibs) -> Result<Memory> {
    let pages = |m: &Mib, name: &str| -> Result<u64> {
        Ok(m.uint().with_context(|| name.to_string())? * host.pagesize)
    };
    Ok(Memory {
        total: pages(&mibs.v_page_count, "v_page_count")?,
        active: pages(&mibs.v_active_count, "v_active_count")?,
        inactive: pages(&mibs.v_inactive_count, "v_inactive_count")?,
        laundry: pages(&mibs.v_laundry_count, "v_laundry_count").unwrap_or(0),
        wired: pages(&mibs.v_wire_count, "v_wire_count")?,
        free: pages(&mibs.v_free_count, "v_free_count")?,
        arc: mibs.arc_size.uint().ok(),
    })
}

fn swap(pagesize: u64) -> Result<Vec<SwapDev>> {
    let name = CString::new("vm.swap_info").unwrap();
    let mut mib = [0 as libc::c_int; 16];
    let mut miblen: libc::size_t = mib.len();
    if unsafe { libc::sysctlnametomib(name.as_ptr(), mib.as_mut_ptr(), &mut miblen) } != 0 {
        bail!("vm.swap_info: {}", io::Error::last_os_error());
    }
    let mut devs = Vec::new();
    for i in 0.. {
        let mut m = mib[..miblen].to_vec();
        m.push(i);
        let buf = match sysctl_mib_raw(&m) {
            Ok(b) => b,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => break,
            Err(e) => return Err(e.into()),
        };
        if buf.len() < size_of::<XswDev>() {
            break;
        }
        let x: XswDev = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        let name = if x.dev == NODEV {
            "[NFS swap]".to_string()
        } else {
            let p = unsafe { libc::devname(x.dev as libc::dev_t, libc::S_IFCHR) };
            if p.is_null() {
                format!("swap{i}")
            } else {
                format!("/dev/{}", unsafe { CStr::from_ptr(p) }.to_string_lossy())
            }
        };
        devs.push(SwapDev {
            name,
            total: x.nblks.max(0) as u64 * pagesize,
            used: x.used.max(0) as u64 * pagesize,
        });
    }
    Ok(devs)
}

fn vm_counters(mibs: &Mibs) -> VmCounters {
    VmCounters {
        context_switches: mibs.v_swtch.uint_or_zero(),
        interrupts: mibs.v_intr.uint_or_zero(),
        syscalls: mibs.v_syscall.uint_or_zero(),
        traps: mibs.v_trap.uint_or_zero(),
        forks: mibs.v_forks.uint_or_zero() + mibs.v_vforks.uint_or_zero() + mibs.v_rforks.uint_or_zero(),
        faults: mibs.v_vm_faults.uint_or_zero(),
        swap_pages_in: mibs.v_swappgsin.uint_or_zero(),
        swap_pages_out: mibs.v_swappgsout.uint_or_zero(),
        swap_ins: mibs.v_swapin.uint_or_zero(),
        swap_outs: mibs.v_swapout.uint_or_zero(),
        vnode_ins: mibs.v_vnodein.uint_or_zero(),
        vnode_outs: mibs.v_vnodeout.uint_or_zero(),
        vnode_pages_in: mibs.v_vnodepgsin.uint_or_zero(),
        vnode_pages_out: mibs.v_vnodepgsout.uint_or_zero(),
        zero_fill_faults: mibs.v_zfod.uint_or_zero(),
        cow_faults: mibs.v_cow_faults.uint_or_zero(),
        intransit_faults: mibs.v_intrans.uint_or_zero(),
        reactivated: mibs.v_reactivated.uint_or_zero(),
        pages_freed: mibs.v_tfree.uint_or_zero(),
        pageout_wakeups: mibs.v_pdwakeups.uint_or_zero(),
        pageout_scanned: mibs.v_pdpages.uint_or_zero(),
    }
}

/// `struct vmtotal` from <sys/vmmeter.h>: nine uint64_t memory totals, then
/// int16_t thread counts (run queue, disk wait, page wait, sleeping).
pub(crate) fn parse_vmtotal(buf: &[u8]) -> Option<RunQueue> {
    let at = |off: usize| -> Option<u64> {
        let b = buf.get(off..off + 2)?;
        Some(i16::from_ne_bytes([b[0], b[1]]).max(0) as u64)
    };
    Some(RunQueue { runnable: at(72)?, disk_wait: at(74)?, page_wait: at(76)?, sleeping: at(78)? })
}

fn superpages(mibs: &Mibs) -> Option<Superpages> {
    Some(Superpages {
        enabled: mibs.pg_ps_enabled.int().unwrap_or(0) != 0,
        mappings: mibs.pde_mappings.uint().ok()?,
        promotions: mibs.pde_promotions.uint().ok()?,
        demotions: mibs.pde_demotions.uint().ok()?,
        failures: mibs.pde_failures.uint_or_zero(),
    })
}

fn loadavg() -> [f64; 3] {
    let mut l = [0f64; 3];
    unsafe { libc::getloadavg(l.as_mut_ptr(), 3) };
    l
}

fn uptime() -> f64 {
    let mut ts = MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_UPTIME, ts.as_mut_ptr()) } != 0 {
        return 0.0;
    }
    let ts = unsafe { ts.assume_init() };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

fn disks(mibs: &Mibs) -> Result<Vec<Disk>> {
    Ok(parse_devstat(&mibs.devstat_all.raw()?))
}

/// kern.devstat.all: a `long` generation number followed by the devstat array.
pub(crate) fn parse_devstat(buf: &[u8]) -> Vec<Disk> {
    let hdr = size_of::<libc::c_long>();
    let sz = size_of::<DevStat>();
    if buf.len() < hdr {
        return Vec::new();
    }
    let mut out = Vec::new();
    for chunk in buf[hdr..].chunks_exact(sz) {
        let d: DevStat = unsafe { std::ptr::read_unaligned(chunk.as_ptr().cast()) };
        if d.device_type & DEVSTAT_TYPE_PASS != 0 {
            continue;
        }
        out.push(devstat_to_disk(format!("{}{}", cchars(&d.device_name), d.unit_number), &d));
    }
    out
}

fn nets() -> Result<Vec<NetIf>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        bail!("getifaddrs: {}", io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_data.is_null() {
            continue;
        }
        if unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_LINK {
            continue;
        }
        let d: libc::if_data = unsafe { std::ptr::read_unaligned(ifa.ifa_data.cast()) };
        out.push(NetIf {
            name: unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned(),
            up: ifa.ifa_flags & libc::IFF_UP as u32 != 0,
            mtu: d.ifi_mtu,
            baudrate: d.ifi_baudrate,
            rx_bytes: d.ifi_ibytes,
            tx_bytes: d.ifi_obytes,
            rx_packets: d.ifi_ipackets,
            tx_packets: d.ifi_opackets,
            rx_errors: d.ifi_ierrors,
            tx_errors: d.ifi_oerrors,
            rx_drops: d.ifi_iqdrops,
            tx_drops: d.ifi_oqdrops,
        });
    }
    unsafe { libc::freeifaddrs(ifap) };
    Ok(out)
}

/// Pseudo filesystems that have no meaningful capacity.
const SKIP_FS: &[&str] = &["devfs", "fdescfs", "procfs", "linprocfs", "linsysfs", "autofs", "nullfs", "mqueuefs"];

fn filesystems() -> Result<Vec<Filesystem>> {
    let mut mnt: *mut libc::statfs = std::ptr::null_mut();
    let n = unsafe { libc::getmntinfo(&mut mnt, libc::MNT_NOWAIT) };
    if n <= 0 {
        bail!("getmntinfo: {}", io::Error::last_os_error());
    }
    let list = unsafe { std::slice::from_raw_parts(mnt, n as usize) };
    Ok(list
        .iter()
        .filter_map(|cached| {
            let fstype = cchars(&cached.f_fstypename);
            if SKIP_FS.contains(&fstype.as_str()) {
                return None;
            }
            // MNT_NOWAIT returns the kernel's cached counters, which can lag by
            // gigabytes; refresh local filesystems like df(1) does. Network
            // filesystems keep the cached values so a dead server can't hang us.
            let mut fresh = MaybeUninit::<libc::statfs>::uninit();
            let s = if cached.f_flags & libc::MNT_LOCAL != 0
                && unsafe { libc::statfs(cached.f_mntonname.as_ptr(), fresh.as_mut_ptr()) } == 0
            {
                unsafe { fresh.assume_init() }
            } else {
                *cached
            };
            if s.f_blocks == 0 {
                return None;
            }
            let bs = s.f_bsize;
            Some(Filesystem {
                device: cchars(&s.f_mntfromname),
                mountpoint: cchars(&s.f_mntonname),
                fstype,
                total: s.f_blocks * bs,
                free: s.f_bfree * bs,
                avail: s.f_bavail.max(0) as u64 * bs,
            })
        })
        .collect())
}

fn proc_state(stat: libc::c_char) -> &'static str {
    match stat as i32 {
        1 => "idle",
        2 => "running",
        3 => "sleeping",
        4 => "stopped",
        5 => "zombie",
        6 => "waiting",
        7 => "locked",
        _ => "unknown",
    }
}

/// Processes plus each one's start time (seconds), used to key the args cache.
fn processes(pagesize: u64) -> Result<(Vec<Process>, Vec<i64>)> {
    parse_procs(&sysctl_mib_raw(&[libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PROC, 0])?, pagesize)
}

pub(crate) fn parse_procs(buf: &[u8], pagesize: u64) -> Result<(Vec<Process>, Vec<i64>)> {
    if buf.len() < size_of::<libc::c_int>() {
        return Ok(Default::default());
    }
    // Trust the kernel's record size; it's the ABI contract for kinfo_proc.
    let stride = i32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
    if stride < size_of::<libc::kinfo_proc>() {
        bail!("kinfo_proc size {stride} smaller than expected {}", size_of::<libc::kinfo_proc>());
    }
    Ok(buf
        .chunks_exact(stride)
        .filter_map(|c| {
            let k: libc::kinfo_proc = unsafe { std::ptr::read_unaligned(c.as_ptr().cast()) };
            let command = cchars(&k.ki_comm);
            // The kernel's idle threads would always top the list (like top -S).
            if k.ki_flag & libc::P_SYSTEM as libc::c_long != 0 && command == "idle" {
                return None;
            }
            let tv_us = |tv: &libc::timeval| {
                (tv.tv_sec.max(0) as u64).saturating_mul(1_000_000) + (tv.tv_usec.max(0) as u64)
            };
            let start_time = (k.ki_start.tv_sec as i64)
                .saturating_mul(1_000_000)
                .saturating_add(k.ki_start.tv_usec as i64);
            let p = Process {
                pid: k.ki_pid,
                ppid: k.ki_ppid,
                uid: k.ki_uid,
                user: String::new(),
                command,
                args: String::new(),
                jid: k.ki_jid,
                state: proc_state(k.ki_stat),
                threads: k.ki_numthreads.max(0) as u32,
                start_time,
                cpu_time_us: k.ki_runtime,
                user_time_us: tv_us(&k.ki_rusage.ru_utime),
                sys_time_us: tv_us(&k.ki_rusage.ru_stime),
                rss: k.ki_rssize.max(0) as u64 * pagesize,
                vsize: k.ki_size as u64,
                read_ops: k.ki_rusage.ru_inblock.max(0) as u64,
                write_ops: k.ki_rusage.ru_oublock.max(0) as u64,
                minor_faults: k.ki_rusage.ru_minflt.max(0) as u64,
                major_faults: k.ki_rusage.ru_majflt.max(0) as u64,
            };
            Some((p, start_time))
        })
        .unzip())
}

/// kern.proc.args.<pid>: NUL-separated argv. Fails for processes we may not inspect.
fn proc_args(pid: i32) -> Option<String> {
    let buf = sysctl_mib_raw(&[libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ARGS, pid]).ok()?;
    let args: Vec<String> = buf
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    Some(args.join(" "))
}

// ---------------------------------------------------------------------------
// Sensors

fn sysctl_celsius(name: &str) -> Option<f64> {
    deci_kelvin_to_celsius(sysctl_uint(name).ok()?)
}

fn sensors(mibs: &Mibs) -> Sensors {
    let cpu_temps: Vec<f64> = mibs.cpu_temps.iter().map_while(Mib::celsius).collect();
    let thermal_zones = (0..)
        .map_while(|i| {
            let base = format!("hw.acpi.thermal.tz{i}");
            sysctl_int(&format!("{base}.active"))?;
            Some((format!("tz{i}"), sysctl_celsius(&format!("{base}.temperature"))))
        })
        .filter_map(|(n, t)| Some((n, t?)))
        .collect();
    let cpu_freqs_mhz: Vec<u64> =
        mibs.cpu_freqs.iter().map_while(Mib::int).map(|f| f.max(0) as u64).collect();
    Sensors {
        cpu_temps,
        cpu_tjmax: mibs.cpu_tjmax.celsius(),
        cpu_freq_mhz: cpu_freqs_mhz.first().copied(),
        cpu_freqs_mhz,
        thermal_zones,
        battery: None,
    }
}

fn battery() -> Option<Battery> {
    (sysctl_int("hw.acpi.battery.units").unwrap_or(0) > 0).then(|| {
        let state = sysctl_int("hw.acpi.battery.state").unwrap_or(0);
        let minutes = sysctl_int("hw.acpi.battery.time").unwrap_or(-1);
        Battery {
            life: sysctl_int("hw.acpi.battery.life").unwrap_or(0).clamp(0, 100) as f64,
            minutes_left: (minutes >= 0).then_some(minutes as u64),
            state: if state & 4 != 0 {
                "critical"
            } else if state & 1 != 0 {
                "discharging"
            } else if state & 2 != 0 {
                "charging"
            } else {
                "full"
            },
            ac_online: sysctl_int("hw.acpi.acline").unwrap_or(0) == 1,
        }
    })
}

// ---------------------------------------------------------------------------
// TCP

/// TCP_NSTATES order from <netinet/tcp_fsm.h>, named as in OTel semconv.
const TCP_STATES: [&str; 11] = [
    "close",
    "listen",
    "syn_sent",
    "syn_recv",
    "established",
    "close_wait",
    "fin_wait_1",
    "closing",
    "last_ack",
    "fin_wait_2",
    "time_wait",
];

fn tcp(mibs: &Mibs) -> Result<Option<Tcp>> {
    let stats = mibs.tcp_stats.raw()?;
    let states = mibs.tcp_states.raw().unwrap_or_default();
    Ok(parse_tcp(&stats, &states))
}

fn udp(mibs: &Mibs) -> Option<Udp> {
    parse_udp(&mibs.udp_stats.raw().ok()?)
}

/// `struct udpstat` from <netinet/udp_var.h>: uint64_t counters. Index 8 and
/// 9 are the pcb cache/hash misses; output counters start at 10.
pub(crate) fn parse_udp(stats: &[u8]) -> Option<Udp> {
    let v: Vec<u64> = stats.as_chunks::<8>().0.iter().map(|c| u64::from_ne_bytes(*c)).collect();
    if v.len() <= 10 {
        return None;
    }
    Some(Udp {
        datagrams_in: v[0],
        in_errors: v[1].saturating_add(v[2]).saturating_add(v[4]),
        no_ports: v[5],
        full_socket_buffers: v[7],
        datagrams_out: v[10],
    })
}

/// `struct tcpstat` is all uint64_t counters; indices from <netinet/tcp_var.h>.
pub(crate) fn parse_tcp(stats: &[u8], states: &[u8]) -> Option<Tcp> {
    let u64s = |b: &[u8]| -> Vec<u64> {
        b.as_chunks::<8>().0.iter().map(|c| u64::from_ne_bytes(*c)).collect()
    };
    let v = u64s(stats);
    if v.len() <= 63 {
        return None;
    }
    let st = u64s(states);
    Some(Tcp {
        conn_attempts: v[0],
        accepts: v[1],
        drops: v[3],
        segs_sent: v[17],
        retransmits: v[20],
        segs_received: v[28],
        bad_checksums: v[31],
        listen_drops: v[63],
        states: TCP_STATES.iter().zip(st).map(|(n, c)| (*n, c)).collect(),
    })
}

// ---------------------------------------------------------------------------
// Jails

fn jails() -> Result<Vec<Jail>> {
    let mut out = Vec::new();
    let mut lastjid: libc::c_int = 0;
    loop {
        let mut jid: libc::c_int = 0;
        let mut name = [0u8; 256];
        let mut host = [0u8; 256];
        let iov = |b: *mut libc::c_void, len: usize| libc::iovec { iov_base: b, iov_len: len };
        let key = |k: &'static [u8]| iov(k.as_ptr() as *mut libc::c_void, k.len());
        let mut v = [
            key(b"lastjid\0"),
            iov((&mut lastjid as *mut libc::c_int).cast(), size_of::<libc::c_int>()),
            key(b"jid\0"),
            iov((&mut jid as *mut libc::c_int).cast(), size_of::<libc::c_int>()),
            key(b"name\0"),
            iov(name.as_mut_ptr().cast(), name.len()),
            key(b"host.hostname\0"),
            iov(host.as_mut_ptr().cast(), host.len()),
        ];
        let r = unsafe { libc::jail_get(v.as_mut_ptr(), v.len() as u32, 0) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                break;
            }
            return Err(e.into());
        }
        lastjid = r;
        out.push(Jail { jid, name: cstr_bytes(&name), hostname: cstr_bytes(&host) });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ZFS

fn zpool_list() -> Result<Vec<ZPool>> {
    let out = std::process::Command::new("zpool")
        .args(["list", "-Hp", "-o", "name,size,alloc,free,frag,health"])
        .stderr(std::process::Stdio::null())
        .output()
        .context("running zpool")?;
    if !out.status.success() {
        bail!("zpool list exited with {}", out.status);
    }
    Ok(parse_zpool_list(&String::from_utf8_lossy(&out.stdout)))
}

pub(crate) fn parse_zpool_list(text: &str) -> Vec<ZPool> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 6 {
                return None;
            }
            Some(ZPool {
                name: f[0].to_string(),
                size: f[1].parse().ok()?,
                allocated: f[2].parse().ok()?,
                free: f[3].parse().ok()?,
                fragmentation: f[4].trim_end_matches('%').parse().ok(),
                health: f[5].to_string(),
                ..Default::default()
            })
        })
        .collect()
}

/// Logical pool I/O: OpenZFS keeps per-dataset counters under
/// kstat.zfs.<pool>.dataset.objset-0x<id>. Finds each dataset's
/// nread/nwritten/reads/writes MIBs.
fn dataset_mibs(pool: &str) -> Vec<[Vec<libc::c_int>; 4]> {
    let mut sets: HashMap<String, [Vec<libc::c_int>; 4]> = HashMap::new();
    for (name, mib) in sysctl_children(&format!("kstat.zfs.{pool}.dataset")) {
        let Some((objset, field)) = name.rsplit_once('.') else { continue };
        let slot = match field {
            "nread" => 0,
            "nwritten" => 1,
            "reads" => 2,
            "writes" => 3,
            _ => continue,
        };
        sets.entry(objset.to_string()).or_default()[slot] = mib;
    }
    sets.into_values().filter(|m| m.iter().all(|x| !x.is_empty())).collect()
}

/// Sums [read bytes, written bytes, reads, writes] over a pool's datasets.
fn pool_io(mibs: &[[Vec<libc::c_int>; 4]]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for set in mibs {
        for (total, mib) in out.iter_mut().zip(set) {
            if let Ok(v) = sysctl_mib_uint(mib) {
                *total += v;
            }
        }
    }
    out
}

/// Leaf names and MIBs below a sysctl node, walked with the sysctl.next interface.
fn sysctl_children(prefix: &str) -> Vec<(String, Vec<libc::c_int>)> {
    let Ok(cname) = CString::new(prefix) else { return Vec::new() };
    let mut mib = [0 as libc::c_int; libc::CTL_MAXNAME as usize];
    let mut len: libc::size_t = mib.len();
    if unsafe { libc::sysctlnametomib(cname.as_ptr(), mib.as_mut_ptr(), &mut len) } != 0 {
        return Vec::new();
    }
    let root: Vec<libc::c_int> = mib[..len].to_vec();
    let mut cur = root.clone();
    let mut out = Vec::new();
    loop {
        // {CTL_SYSCTL, CTL_SYSCTL_NEXT, <oid>} returns the next oid in the tree.
        let mut q = vec![0, 2];
        q.extend_from_slice(&cur);
        let mut next = [0 as libc::c_int; libc::CTL_MAXNAME as usize];
        let mut nlen: libc::size_t = size_of_val(&next);
        let rc = unsafe {
            libc::sysctl(q.as_ptr(), q.len() as u32, next.as_mut_ptr().cast(), &mut nlen, std::ptr::null(), 0)
        };
        if rc != 0 {
            break;
        }
        cur = next[..nlen / size_of::<libc::c_int>()].to_vec();
        if !cur.starts_with(&root) {
            break;
        }
        // {CTL_SYSCTL, CTL_SYSCTL_NAME, <oid>} gives the dotted name.
        let mut q = vec![0, 1];
        q.extend_from_slice(&cur);
        if let Ok(name) = sysctl_mib_raw(&q) {
            out.push((cstr_bytes(&name), cur.clone()));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// GEOM statistics (partitions, mirrors, encrypted providers)

/// GEOM classes whose providers are worth showing next to whole disks.
/// LABEL (gptid/..., diskid/...) only aliases other providers, and DISK
/// providers are the whole disks themselves.
const GEOM_CLASSES: &[&str] = &["PART", "MIRROR", "STRIPE", "CONCAT", "RAID", "RAID3", "ELI"];

/// DIOCGMEDIASIZE = _IOR('d', 129, off_t)
const DIOCGMEDIASIZE: libc::c_ulong = 0x4008_6481;

/// Reads the kernel's GEOM devstat pages from /dev/devstat, as gstat(8) and
/// libgeom do. These entries aren't in kern.devstat.all; each one's `id` is
/// the address of its GEOM provider, named in kern.geom.confxml.
struct GeomStats {
    fd: std::fs::File,
    map: *const u8,
    len: usize,
    names: HashMap<usize, String>,
    names_at: Instant,
}

impl GeomStats {
    fn open() -> Result<GeomStats> {
        let fd = std::fs::File::open("/dev/devstat").context("opening /dev/devstat")?;
        let mut g = GeomStats { fd, map: std::ptr::null(), len: 0, names: HashMap::new(), names_at: Instant::now() };
        g.remap()?;
        g.names = geom_providers();
        Ok(g)
    }

    /// (Re)maps the stats area when the kernel has grown it.
    fn remap(&mut self) -> Result<()> {
        use std::os::fd::AsRawFd;
        let mut size: libc::off_t = 0;
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), DIOCGMEDIASIZE, &mut size) } != 0 {
            bail!("DIOCGMEDIASIZE: {}", io::Error::last_os_error());
        }
        let size = size.max(0) as usize;
        if size == self.len {
            return Ok(());
        }
        if !self.map.is_null() {
            unsafe { libc::munmap(self.map as *mut libc::c_void, self.len) };
            self.map = std::ptr::null();
            self.len = 0;
        }
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ, libc::MAP_SHARED, self.fd.as_raw_fd(), 0)
        };
        if p == libc::MAP_FAILED {
            bail!("mmap /dev/devstat: {}", io::Error::last_os_error());
        }
        self.map = p as *const u8;
        self.len = size;
        Ok(())
    }

    fn read(&mut self) -> Vec<Disk> {
        if self.remap().is_err() || self.map.is_null() {
            return Vec::new();
        }
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as usize;
        let per_page = page / size_of::<DevStat>();
        let mut out = Vec::new();
        let mut unknown = false;
        for pg in 0..self.len / page {
            for i in 0..per_page {
                let ptr = unsafe { self.map.add(pg * page + i * size_of::<DevStat>()) };
                // Entries change under us; retry until the sequence numbers agree.
                let mut d: DevStat = unsafe { std::ptr::read_volatile(ptr.cast()) };
                for _ in 0..3 {
                    if d.sequence0 == d.sequence1 {
                        break;
                    }
                    d = unsafe { std::ptr::read_volatile(ptr.cast()) };
                }
                if d.id.is_null() || d.sequence0 != d.sequence1 {
                    continue;
                }
                match self.names.get(&(d.id as usize)) {
                    Some(name) => out.push(devstat_to_disk(name.clone(), &d)),
                    None => unknown = true,
                }
            }
        }
        // New providers appear when disks are attached or partitioned.
        if unknown && self.names_at.elapsed() >= Duration::from_secs(10) {
            self.names = geom_providers();
            self.names_at = Instant::now();
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

impl Drop for GeomStats {
    fn drop(&mut self) {
        if !self.map.is_null() {
            unsafe { libc::munmap(self.map as *mut libc::c_void, self.len) };
        }
    }
}

// The mapping is read-only and only touched by the sampler thread.
unsafe impl Send for GeomStats {}

fn devstat_to_disk(name: String, d: &DevStat) -> Disk {
    Disk {
        name,
        read_bytes: d.bytes[DEVSTAT_READ],
        write_bytes: d.bytes[DEVSTAT_WRITE],
        read_ops: d.operations[DEVSTAT_READ],
        write_ops: d.operations[DEVSTAT_WRITE],
        busy_secs: bintime_secs(&d.busy_time),
        read_secs: bintime_secs(&d.duration[DEVSTAT_READ]),
        write_secs: bintime_secs(&d.duration[DEVSTAT_WRITE]),
        queue: d.start_count.wrapping_sub(d.end_count) as u64,
    }
}

fn geom_providers() -> HashMap<usize, String> {
    sysctl_string("kern.geom.confxml").map(|x| parse_confxml(&x)).unwrap_or_default()
}

/// Provider id -> name for providers of the classes in GEOM_CLASSES.
pub(crate) fn parse_confxml(xml: &str) -> HashMap<usize, String> {
    let mut out = HashMap::new();
    let mut class = String::new();
    let mut want_class = false;
    let mut provider: Option<usize> = None;
    for line in xml.lines().map(str::trim) {
        if line.starts_with("<class id=") {
            want_class = true;
        } else if let Some(rest) = line.strip_prefix("<provider id=\"0x") {
            provider = usize::from_str_radix(rest.trim_end_matches("\">"), 16).ok();
        } else if let Some(name) = line.strip_prefix("<name>").and_then(|n| n.strip_suffix("</name>")) {
            if want_class {
                class = name.to_string();
                want_class = false;
            } else if let Some(id) = provider.take()
                && GEOM_CLASSES.contains(&class.as_str())
            {
                out.insert(id, name.to_string());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// NFS

fn nfs() -> Result<Nfs> {
    let out = std::process::Command::new("nfsstat")
        .args(["--libxo", "json"])
        .stderr(std::process::Stdio::null())
        .output()
        .context("running nfsstat")?;
    if !out.status.success() {
        bail!("nfsstat exited with {}", out.status);
    }
    parse_nfsstat(&out.stdout)
}

pub(crate) fn parse_nfsstat(json: &[u8]) -> Result<Nfs> {
    let v: serde_json::Value = serde_json::from_slice(json).context("parsing nfsstat output")?;
    let root = &v["nfsstat"];
    let ops = |section: &str| -> Vec<(String, u64)> {
        root[section]["operations"]
            .as_object()
            .map(|m| m.iter().filter_map(|(k, v)| Some((k.clone(), v.as_u64()?))).collect())
            .unwrap_or_default()
    };
    let rpc = |k: &str| root["clientstats"]["rpcs"][k].as_u64().unwrap_or(0);
    Ok(Nfs {
        client_ops: ops("clientstats"),
        client_requests: rpc("requests"),
        client_retries: rpc("retries"),
        client_timeouts: rpc("timedout"),
        server_ops: ops("serverstats"),
    })
}

/// Parsers checked against raw sysctl data captured from a FreeBSD 15.1
/// machine (`sysctl -b ...`), next to what the base tools printed for it.
#[cfg(test)]
mod fixtures {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}{name}")).unwrap()
    }

    #[test]
    fn cp_times_match_sysctl_text() {
        let ticks = parse_cp_times(&read("cp_times.bin"));
        let text: Vec<u64> = String::from_utf8(read("cp_times.txt"))
            .unwrap()
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(ticks.len(), 8);
        let flat: Vec<u64> = ticks.iter().flat_map(|t| [t.user, t.nice, t.system, t.interrupt, t.idle]).collect();
        assert_eq!(flat.len(), text.len());
        // The text copy was read a moment later, so counters may have ticked on.
        for (bin, txt) in flat.iter().zip(&text) {
            assert!(txt >= bin && txt - bin < 500, "binary {bin} vs text {txt}");
        }
    }

    #[test]
    fn devstat_finds_the_disk() {
        let disks = parse_devstat(&read("devstat.bin"));
        let ada0 = disks.iter().find(|d| d.name == "ada0").expect("ada0");
        assert!(ada0.write_bytes > 0 && ada0.write_ops > 0);
        assert!(ada0.busy_secs > 0.0 && ada0.write_secs > 0.0);
        assert!(disks.iter().all(|d| !d.name.starts_with("pass")));
    }

    #[test]
    fn kinfo_proc_records() {
        let (procs, starts) = parse_procs(&read("procs.bin"), 4096).unwrap();
        assert_eq!(procs.len(), starts.len());
        let kernel = procs.iter().find(|p| p.pid == 0).expect("pid 0");
        assert_eq!(kernel.command, "kernel");
        let init = procs.iter().find(|p| p.pid == 1).expect("pid 1");
        assert_eq!(init.command, "init");
        assert_eq!((init.uid, init.ppid, init.jid), (0, 0, 0));
        assert!(init.rss > 0 && init.vsize > init.rss);
    }

    #[test]
    fn tcpstat_matches_netstat() {
        let tcp = parse_tcp(&read("tcpstats.bin"), &read("tcpstates.bin")).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&read("tcp.json")).unwrap();
        let n = |k: &str| json["statistics"]["tcp"][k].as_u64().unwrap();
        assert_eq!(tcp.segs_sent, n("sent-packets"));
        assert_eq!(tcp.segs_received, n("received-packets"));
        assert_eq!(tcp.retransmits, n("sent-retransmitted-packets"));
        assert_eq!(tcp.listen_drops, n("listen-queue-overflows"));
        assert_eq!(tcp.conn_attempts, n("connection-requests"));
        assert_eq!(tcp.accepts, n("connections-accepts"));
        assert_eq!(tcp.drops, n("connection-drops"));
        assert_eq!(tcp.bad_checksums, n("discard-bad-checksum"));
        assert_eq!(tcp.states.iter().find(|s| s.0 == "listen").unwrap().1, 7);
    }

    #[test]
    fn zpool_list_output() {
        let pools = parse_zpool_list("zroot\t498216206336\t143343964160\t354872242176\t12%\tONLINE\ntank\t100\t50\t50\t-\tDEGRADED\n");
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].name, "zroot");
        assert_eq!(pools[0].allocated, 143343964160);
        assert_eq!(pools[0].fragmentation, Some(12));
        assert_eq!(pools[1].fragmentation, None);
        assert_eq!(pools[1].health, "DEGRADED");
    }
}

#[cfg(test)]
mod fixtures_more {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}{name}")).unwrap()
    }

    #[test]
    fn vmtotal_thread_counts() {
        // Captured with 1 runnable thread, none in disk or page wait, 48 sleeping.
        let rq = parse_vmtotal(&read("vmtotal.bin")).unwrap();
        assert_eq!((rq.runnable, rq.disk_wait, rq.page_wait, rq.sleeping), (1, 0, 0, 48));
        assert!(parse_vmtotal(&[0u8; 10]).is_none());
    }

    #[test]
    fn confxml_keeps_partitions_not_disks_or_labels() {
        let xml = String::from_utf8(read("confxml.xml")).unwrap();
        let mut names: Vec<String> = parse_confxml(&xml).into_values().collect();
        names.sort();
        assert_eq!(names, ["ada0p1", "ada0p2", "ada0p3", "ada0p4", "ada0p5"]);
    }

    #[test]
    fn nfsstat_json() {
        let nfs = parse_nfsstat(&read("nfsstat.json")).unwrap();
        assert_eq!(nfs.client_ops.len(), 21);
        assert!(nfs.client_ops.iter().any(|(op, _)| op == "getattr"));
        assert_eq!(nfs.server_ops.len(), 21);
        assert!(parse_nfsstat(b"not json").is_err());
    }

    #[test]
    fn udpstat_counters() {
        let mut raw = Vec::new();
        // ipackets, hdrops, badsum, nosum, badlen, noport, noportbcast,
        // fullsock, pcbcachemiss, pcbhashmiss, opackets
        for v in [100u64, 1, 2, 0, 3, 5, 0, 7, 9, 11, 200] {
            raw.extend_from_slice(&v.to_ne_bytes());
        }
        let u = parse_udp(&raw).unwrap();
        assert_eq!(u.datagrams_in, 100);
        assert_eq!(u.in_errors, 6);
        assert_eq!(u.no_ports, 5);
        assert_eq!(u.full_socket_buffers, 7);
        assert_eq!(u.datagrams_out, 200);
        assert!(parse_udp(&raw[..80]).is_none());
    }
}
