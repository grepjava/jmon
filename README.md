# jmon

jmon is a performance monitor for FreeBSD modelled on [nmon](https://nmon.sourceforge.io). It can also emit OpenTelemetry metrics.

- **Interactive screen** with nmon's single-key panels:
  - CPU per core, a compact grid for many cores, and a long-term graph
  - memory and swap
  - kernel counters
  - disks, including latency and queue depth
  - network and TCP
  - filesystems
  - ZFS ARC and pools
  - jails and bhyve VMs
  - temperatures, CPU clock and battery
  - top processes, with full command lines, I/O and a per-user filter
- **OTLP push** over gRPC, HTTP/protobuf or HTTP/JSON, optionally over TLS. Names follow the OpenTelemetry semantic conventions.
- **Prometheus** scrape endpoint.
- **Capture files** in nmon CSV format (readable by nmon analyser and nmonchart) or JSON Lines, with daily rotation.

Everything is read through sysctl(3), getifaddrs(3), getmntinfo(3) and jail_get(2). jmon runs as an unprivileged user and takes about 4 ms per sample.

## Build

On FreeBSD 14 or later:

```sh
pkg install rust
cargo build --release
install -m 755 target/release/jmon /usr/local/bin/
install -m 444 man/jmon.1 /usr/local/share/man/man1/
```

- **From another machine:** `scripts/freebsd-build.sh user@host [cargo args]` copies the tree to a FreeBSD host and runs cargo there.
- **Other operating systems:** builds use synthetic demo data, so you can work on the screen and exporters anywhere.
- **Type-checking without FreeBSD:** `cargo check --target x86_64-unknown-freebsd --no-default-features` checks the real collector from any OS. The `tls` feature, on by default, needs a C toolchain for the target, so it's left out of that check.
- **Port:** a skeleton is in [packaging/freebsd/sysutils/jmon](packaging/freebsd/sysutils/jmon).

## Use

```sh
jmon                                       # interactive; press h for keys
jmon --show cmdnt                          # open panels at start (or JMON=cmdnt)
jmon -d --otlp-endpoint http://otel:4317   # headless agent, OTLP/gRPC
jmon -d --otlp-endpoint https://otel:4317 --otlp-ca ca.pem
jmon -d --prometheus 0.0.0.0:9464          # headless agent, scrape endpoint
jmon -f -s 60 --rotate --record-keep 30    # daily .nmon files, kept 30 days
jmon --once                                # one sample as JSON
jmon --disk-group mirror=ada0,ada1         # disk groups (g key, DG* in nmon files)
```

| Key | Panel | Key | Panel |
|-----|-------|-----|-------|
| `c` | CPU by processor, `>` marks peaks | `d` | Disk I/O, latency, queue depth |
| `C` | CPU grid (many cores) | `g` | Disk groups |
| `l` | CPU long-term graph | `o` | Disk busy map |
| `m` | Memory, swap, ZFS ARC | `n` | Network interfaces, packet sizes |
| `V` | Virtual memory detail | `T` | TCP |
| `L` | Superpages | `N` | NFS client and server |
| `k` | Kernel counters, load, run queue | `j` | Filesystems |
| `s` | Temperature, clock, battery | `z` | ZFS ARC and pools |
| `t` | Top processes | `J` | Jails and bhyve VMs |
| `v` | Checks (ok / warning / danger) | `r` | System resources |

In the process list:
- `3`, `4` and `5` sort by CPU, memory or I/O.
- `a` shows full command lines.
- `u` filters by user.
- `/` searches by command, arguments, user or jail.

Anywhere:
- `.` hides idle CPUs, disks, interfaces and processes.
- `p` pauses.
- `w` starts or stops an `.nmon` recording.
- `Up`, `Down`, `PgUp`, `PgDn`, `Home` and `End` scroll overflowing panels or the process list.
- `G` adds partitions and other GEOM providers to the disk views.
- `0` resets the CPU peak markers.
- `b` switches to black and white (also when `NO_COLOR` is set).
- `R` resets the temperature peak.
- `+` and `-` double or halve the interval.

### Configuration

Options can go in `/usr/local/etc/jmon.conf`, or in another file given with `--config`. Keys are the long option names, and command-line options win. See [contrib/jmon.conf.sample](contrib/jmon.conf.sample).

```toml
interval = 10
otlp-endpoint = "https://collector.example.org:4317"
otlp-ca = "/usr/local/etc/ssl/collector-ca.pem"
prometheus = "127.0.0.1:9464"
```

The standard `OTEL_*` variables are honoured, for example:
- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_HEADERS`
- `OTEL_EXPORTER_OTLP_CERTIFICATE`
- `OTEL_RESOURCE_ATTRIBUTES`

### As a service

```sh
install -m 555 contrib/rc.d/jmon /usr/local/etc/rc.d/jmon
cp contrib/jmon.conf.sample /usr/local/etc/jmon.conf   # then edit it
sysrc jmon_enable=YES
service jmon start
```

The service runs as `nobody` under daemon(8), which restarts it if it exits. `service jmon reload` rereads the config file's `interval` and `export-top` without a restart. Logs go to syslog: info messages land in `/var/log/daemon.log`, and warnings also reach `/var/log/messages`.

## Metrics

| Metric | Unit | Attributes |
|--------|------|------------|
| `system.cpu.time`, `system.cpu.utilization` | s, 1 | `cpu.logical_number`, `cpu.mode` |
| `system.cpu.logical.count`, `system.cpu.load_average.{1m,5m,15m}` | | |
| `system.cpu.frequency` | Hz | `cpu.logical_number` |
| `system.memory.usage`, `system.memory.utilization`, `system.memory.limit` | By, 1 | `system.memory.state` (active, inactive, laundry, wired, free) |
| `system.paging.usage`, `.utilization`, `.operations` | | `system.device`, `system.paging.state` / `.direction` |
| `system.disk.io`, `.operations`, `.operation_time`, `.io_time`, `.pending_operations` | | `system.device`, `disk.io.direction` |
| `freebsd.disk.busy`, `freebsd.disk.latency` | 1, s | `system.device`, `disk.io.direction` |
| `system.network.io`, `.packets`, `.errors`, `.dropped` | | `network.interface.name`, `network.io.direction` |
| `system.network.connections` | | `network.transport`, `network.connection.state` |
| `freebsd.tcp.{segments,retransmitted_segments,listen_queue_overflows,accepts,connect_attempts}` | | |
| `freebsd.udp.{datagrams,errors,dropped}` | | `network.io.direction`, `freebsd.udp.drop_reason` |
| `system.filesystem.usage`, `.utilization` | By, 1 | `system.device`, `system.filesystem.{mountpoint,type,state}` |
| `system.process.count`, `system.process.created`, `system.uptime` | | `process.state` |
| `freebsd.threads.count` | | `freebsd.thread.state` (runnable, disk_wait, page_wait, sleeping) |
| `freebsd.vm.faults`, `freebsd.vm.pager.{operations,pages}` | | `freebsd.vm.fault_type`; `freebsd.vm.pager`, `system.paging.direction` |
| `freebsd.vm.{reactivated_pages,freed_pages}`, `freebsd.vm.pageout.{scanned_pages,wakeups}` | | |
| `freebsd.vm.superpage.operations` | | `freebsd.vm.superpage.operation` |
| `freebsd.nfs.{client,server}.operations`, `freebsd.nfs.client.rpc.{retries,timeouts}` | | `nfs.operation` |
| `freebsd.kernel.{context_switches,interrupts,syscalls,traps}`, `freebsd.vm.page_faults` | | |
| `hw.temperature` | Cel | `hw.id`, `hw.type` (cpu, thermal_zone) |
| `hw.battery.charge`, `hw.battery.time_left` | 1, s | `hw.id`, `hw.battery.state` |
| `freebsd.jail.{cpu.utilization,memory.usage,process.count,io.operations}` | | `freebsd.jail.id`, `freebsd.jail.name` |
| `freebsd.bhyve.{cpu.utilization,memory.usage}` | | `freebsd.bhyve.vm.name` |
| `freebsd.zfs.arc.{size,target_size,hits,misses,hit_ratio}`, `freebsd.zfs.l2arc.size` | | |
| `freebsd.zfs.pool.{usage,fragmentation,health,io,operations}` | | `zfs.pool.name`, `zfs.pool.state` / `.health`, `disk.io.direction` |
| `process.{cpu.time,cpu.utilization,memory.usage,memory.virtual,disk.operations,paging.faults}` | | `process.pid`, `process.executable.name`, `process.owner`. Only emitted with `--export-top N` |
| `jmon.collection.duration`, `jmon.otlp.exports`, `jmon.prometheus.scrapes` | | `result` |

In Prometheus output, dots become underscores and the usual suffixes are added (for example `system_cpu_time_seconds_total`).

## Testing

`cargo test` runs:
- unit tests
- screen rendering tests, using demo data
- on FreeBSD, parser tests against kernel data captured from a real machine in [tests/fixtures](tests/fixtures)

The fixture tests check jmon's parsers against what `sysctl` and `netstat` printed for the same data.

## Notes

- CPU temperatures need `kldload coretemp` (Intel) or `amdtemp` (AMD).
- FreeBSD has no iowait, so the nmon `Wait%` column is always 0. Interrupt time is counted as system time in nmon files.
- ZFS pool capacity comes from `zpool list`. It refreshes every 30 s, or every 5 s while pools are being written.
- Battery readings run ACPI methods, so they refresh every 30 s.
- Jails created by podman are named after their 64-character container ID. The screen shortens them.
- Partitions are shown and recorded but not exported, since they would double-count their disks.
- NFS statistics come from `nfsstat`. It only runs while NFS is in use: an NFS mount exists or `nfsd` is running.
- FreeBSD keeps no count of `exec` calls, so nmon's exec rate isn't available.

### Recording hooks

Like nmon, `NMON_START`, `NMON_SNAP` and `NMON_END` (or the `JMON_` versions) name shell commands run during an nmon recording. The snapshot hook gets the tag (`T0001`, ...) as `$1`, and each hook's output is appended to the file:

```sh
NMON_SNAP='echo "LOADAVG,$1,$(sysctl -n vm.loadavg | cut -d" " -f2)"' jmon -f -s 60
```
