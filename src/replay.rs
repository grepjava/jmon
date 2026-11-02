//! Plays a JSON Lines recording back through the screen (`--replay`): at the
//! recorded pace or faster, with pause, step and seek.

use crate::sample::{Hub, Sample};
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::warn;

/// A recording indexed by line, so a day of samples is never all in memory.
pub struct Recording {
    path: PathBuf,
    file: BufReader<File>,
    offsets: Vec<u64>,
}

impl Recording {
    pub fn open(path: &Path) -> Result<Recording> {
        let mut file = BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
        let mut magic = [0u8; 2];
        if file.read(&mut magic)? == 2 && magic == [0x1f, 0x8b] {
            bail!("{} is gzip-compressed; gunzip it first", path.display());
        }
        file.seek(SeekFrom::Start(0))?;
        let mut offsets = Vec::new();
        let (mut at, mut line) = (0u64, Vec::new());
        loop {
            line.clear();
            let n = file.read_until(b'\n', &mut line)?;
            if n == 0 {
                break;
            }
            if line.iter().any(|b| !b.is_ascii_whitespace()) {
                offsets.push(at);
            }
            at += n as u64;
        }
        if offsets.is_empty() {
            bail!("{} has no samples", path.display());
        }
        let mut rec = Recording { path: path.to_path_buf(), file, offsets };
        rec.read(0).with_context(|| {
            format!("{} is not a jmon JSON Lines recording (record with --record-format jsonl)", path.display())
        })?;
        Ok(rec)
    }

    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    pub fn read(&mut self, i: usize) -> Result<Sample> {
        self.file.seek(SeekFrom::Start(self.offsets[i]))?;
        let mut line = String::new();
        self.file.read_line(&mut line)?;
        serde_json::from_str(&line).with_context(|| format!("{} line {}", self.path.display(), i + 1))
    }
}

pub enum Cmd {
    /// Pause, or play (from the start once at the end).
    Toggle,
    /// Pause and move this many samples.
    Step(i64),
    /// Move by this fraction of the recording.
    Seek(f64),
    /// Multiply the playback speed.
    Speed(f64),
}

#[derive(Debug, Clone, Copy)]
pub struct Position {
    pub index: usize,
    pub len: usize,
    pub speed: f64,
    pub playing: bool,
}

/// The screen's handle on the player.
pub struct Control {
    tx: mpsc::Sender<Cmd>,
    pos: Arc<Mutex<Position>>,
}

impl Control {
    pub fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }

    pub fn position(&self) -> Position {
        *self.pos.lock().unwrap()
    }
}

/// Publishes the recording's samples into `hub` at the recorded pace times
/// the speed, until the hub is stopped.
pub fn spawn(hub: Arc<Hub>, mut rec: Recording) -> Result<(Control, JoinHandle<()>)> {
    let (tx, rx) = mpsc::channel();
    let len = rec.len();
    let pos = Arc::new(Mutex::new(Position { index: 0, len, speed: 1.0, playing: true }));
    let shared = pos.clone();
    let thread = std::thread::Builder::new().name("replay".into()).spawn(move || {
        let mut p = Position { index: 0, len, speed: 1.0, playing: true };
        // The sample on screen, and the next one, read ahead to know when it is due.
        let mut cur: Option<Arc<Sample>> = None;
        let mut next: Option<(usize, Arc<Sample>)> = None;
        let load = |rec: &mut Recording, i: usize| match rec.read(i) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                warn!("replay: {e:#}");
                None
            }
        };
        let mut show = true;
        while !hub.stopped() {
            if show {
                cur = load(&mut rec, p.index).or(cur);
                if let Some(s) = &cur {
                    hub.publish(s.clone());
                }
                *shared.lock().unwrap() = p;
                show = false;
            }
            if p.playing && p.index + 1 >= len {
                p.playing = false;
                *shared.lock().unwrap() = p;
            }
            // When the next sample is due, if playing.
            let due = if p.playing {
                if next.as_ref().is_none_or(|(i, _)| *i != p.index + 1) {
                    next = load(&mut rec, p.index + 1).map(|s| (p.index + 1, s));
                }
                let gap = match (&cur, &next) {
                    (Some(c), Some((_, n))) => (n.snap.timestamp - c.snap.timestamp).clamp(0.0, 3600.0),
                    _ => 0.0,
                };
                Some(Instant::now() + Duration::from_secs_f64(gap / p.speed))
            } else {
                None
            };
            // Wait for it or a command, checking for stop now and then.
            let cmd = loop {
                let left = due.map_or(Duration::from_millis(200), |d| d.saturating_duration_since(Instant::now()));
                match rx.recv_timeout(left.min(Duration::from_millis(200))) {
                    Ok(cmd) => break Some(cmd),
                    Err(RecvTimeoutError::Disconnected) => return,
                    Err(RecvTimeoutError::Timeout) if due.is_some_and(|d| Instant::now() >= d) => break None,
                    Err(RecvTimeoutError::Timeout) if hub.stopped() => return,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            };
            let last = len as i64 - 1;
            match cmd {
                None => {
                    p.index += 1;
                    if let Some((_, s)) = next.take() {
                        cur = Some(s);
                        hub.publish(cur.clone().unwrap());
                        *shared.lock().unwrap() = p;
                        continue;
                    }
                }
                Some(Cmd::Toggle) => {
                    p.playing = !p.playing;
                    if p.playing && p.index as i64 >= last {
                        p.index = 0;
                    }
                }
                Some(Cmd::Step(n)) => {
                    p.playing = false;
                    p.index = (p.index as i64 + n).clamp(0, last) as usize;
                }
                Some(Cmd::Seek(f)) => {
                    let n = (f * len as f64).round() as i64;
                    p.index = (p.index as i64 + n).clamp(0, last) as usize;
                }
                Some(Cmd::Speed(f)) => p.speed = (p.speed * f).clamp(0.125, 1024.0),
            }
            show = true;
        }
    })?;
    Ok((Control { tx, pos }, thread))
}

#[cfg(all(test, not(target_os = "freebsd")))]
mod tests {
    use super::*;
    use crate::platform::Collector;
    use std::io::Write;

    /// Records `n` demo samples a second apart (by their timestamps).
    fn recording(n: usize) -> PathBuf {
        let mut c = Collector::new().unwrap();
        let path = std::env::temp_dir().join(format!("jmon-replay-{}-{n}.jsonl", std::process::id()));
        let mut f = File::create(&path).unwrap();
        let mut prev = c.collect();
        for i in 0..n {
            let mut snap = c.collect();
            snap.timestamp = 1_800_000_000.0 + i as f64;
            let s = Sample::derive(i as u64 + 1, c.host(), Some(&prev), snap.clone());
            prev = snap;
            serde_json::to_writer(&mut f, &s).unwrap();
            f.write_all(b"\n").unwrap();
        }
        path
    }

    fn wait_for(hub: &Hub, seq: u64) -> Arc<Sample> {
        let start = Instant::now();
        loop {
            if let Some(s) = hub.latest().filter(|s| s.seq == seq) {
                return s;
            }
            assert!(start.elapsed() < Duration::from_secs(5), "sample {seq} never came");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn plays_steps_seeks_and_stops() {
        let path = recording(20);
        let rec = Recording::open(&path).unwrap();
        assert_eq!(rec.len(), 20);
        let hub = Hub::new(Duration::from_secs(1), 0);
        let (ctl, thread) = spawn(hub.clone(), rec).unwrap();
        wait_for(&hub, 1);
        // 1 s apart at 1024x: the end comes in well under a second.
        ctl.send(Cmd::Speed(1024.0));
        wait_for(&hub, 20);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!ctl.position().playing, "stops at the end");
        ctl.send(Cmd::Step(-5));
        assert_eq!(wait_for(&hub, 15).snap.timestamp, 1_800_000_014.0);
        ctl.send(Cmd::Seek(-0.5));
        wait_for(&hub, 5);
        ctl.send(Cmd::Step(1));
        wait_for(&hub, 6);
        let p = ctl.position();
        assert_eq!((p.index, p.len, p.playing), (5, 20, false));
        hub.request_stop();
        thread.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn refuses_what_it_cannot_play() {
        let dir = std::env::temp_dir();
        let nmon = dir.join(format!("jmon-replay-{}.nmon", std::process::id()));
        std::fs::write(&nmon, "AAA,progname,jmon\n").unwrap();
        let e = Recording::open(&nmon).err().unwrap();
        assert!(format!("{e:#}").contains("not a jmon JSON Lines recording"), "{e:#}");
        let gz = dir.join(format!("jmon-replay-{}.jsonl.gz", std::process::id()));
        std::fs::write(&gz, [0x1f, 0x8b, 8, 0]).unwrap();
        assert!(format!("{:#}", Recording::open(&gz).err().unwrap()).contains("gunzip it first"));
        std::fs::remove_file(nmon).unwrap();
        std::fs::remove_file(gz).unwrap();
    }
}
