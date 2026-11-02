//! Incident capture: keeps the last few minutes of samples, and when a check
//! stays at warning or worse, saves them and what follows to a JSON Lines
//! file that `jmon --replay` plays back.

use crate::checks::{self, Level};
use crate::sample::{Sample, Sink};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};

pub struct Settings {
    pub dir: PathBuf,
    /// How long a problem must last to count.
    pub sustain: Duration,
    /// Samples kept from before an incident.
    pub before: Duration,
    /// How long an incident is followed after its problems clear.
    pub after: Duration,
}

type Evaluate = fn(&Sample) -> Option<Vec<(Level, String)>>;

pub struct Incidents {
    settings: Settings,
    evaluate: Evaluate,
    /// Recent samples as JSON, with their timestamps.
    ring: VecDeque<(f64, String)>,
    /// When each current problem was first seen, by `problem_key`.
    since: HashMap<String, f64>,
    open: Option<Open>,
    /// A file could not be opened: don't retry until the problems clear.
    failed: bool,
}

struct Open {
    out: BufWriter<File>,
    path: PathBuf,
    /// When a lasting problem was last seen.
    last_problem: f64,
}

/// A check's text with its numbers blanked, so "CPU busy 96%" and
/// "CPU busy 98%" are the same problem but disks ada0 and ada1 are not.
pub fn problem_key(text: &str) -> String {
    text.split_whitespace()
        .map(|w| {
            let bare = w.trim_matches(|c: char| "()%,:;".contains(c)).trim_end_matches("ms").trim_end_matches("/s");
            if !bare.is_empty() && bare.parse::<f64>().is_ok() { "#" } else { w }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl Incidents {
    pub fn new(settings: Settings) -> io::Result<Incidents> {
        std::fs::create_dir_all(&settings.dir)?;
        Ok(Self::with_checks(settings, checks::evaluate))
    }

    fn with_checks(settings: Settings, evaluate: Evaluate) -> Incidents {
        Incidents { settings, evaluate, ring: VecDeque::new(), since: HashMap::new(), open: None, failed: false }
    }

    fn start(&mut self, s: &Sample, why: &[&String]) -> io::Result<Open> {
        let when = chrono::DateTime::from_timestamp(s.snap.timestamp as i64, 0)
            .map(|t| t.with_timezone(&chrono::Local).format("%y%m%d_%H%M%S").to_string())
            .unwrap_or_default();
        let path = self.settings.dir.join(format!("{}_incident_{when}.jsonl", s.host.hostname));
        let file = File::options().write(true).create_new(true).open(&path)?;
        let mut out = BufWriter::new(file);
        for (_, line) in &self.ring {
            writeln!(out, "{line}")?;
        }
        let more = if why.len() > 1 { format!(" (and {} more)", why.len() - 1) } else { String::new() };
        info!("incident: {}{more}; recording to {}", why[0], path.display());
        Ok(Open { out, path, last_problem: s.snap.timestamp })
    }
}

impl Sink for Incidents {
    fn write(&mut self, s: &Sample) -> io::Result<()> {
        let now = s.snap.timestamp;
        let oldest = now - self.settings.before.as_secs_f64();
        while self.ring.front().is_some_and(|(t, _)| *t < oldest) {
            self.ring.pop_front();
        }
        let line = serde_json::to_string(s)?;
        let problems: Vec<String> = (self.evaluate)(s)
            .unwrap_or_default()
            .into_iter()
            .filter(|(level, _)| *level != Level::Ok)
            .map(|(_, text)| text)
            .collect();
        let keys: HashSet<String> = problems.iter().map(|t| problem_key(t)).collect();
        self.since.retain(|k, _| keys.contains(k));
        let sustain = self.settings.sustain.as_secs_f64();
        let lasting: Vec<&String> = problems
            .iter()
            .filter(|t| now - *self.since.entry(problem_key(t)).or_insert(now) >= sustain)
            .collect();
        if lasting.is_empty() {
            self.failed = false;
        }

        let mut result = Ok(());
        match &mut self.open {
            None if !lasting.is_empty() && !self.failed => match self.start(s, &lasting) {
                Ok(mut open) => {
                    result = writeln!(open.out, "{line}").and_then(|_| open.out.flush());
                    self.open = Some(open);
                }
                Err(e) => {
                    self.failed = true;
                    warn!("incident: cannot record to {}: {e}", self.settings.dir.display());
                }
            },
            None => {}
            Some(open) => {
                result = writeln!(open.out, "{line}").and_then(|_| open.out.flush());
                if !lasting.is_empty() {
                    open.last_problem = now;
                } else if now - open.last_problem >= self.settings.after.as_secs_f64() {
                    info!("incident over; recorded in {}", open.path.display());
                    self.open = None;
                }
            }
        }

        self.ring.push_back((now, line));
        result
    }
}

#[cfg(all(test, not(target_os = "freebsd")))]
mod tests {
    use super::*;
    use crate::platform::Collector;

    #[test]
    fn keys_ignore_the_numbers() {
        assert_eq!(problem_key("CPU busy 96% (warn 80, danger 95)"), problem_key("CPU busy 99% (warn 80, danger 95)"));
        assert_ne!(problem_key("Disk ada0 busy 96%"), problem_key("Disk ada1 busy 96%"));
        assert_eq!(problem_key("Disk ada0 latency 51.2 ms"), "Disk ada0 latency # ms");
    }

    /// The problem is CPU busy while the sample's seq is 10..=14.
    fn busy(s: &Sample) -> Option<Vec<(Level, String)>> {
        let hot = (10..=14).contains(&s.seq);
        Some(vec![(if hot { Level::Danger } else { Level::Ok }, format!("CPU busy {}%", 90 + s.seq))])
    }

    #[test]
    fn records_before_during_and_after() {
        let dir = std::env::temp_dir().join(format!("jmon-incidents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let settings = Settings {
            dir: dir.clone(),
            sustain: Duration::from_secs(2),
            before: Duration::from_secs(3),
            after: Duration::from_secs(4),
        };
        std::fs::create_dir_all(&dir).unwrap();
        let mut inc = Incidents::with_checks(settings, busy);
        let mut c = Collector::new().unwrap();
        let first = c.collect();
        // One sample a second, by timestamp; CPU busy from 10 to 14.
        for seq in 1..=30u64 {
            let mut snap = c.collect();
            snap.timestamp = 1_800_000_000.0 + seq as f64;
            inc.write(&Sample::derive(seq, c.host(), Some(&first), snap)).unwrap();
        }
        let files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(files.len(), 1, "{files:?}");
        assert!(files[0].file_name().unwrap().to_string_lossy().contains("_incident_"));
        let seqs: Vec<u64> = std::fs::read_to_string(&files[0])
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Sample>(l).unwrap().seq)
            .collect();
        // Lasting from 12 (2 s after 10), with 3 s before it (9..=11), until 4 s
        // after the last lasting problem at 14.
        assert_eq!(seqs, (9..=18).collect::<Vec<_>>());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
