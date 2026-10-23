//! nmon-style interactive screen: single-key toggles stack panels in the
//! order they were opened.

use crate::logring::LogRing;
use crate::model::{DiskGroup, Snapshot};
use crate::sample::{CpuUtil, DiskRate, GroupRate, Hub, Rates, Sample, group_rates};
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::backend::Backend;
use ratatui::{DefaultTerminal, Frame, Terminal};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Panel {
    Help,
    Resources,
    Cpu,
    CpuGrid,
    CpuLong,
    Mem,
    Kernel,
    Disk,
    Net,
    Tcp,
    Nfs,
    Fs,
    Top,
    Sensors,
    Jails,
    Zfs,
    DiskGroups,
    DiskMap,
    Vm,
    Superpages,
    Verbose,
}

impl Panel {
    fn from_key(c: char) -> Option<Panel> {
        Some(match c {
            'h' | '?' => Panel::Help,
            'r' => Panel::Resources,
            'c' => Panel::Cpu,
            'C' => Panel::CpuGrid,
            'l' => Panel::CpuLong,
            'm' => Panel::Mem,
            'k' => Panel::Kernel,
            'd' => Panel::Disk,
            'n' => Panel::Net,
            'T' => Panel::Tcp,
            'N' => Panel::Nfs,
            'g' => Panel::DiskGroups,
            'o' => Panel::DiskMap,
            'V' => Panel::Vm,
            'L' => Panel::Superpages,
            'v' => Panel::Verbose,
            'j' => Panel::Fs,
            't' => Panel::Top,
            's' => Panel::Sensors,
            'J' => Panel::Jails,
            'z' => Panel::Zfs,
            _ => return None,
        })
    }

    fn title(self) -> &'static str {
        match self {
            Panel::Help => "Help",
            Panel::Resources => "Resources",
            Panel::Cpu => "CPU Utilisation",
            Panel::CpuGrid => "CPU Grid",
            Panel::CpuLong => "CPU Long-Term",
            Panel::Mem => "Memory",
            Panel::Kernel => "Kernel",
            Panel::Disk => "Disk I/O",
            Panel::Net => "Network I/O",
            Panel::Tcp => "TCP",
            Panel::Nfs => "NFS",
            Panel::DiskGroups => "Disk Groups",
            Panel::DiskMap => "Disk Busy Map",
            Panel::Vm => "Virtual Memory",
            Panel::Superpages => "Superpages",
            Panel::Verbose => "Checks",
            Panel::Fs => "Filesystems",
            Panel::Top => "Top Processes",
            Panel::Sensors => "Sensors",
            Panel::Jails => "Jails & bhyve VMs",
            Panel::Zfs => "ZFS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopSort {
    Cpu,
    Mem,
    Io,
}

const HISTORY: usize = 1024;

const C_USER: Color = Color::Green;
const C_NICE: Color = Color::Blue;
const C_SYS: Color = Color::Red;
const C_INTR: Color = Color::Magenta;
const C_READ: Color = Color::Cyan;
const C_WRITE: Color = Color::Yellow;
/// Secondary text and borders. A fixed grey is unreadable on one kind of theme
/// or the other (dark grey on dark backgrounds, light grey on light ones), so
/// fade the terminal's own foreground colour instead.
const DIM: Style = Style::new().add_modifier(Modifier::DIM);

/// Display options shared by the panel renderers.
struct View {
    width: usize,
    show_partitions: bool,
    busy_only: bool,
    sort: TopSort,
    show_args: bool,
    user_filter: Option<String>,
}

struct App {
    hub: Arc<Hub>,
    panels: Vec<Panel>,
    sort: TopSort,
    show_args: bool,
    busy_only: bool,
    /// Frozen sample while paused.
    paused: Option<Arc<Sample>>,
    user_filter: Option<String>,
    /// Text being typed for the user filter.
    input: Option<String>,
    history: VecDeque<CpuUtil>,
    /// Hottest CPU reading since start (or the last reset): (Celsius, unix time).
    temp_peak: Option<(f64, f64)>,
    /// Highest busy fraction per CPU since start (or `0`), then the average.
    cpu_peaks: Vec<f64>,
    show_partitions: bool,
    /// Black and white: no colours, only bold/dim/reverse (also NO_COLOR).
    mono: bool,
    groups: Vec<DiskGroup>,
    last_seq: Option<u64>,
    status: Vec<String>,
    log: LogRing,
}

pub fn run(hub: Arc<Hub>, show: &str, status: Vec<String>, log: LogRing, groups: Vec<DiskGroup>) -> Result<()> {
    let mut app = App::new(hub, show, status, log);
    app.groups = groups;
    // https://no-color.org
    app.mono = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let mut terminal = ratatui::init();
    let res = app.run(&mut terminal);
    // The FreeBSD console (vt) has no alternate screen, so the last frame
    // would stay behind the shell prompt; blank it and home the cursor first.
    // (Not terminal.clear(): it first queries the cursor and gives up if the
    // terminal doesn't answer.)
    let _ = ratatui::crossterm::execute!(
        terminal.backend_mut(),
        ratatui::crossterm::terminal::Clear(ratatui::crossterm::terminal::ClearType::All),
        ratatui::crossterm::cursor::MoveTo(0, 0)
    );
    ratatui::restore();
    res
}

/// How often the whole screen is rewritten, not just the cells that changed.
const REPAINT: Duration = Duration::from_secs(5);

/// Makes the next draw rewrite every cell. ratatui only writes cells that
/// changed, so anything else that writes to the terminal, such as kernel
/// messages on the console, would stay on screen (and a scroll would shift
/// everything) until those cells happened to change.
fn invalidate<B: Backend>(terminal: &mut Terminal<B>) {
    // Between draws the current buffer is the blank one the next frame goes
    // into. Fill it with a symbol that's never drawn and swap, so it becomes
    // the buffer the next frame is compared with and every cell differs.
    for c in &mut terminal.current_buffer_mut().content {
        c.set_symbol("\u{fffe}");
    }
    terminal.swap_buffers();
}

impl App {
    fn new(hub: Arc<Hub>, show: &str, status: Vec<String>, log: LogRing) -> App {
        let mut panels: Vec<Panel> = Vec::new();
        for p in show.chars().filter_map(Panel::from_key) {
            if !panels.contains(&p) {
                panels.push(p);
            }
        }
        App {
            hub,
            panels,
            sort: TopSort::Cpu,
            show_args: false,
            busy_only: false,
            paused: None,
            user_filter: None,
            input: None,
            history: VecDeque::with_capacity(HISTORY),
            temp_peak: None,
            cpu_peaks: Vec::new(),
            show_partitions: false,
            mono: false,
            groups: Vec::new(),
            last_seq: None,
            status,
            log,
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        let mut dirty = true;
        // The console has no alternate screen, so whatever was on it (the login
        // banner, the shell) is still there; write the blank cells too.
        invalidate(terminal);
        let mut last_repaint = Instant::now();
        loop {
            if self.hub.stopped() {
                return Ok(());
            }
            let sample = match &self.paused {
                Some(s) => Some(s.clone()),
                None => self.hub.latest(),
            };
            if let Some(s) = &sample
                && self.last_seq != Some(s.seq)
            {
                self.last_seq = Some(s.seq);
                self.record(s);
                dirty = true;
            }
            if last_repaint.elapsed() >= REPAINT {
                invalidate(terminal);
                last_repaint = Instant::now();
                dirty = true;
            }
            if dirty {
                terminal.draw(|f| self.draw(f, sample.as_deref()))?;
                dirty = false;
            }
            if event::poll(Duration::from_millis(200))? {
                match event::read()? {
                    Event::Key(k)
                        if k.kind == KeyEventKind::Press
                            && k.modifiers.contains(KeyModifiers::CONTROL)
                            && k.code == KeyCode::Char('l') =>
                    {
                        invalidate(terminal);
                        last_repaint = Instant::now();
                        dirty = true;
                    }
                    Event::Key(k) if k.kind == KeyEventKind::Press => {
                        if !self.key(k.code, k.modifiers) {
                            self.hub.request_stop();
                            return Ok(());
                        }
                        dirty = true;
                    }
                    Event::Resize(..) => dirty = true,
                    _ => {}
                }
            }
        }
    }

    /// Updates session history (CPU graph, temperature peak) from a new sample.
    fn record(&mut self, s: &Sample) {
        if let Some(r) = &s.rates {
            if self.history.len() == HISTORY {
                self.history.pop_front();
            }
            self.history.push_back(r.cpu_total);
            let busy = r.cpus.iter().chain(std::iter::once(&r.cpu_total)).map(|u| 1.0 - u.idle);
            if self.cpu_peaks.len() != r.cpus.len() + 1 {
                self.cpu_peaks = vec![0.0; r.cpus.len() + 1];
            }
            for (peak, b) in self.cpu_peaks.iter_mut().zip(busy) {
                *peak = peak.max(b);
            }
        }
        let hottest = s.snap.sensors.cpu_temps.iter().copied().fold(None, |m: Option<f64>, t| Some(m.map_or(t, |m| m.max(t))));
        if let Some(t) = hottest
            && self.temp_peak.is_none_or(|(p, _)| t > p)
        {
            self.temp_peak = Some((t, s.snap.timestamp));
        }
    }

    /// Returns false to quit.
    fn key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            return false;
        }
        if let Some(buf) = &mut self.input {
            match code {
                KeyCode::Enter => {
                    let v = buf.trim().to_string();
                    self.user_filter = (!v.is_empty()).then_some(v);
                    self.input = None;
                }
                KeyCode::Esc => self.input = None,
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return true;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Char('+') => self.hub.set_interval(self.hub.interval() * 2),
            KeyCode::Char('-') => self.hub.set_interval(self.hub.interval() / 2),
            KeyCode::Char('3') => self.sort = TopSort::Cpu,
            KeyCode::Char('4') => self.sort = TopSort::Mem,
            KeyCode::Char('5') => self.sort = TopSort::Io,
            KeyCode::Char('a') => self.show_args = !self.show_args,
            KeyCode::Char('.') => self.busy_only = !self.busy_only,
            KeyCode::Char('R') => self.temp_peak = None,
            KeyCode::Char('0') => self.cpu_peaks.clear(),
            KeyCode::Char('G') => self.show_partitions = !self.show_partitions,
            KeyCode::Char('b') => self.mono = !self.mono,
            KeyCode::Char('u') => self.input = Some(self.user_filter.clone().unwrap_or_default()),
            KeyCode::Char('p') => {
                self.paused = match self.paused {
                    Some(_) => None,
                    None => self.hub.latest(),
                }
            }
            KeyCode::Char(c) => {
                if let Some(p) = Panel::from_key(c) {
                    match self.panels.iter().position(|&x| x == p) {
                        Some(i) => {
                            self.panels.remove(i);
                        }
                        None => self.panels.push(p),
                    }
                }
            }
            _ => {}
        }
        true
    }

    fn view(&self, width: usize) -> View {
        View {
            width,
            show_partitions: self.show_partitions,
            busy_only: self.busy_only,
            sort: self.sort,
            show_args: self.show_args,
            user_filter: self.user_filter.clone(),
        }
    }

    fn draw(&self, f: &mut Frame, sample: Option<&Sample>) {
        self.draw_panels(f, sample);
        if self.mono {
            for cell in f.buffer_mut().content.iter_mut() {
                cell.fg = Color::Reset;
                cell.bg = Color::Reset;
            }
        }
    }

    fn draw_panels(&self, f: &mut Frame, sample: Option<&Sample>) {
        let [head, body, foot] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0), Constraint::Length(1)]).areas(f.area());
        f.render_widget(self.header(sample), head);
        f.render_widget(self.footer(), foot);

        let Some(s) = sample else {
            f.render_widget(Paragraph::new("Collecting first sample..."), body);
            return;
        };
        if self.panels.is_empty() {
            f.render_widget(welcome(), body);
            return;
        }
        let v = self.view(body.width.saturating_sub(2) as usize);
        let contents: Vec<(Panel, Vec<Line<'static>>)> = self
            .panels
            .iter()
            .map(|&p| {
                let lines = match p {
                    Panel::Help => help_lines(),
                    Panel::Resources => resources(s, &self.status),
                    Panel::Cpu => cpu(s, &v, &self.cpu_peaks),
                    Panel::CpuGrid => cpu_grid(s, &v, &self.cpu_peaks),
                    Panel::CpuLong => cpu_long(&self.history, v.width, 12),
                    Panel::Mem => mem(&s.snap, v.width),
                    Panel::Kernel => kernel(s),
                    Panel::Disk => disks(s, &v),
                    Panel::Net => nets(s, &v),
                    Panel::Tcp => tcp(s),
                    Panel::Nfs => nfs(s),
                    Panel::DiskGroups => disk_groups(s, &v, &self.groups),
                    Panel::DiskMap => disk_map(s, &v),
                    Panel::Vm => vm_detail(s),
                    Panel::Superpages => superpages(s),
                    Panel::Verbose => checks(s),
                    Panel::Fs => filesystems(&s.snap, v.width),
                    Panel::Top => top(s, &v),
                    Panel::Sensors => sensors(&s.snap, v.width, self.temp_peak),
                    Panel::Jails => jails(s, &v),
                    Panel::Zfs => zfs(s),
                };
                (p, lines)
            })
            .collect();
        let constraints: Vec<Constraint> = contents
            .iter()
            .map(|(p, lines)| match p {
                Panel::Top => Constraint::Min(5),
                _ => Constraint::Length(lines.len() as u16 + 2),
            })
            .collect();
        let areas = Layout::vertical(constraints).split(body);
        for ((p, lines), area) in contents.into_iter().zip(areas.iter()) {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(DIM)
                .title(Span::styled(
                    format!(" {} ", p.title()),
                    Style::default().remove_modifier(Modifier::DIM).add_modifier(Modifier::BOLD),
                ));
            f.render_widget(Paragraph::new(lines).block(block), *area);
        }
    }

    fn header(&self, s: Option<&Sample>) -> Paragraph<'static> {
        let badge = |bg: Color, fg: Color| Style::default().bg(bg).fg(fg).remove_modifier(Modifier::REVERSED);
        let bar = badge(Color::Blue, Color::White).add_modifier(Modifier::BOLD);
        let mut spans = vec![Span::styled(format!(" jmon {} ", env!("CARGO_PKG_VERSION")), bar)];
        if let Some(s) = s {
            let h = &s.host;
            let when = chrono::DateTime::from_timestamp(s.snap.timestamp as i64, 0)
                .map(|t| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
                .unwrap_or_default();
            spans.push(Span::raw(format!(
                " {} │ FreeBSD {} {} │ Interval {}s │ {when} │ up {}",
                h.hostname,
                h.os_release,
                h.machine,
                fmt_secs(self.hub.interval().as_secs_f64()),
                uptime(s.snap.uptime)
            )));
            if h.demo {
                spans.push(Span::styled(" DEMO DATA ", badge(Color::Red, Color::White)));
            }
        }
        if self.paused.is_some() {
            spans.push(Span::styled(" PAUSED ", badge(Color::Yellow, Color::Black)));
        }
        if self.show_partitions {
            spans.push(Span::raw(" │ partitions"));
        }
        if self.busy_only {
            spans.push(Span::raw(" │ busy only"));
        }
        if let Some(u) = &self.user_filter {
            spans.push(Span::raw(format!(" │ user={u}")));
        }
        Paragraph::new(Line::from(spans)).style(Style::default().add_modifier(Modifier::REVERSED))
    }

    fn footer(&self) -> Paragraph<'static> {
        if let Some(buf) = &self.input {
            return Paragraph::new(Line::from(vec![
                Span::styled(" Show processes of user: ", Style::default().add_modifier(Modifier::REVERSED)),
                Span::raw(format!(" {buf}_   (Enter = apply, empty = all users, Esc = cancel)")),
            ]));
        }
        let dim = DIM;
        let mut spans = vec![Span::styled(" h=help q=quit ", Style::default().add_modifier(Modifier::REVERSED))];
        for s in &self.status {
            spans.push(Span::styled(format!(" {s} │"), dim));
        }
        if let Some(l) = self.log.last() {
            spans.push(Span::styled(format!(" {l}"), Style::default().fg(Color::Yellow)));
        }
        Paragraph::new(Line::from(spans))
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers

fn fmt_secs(s: f64) -> String {
    if s.fract() == 0.0 { format!("{s:.0}") } else { format!("{s:.1}") }
}

fn uptime(secs: f64) -> String {
    let s = secs as u64;
    let (d, h, m) = (s / 86400, s % 86400 / 3600, s % 3600 / 60);
    if d > 0 { format!("{d}d {h}h {m}m") } else { format!("{h}h {m}m") }
}

fn mb(b: u64) -> String {
    format!("{:.1}", b as f64 / 1048576.0)
}

fn human(b: u64) -> String {
    const U: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b}B") } else { format!("{v:.1}{}", U[i]) }
}

/// A horizontal bar of `width` cells made of coloured letter segments, like
/// nmon's `UUUUssss`. Rounds cumulatively so segments never overflow.
fn bar(segments: &[(f64, char, Color)], width: usize) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut acc = 0.0;
    let mut used = 0usize;
    for &(frac, ch, color) in segments {
        acc += frac.max(0.0);
        let end = ((acc * width as f64).round() as usize).min(width);
        if end > used {
            spans.push(Span::styled(ch.to_string().repeat(end - used), Style::default().fg(color)));
            used = end;
        }
    }
    spans.push(Span::raw(" ".repeat(width - used)));
    spans
}

/// `bar` plus nmon's peak marker: a `>` at the highest level reached since
/// start, when that is beyond the current bar.
fn bar_with_peak(segments: &[(f64, char, Color)], width: usize, peak: Option<f64>) -> Vec<Span<'static>> {
    let mut spans = bar(segments, width);
    let Some(peak) = peak else { return spans };
    let pos = ((peak * width as f64).round() as usize).min(width);
    let pad = spans.last().map_or(0, |s| s.content.chars().count());
    let used = width - pad;
    if pos > used {
        spans.pop();
        spans.push(Span::raw(" ".repeat(pos - 1 - used)));
        spans.push(Span::styled(">", Style::default().add_modifier(Modifier::BOLD)));
        spans.push(Span::raw(" ".repeat(width - pos)));
    }
    spans
}

fn busy_color(frac: f64) -> Color {
    if frac >= 0.9 {
        C_SYS
    } else if frac >= 0.7 {
        C_WRITE
    } else {
        C_USER
    }
}

/// "0     |25    |50     |75   100" scale for a bar of `width` cells; the
/// caller supplies the bar's surrounding `|` characters.
fn scale(width: usize) -> String {
    let mut s: Vec<char> = vec![' '; width];
    s[0] = '0';
    for (pos, label) in [(width / 4, "25"), (width / 2, "50"), (width * 3 / 4, "75")] {
        for (k, c) in std::iter::once('|').chain(label.chars()).enumerate() {
            if pos + k < width {
                s[pos + k] = c;
            }
        }
    }
    if width >= 3 {
        s[width - 3..].copy_from_slice(&['1', '0', '0']);
    }
    s.into_iter().collect()
}

/// Width of a left-aligned name column: the longest name plus a gap, so long
/// names (e.g. cni-podman0) don't push the following columns out of line.
fn name_width<'a>(names: impl Iterator<Item = &'a str>) -> usize {
    names.map(|n| n.chars().count() + 1).max().unwrap_or(0).max(10)
}

fn hdr(s: String) -> Line<'static> {
    Line::styled(s, Style::default().add_modifier(Modifier::BOLD))
}

fn dim(s: impl Into<String>) -> Line<'static> {
    Line::styled(s.into(), DIM)
}

fn waiting() -> Vec<Line<'static>> {
    vec![Line::raw("Waiting for second sample...")]
}

/// Red within 15 °C of the throttle point, yellow within 30 °C. Without a
/// known throttle point, fixed thresholds of 80 and 65 °C.
fn temp_color(c: f64, tjmax: Option<f64>) -> Color {
    let (red, yellow) = match tjmax {
        Some(tj) => (tj - 15.0, tj - 30.0),
        None => (80.0, 65.0),
    };
    if c >= red {
        C_SYS
    } else if c >= yellow {
        C_WRITE
    } else {
        C_USER
    }
}

fn local_time(ts: f64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|t| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Panels

fn welcome() -> Paragraph<'static> {
    let mut lines = vec![
        Line::raw(""),
        Line::styled("   _                        ", Style::default().fg(Color::Cyan)),
        Line::styled("  (_)_ __ ___   ___  _ __   ", Style::default().fg(Color::Cyan)),
        Line::styled("  | | '_ ` _ \\ / _ \\| '_ \\  ", Style::default().fg(Color::Cyan)),
        Line::styled("  | | | | | | | (_) | | | | ", Style::default().fg(Color::Cyan)),
        Line::styled(" _/ |_| |_| |_|\\___/|_| |_| ", Style::default().fg(Color::Cyan)),
        Line::styled("|__/   FreeBSD performance monitor with OpenTelemetry export", Style::default().fg(Color::Cyan)),
        Line::raw(""),
    ];
    lines.extend(help_lines());
    Paragraph::new(lines)
}

/// Panel keys, in rows of three related panels.
const HELP_PANELS: &[(&str, &str)] = &[
    ("c", "CPU by processor"),
    ("C", "CPU grid (many cores)"),
    ("l", "CPU long-term graph"),
    ("m", "Memory & swap"),
    ("V", "Virtual memory"),
    ("L", "Superpages"),
    ("k", "Kernel, load, run queue"),
    ("s", "Sensors (temp, clock, battery)"),
    ("r", "Resources / system info"),
    ("d", "Disk I/O & latency"),
    ("g", "Disk groups"),
    ("o", "Disk busy map"),
    ("n", "Network"),
    ("T", "TCP"),
    ("N", "NFS"),
    ("j", "Filesystems"),
    ("z", "ZFS (ARC, pools)"),
    ("J", "Jails & bhyve VMs"),
    ("t", "Top processes"),
    ("v", "Checks (warnings)"),
    ("h", "Help"),
];

const HELP_TOP: &[(&str, &str)] = &[
    ("3", "Sort by CPU"),
    ("4", "Sort by memory"),
    ("5", "Sort by I/O"),
    ("a", "Full command lines"),
    ("u", "Filter by user"),
];

const HELP_MODES: &[(&str, &str)] = &[
    (".", "Busy only (hide idle)"),
    ("G", "Include partitions/GEOM"),
    ("p", "Pause / resume"),
    ("+", "Double interval"),
    ("-", "Halve interval"),
    ("b", "Black & white"),
    ("0", "Reset CPU peaks (>)"),
    ("R", "Reset temperature peak"),
    ("^L", "Redraw screen"),
    ("q", "Quit"),
];

fn help_lines() -> Vec<Line<'static>> {
    // One column width for every grid so the columns line up across sections,
    // and keys right-aligned so a two-character key like ^L doesn't shift its "=".
    let entries = || [HELP_PANELS, HELP_TOP, HELP_MODES].into_iter().flatten();
    let key_width = entries().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
    let width = entries().map(|(_, d)| key_width + 3 + d.chars().count()).max().unwrap_or(0) + 3;
    let grid = |entries: &[(&str, &str)]| -> Vec<Line<'static>> {
        entries
            .chunks(3)
            .map(|row| {
                let mut spans = vec![Span::raw("  ")];
                for (key, desc) in row {
                    spans.push(Span::styled(format!("{key:>key_width$}"), Style::default().add_modifier(Modifier::BOLD)));
                    let text = format!(" = {desc}");
                    let pad = width.saturating_sub(key_width + text.chars().count());
                    spans.push(Span::raw(format!("{text}{}", " ".repeat(pad))));
                }
                Line::from(spans)
            })
            .collect()
    };
    let mut lines = vec![hdr("Panels".into())];
    lines.extend(grid(HELP_PANELS));
    lines.push(hdr("In the process list".into()));
    lines.extend(grid(HELP_TOP));
    lines.push(hdr("Anywhere".into()));
    lines.extend(grid(HELP_MODES));
    lines.push(dim("Open panels at start: jmon --show cmdn (or JMON=cmdn, like nmon's NMON variable)"));
    lines
}

fn resources(s: &Sample, status: &[String]) -> Vec<Line<'static>> {
    let h = &s.host;
    vec![
        Line::raw(format!("Host      {}", h.hostname)),
        Line::raw(format!("OS        FreeBSD {} {}", h.os_release, h.machine)),
        Line::raw(format!("CPU       {} x {}", h.ncpu, h.cpu_model)),
        Line::raw(format!("Memory    {} physical, {} pages, stathz {}", human(h.physmem), human(h.pagesize), s.snap.stathz)),
        Line::raw(format!("Uptime    {}", uptime(s.snap.uptime))),
        Line::raw(format!("Exporting {}", if status.is_empty() { "nothing".into() } else { status.join(", ") })),
        Line::raw(format!("Sampling  last collection took {:.1} ms", s.collect_secs * 1000.0)),
    ]
}

fn cpu_segments(u: &CpuUtil) -> [(f64, char, Color); 4] {
    [(u.user, 'U', C_USER), (u.nice, 'n', C_NICE), (u.system, 's', C_SYS), (u.interrupt, 'i', C_INTR)]
}

fn cpu_row(label: String, u: &CpuUtil, bw: usize, peak: Option<f64>) -> Line<'static> {
    let mut spans = vec![Span::raw(format!(
        "{label:>3} {:>6.1}{:>6.1}{:>6.1}{:>6.1}{:>6.1}|",
        u.user * 100.0,
        u.nice * 100.0,
        u.system * 100.0,
        u.interrupt * 100.0,
        u.idle * 100.0
    ))];
    spans.extend(bar_with_peak(&cpu_segments(u), bw, peak));
    spans.push(Span::raw("|"));
    Line::from(spans)
}

/// Below this busy fraction a CPU counts as idle for the `.` filter.
const IDLE_CPU: f64 = 0.005;

fn cpu(s: &Sample, v: &View, peaks: &[f64]) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    const LABEL: usize = 3 + 1 + 6 * 5 + 1;
    let bw = v.width.saturating_sub(LABEL + 1).max(10);
    let mut lines = vec![hdr(format!(
        "{:>3} {:>6}{:>6}{:>6}{:>6}{:>6}|{}|",
        "CPU",
        "User%",
        "Nice%",
        "Sys%",
        "Intr%",
        "Idle%",
        scale(bw)
    ))];
    for (i, u) in r.cpus.iter().enumerate() {
        if v.busy_only && 1.0 - u.idle < IDLE_CPU {
            continue;
        }
        lines.push(cpu_row(i.to_string(), u, bw, peaks.get(i).copied()));
    }
    lines.push(cpu_row("Avg".into(), &r.cpu_total, bw, peaks.get(r.cpus.len()).copied()));
    lines
}

/// Compact view for many-core machines: one small bar per CPU, several per row.
fn cpu_grid(s: &Sample, v: &View, peaks: &[f64]) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    const CELL: usize = 26;
    const BAR: usize = 13;
    let cols = (v.width / CELL).max(1);
    let shown: Vec<(usize, &CpuUtil)> =
        r.cpus.iter().enumerate().filter(|(_, u)| !v.busy_only || 1.0 - u.idle >= IDLE_CPU).collect();
    let mut lines = Vec::new();
    for chunk in shown.chunks(cols) {
        let mut spans = Vec::new();
        for (i, u) in chunk {
            spans.push(Span::raw(format!("{i:>3} ")));
            spans.extend(bar_with_peak(&cpu_segments(u), BAR, peaks.get(*i).copied()));
            spans.push(Span::raw(format!("{:>6.1}%  ", (1.0 - u.idle) * 100.0)));
        }
        lines.push(Line::from(spans));
    }
    let t = &r.cpu_total;
    lines.push(dim(format!(
        "Avg  user {:.1}%  sys {:.1}%  intr {:.1}%  idle {:.1}%   ({} CPUs)",
        (t.user + t.nice) * 100.0,
        t.system * 100.0,
        t.interrupt * 100.0,
        t.idle * 100.0,
        r.cpus.len()
    )));
    lines
}

fn cpu_long(history: &VecDeque<CpuUtil>, width: usize, height: usize) -> Vec<Line<'static>> {
    if history.is_empty() {
        return waiting();
    }
    let rows = height.saturating_sub(1).max(1);
    let cols = width.saturating_sub(5).max(1);
    let skip = history.len().saturating_sub(cols);
    let hist: Vec<&CpuUtil> = history.iter().skip(skip).collect();
    let mut lines = Vec::with_capacity(height);
    for r in 0..rows {
        // Cell midpoint as a fraction of total CPU.
        let level = (rows - r) as f64 / rows as f64 - 0.5 / rows as f64;
        let label = match r {
            0 => "100|".to_string(),
            r if r == rows / 2 => " 50|".to_string(),
            _ => "   |".to_string(),
        };
        let mut spans = vec![Span::styled(label, DIM)];
        for u in &hist {
            let user = u.user + u.nice;
            let sys = u.system + u.interrupt;
            let (ch, color) = if level <= user {
                ('U', C_USER)
            } else if level <= user + sys {
                ('s', C_SYS)
            } else {
                (' ', Color::Reset)
            };
            spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::styled(format!("  0+{}", "-".repeat(cols)), DIM));
    lines
}

fn mem(snap: &Snapshot, width: usize) -> Vec<Line<'static>> {
    let m = &snap.memory;
    let total = m.total.max(1) as f64;
    let pct = |b: u64| format!("{:.1}%", b as f64 * 100.0 / total);
    let arc = m.arc.unwrap_or(0);
    let mut lines = vec![
        hdr(format!(
            "{:<10}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}",
            "MB", "Total", "Active", "Inactive", "Laundry", "Wired", "Free", "ZFS ARC"
        )),
        Line::raw(format!(
            "{:<10}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}",
            "Physical",
            mb(m.total),
            mb(m.active),
            mb(m.inactive),
            mb(m.laundry),
            mb(m.wired),
            mb(m.free),
            m.arc.map(mb).unwrap_or_else(|| "-".into())
        )),
        Line::raw(format!(
            "{:<10}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}",
            "% of RAM",
            "",
            pct(m.active),
            pct(m.inactive),
            pct(m.laundry),
            pct(m.wired),
            pct(m.free),
            m.arc.map(pct).unwrap_or_default()
        )),
    ];
    let bw = width.saturating_sub(12).max(10);
    let wired_other = m.wired.saturating_sub(arc) as f64 / total;
    let mut spans = vec![Span::raw("Usage     |")];
    spans.extend(bar(
        &[
            (m.active as f64 / total, 'A', C_USER),
            (m.inactive as f64 / total, 'I', Color::Cyan),
            (m.laundry as f64 / total, 'L', Color::Yellow),
            (wired_other, 'W', C_SYS),
            (arc as f64 / total, 'Z', C_INTR),
        ],
        bw,
    ));
    spans.push(Span::raw("|"));
    lines.push(Line::from(spans));

    let st: u64 = snap.swap.iter().map(|s| s.total).sum();
    let su: u64 = snap.swap.iter().map(|s| s.used).sum();
    lines.push(if st == 0 {
        Line::raw("Swap      none configured")
    } else {
        Line::raw(format!(
            "Swap      {} MB total, {} MB used ({:.1}%), {} device{}",
            mb(st),
            mb(su),
            su as f64 * 100.0 / st as f64,
            snap.swap.len(),
            if snap.swap.len() == 1 { "" } else { "s" }
        ))
    });
    lines
}

fn kernel(s: &Sample) -> Vec<Line<'static>> {
    let snap = &s.snap;
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for p in &snap.processes {
        match counts.iter_mut().find(|(st, _)| *st == p.state) {
            Some((_, n)) => *n += 1,
            None => counts.push((p.state, 1)),
        }
    }
    counts.sort_by_key(|c| std::cmp::Reverse(c.1));
    let procs = counts.iter().map(|(s, n)| format!("{s} {n}")).collect::<Vec<_>>().join("  ");
    let mut lines = vec![Line::raw(format!(
        "Load average  {:.2} {:.2} {:.2}      Uptime {}",
        snap.load[0],
        snap.load[1],
        snap.load[2],
        uptime(snap.uptime)
    ))];
    match &s.rates {
        Some(Rates { vm: v, .. }) => {
            lines.push(Line::raw(format!(
                "Ctx switch/s {:>10.0}   Interrupts/s {:>10.0}   Syscalls/s {:>10.0}",
                v.context_switches, v.interrupts, v.syscalls
            )));
            lines.push(Line::raw(format!(
                "Traps/s      {:>10.0}   Forks/s      {:>10.1}   Faults/s   {:>10.0}   Swap in/out pg/s {:.0}/{:.0}",
                v.traps, v.forks, v.faults, v.swap_pages_in, v.swap_pages_out
            )));
        }
        None => lines.extend(waiting()),
    }
    let rq = &snap.runq;
    let ncpu = s.host.ncpu.max(1) as u64;
    let rq_style = if rq.runnable > 2 * ncpu {
        Style::default().fg(C_SYS)
    } else if rq.runnable > ncpu {
        Style::default().fg(C_WRITE)
    } else {
        Style::default()
    };
    lines.push(Line::from(vec![
        Span::styled(format!("Run queue {:>4}", rq.runnable), rq_style),
        Span::raw(format!(
            "   Blocked on disk {:>3}   Page wait {:>3}   Sleeping {}   ({ncpu} CPUs)",
            rq.disk_wait, rq.page_wait, rq.sleeping
        )),
    ]));
    lines.push(Line::raw(format!("Processes {}: {procs}", snap.processes.len())));
    lines
}

/// One device row. Groups pass `latency: false`, since per-operation time
/// doesn't sum meaningfully across disks.
fn disk_row(name: &str, nw: usize, d: &DiskRate, last: u64, latency: bool, bw: usize) -> Line<'static> {
    let bytes = d.read_bps + d.write_bps;
    let rshare = if bytes > 0.0 { d.read_bps / bytes } else { 0.5 };
    let ms = |v: f64| if latency { format!("{v:.2}") } else { String::new() };
    let mut spans = vec![Span::raw(format!(
        "{:<nw$}{:>7.1}{:>11.1}{:>11.1}{:>8.1}{:>8.1}{:>8}{:>8}{:>6}|",
        name,
        d.busy * 100.0,
        d.read_bps / 1024.0,
        d.write_bps / 1024.0,
        d.read_iops,
        d.write_iops,
        ms(d.read_ms),
        ms(d.write_ms),
        last
    ))];
    spans.extend(bar(&[(d.busy * rshare, 'R', C_READ), (d.busy * (1.0 - rshare), 'W', C_WRITE)], bw));
    spans.push(Span::raw("|"));
    Line::from(spans)
}

fn disks(s: &Sample, v: &View) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    let snap = &s.snap;
    let mut rows: Vec<(&str, &DiskRate, u64)> =
        snap.disks.iter().zip(&r.disks).map(|(d, dr)| (d.name.as_str(), dr, d.queue)).collect();
    if v.show_partitions {
        rows.extend(snap.partitions.iter().zip(&r.partitions).map(|(d, dr)| (d.name.as_str(), dr, d.queue)));
    }
    let nw = name_width(rows.iter().map(|r| r.0));
    let label = nw + 7 + 11 + 11 + 8 + 8 + 8 + 8 + 6 + 1;
    let bw = v.width.saturating_sub(label + 1).max(10);
    let mut lines = vec![hdr(format!(
        "{:<nw$}{:>7}{:>11}{:>11}{:>8}{:>8}{:>8}{:>8}{:>6}|{}|",
        "Disk",
        "Busy%",
        "Read-KB/s",
        "Write-KB/s",
        "Rd/s",
        "Wr/s",
        "ms/rd",
        "ms/wr",
        "Queue",
        scale(bw)
    ))];
    for (name, dr, queue) in rows {
        let idle = dr.busy < 0.001 && dr.read_iops + dr.write_iops < 0.05 && queue == 0;
        if v.busy_only && idle {
            continue;
        }
        lines.push(disk_row(name, nw, dr, queue, true, bw));
    }
    lines
}

fn disk_groups(s: &Sample, v: &View, groups: &[DiskGroup]) -> Vec<Line<'static>> {
    if groups.is_empty() {
        return vec![dim("No disk groups. Define them with --disk-group NAME=ada0,ada1 or disk-group in jmon.conf")];
    }
    let Some(r) = &s.rates else { return waiting() };
    let totals = group_rates(groups, &s.snap, r);
    let nw = name_width(groups.iter().map(|g| g.name.as_str()));
    let label = nw + 7 + 11 + 11 + 8 + 8 + 8 + 8 + 6 + 1;
    let bw = v.width.saturating_sub(label + 1).max(10);
    let mut lines = vec![hdr(format!(
        "{:<nw$}{:>7}{:>11}{:>11}{:>8}{:>8}{:>8}{:>8}{:>6}|{}|",
        "Group",
        "Busy%",
        "Read-KB/s",
        "Write-KB/s",
        "Rd/s",
        "Wr/s",
        "",
        "",
        "Disks",
        scale(bw)
    ))];
    for (g, t) in groups.iter().zip(&totals) {
        lines.push(disk_row(&g.name, nw, t, g.members.len() as u64, false, bw));
    }
    lines.push(dim(
        groups.iter().map(|g| format!("{}: {}", g.name, g.members.join(" "))).collect::<Vec<_>>().join("   "),
    ));
    lines
}

/// One cell per device, coloured by how busy it is (nmon's `o`).
fn disk_map(s: &Sample, v: &View) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    let snap = &s.snap;
    let mut cells: Vec<(&str, f64)> = snap.disks.iter().zip(&r.disks).map(|(d, dr)| (d.name.as_str(), dr.busy)).collect();
    if v.show_partitions {
        cells.extend(snap.partitions.iter().zip(&r.partitions).map(|(d, dr)| (d.name.as_str(), dr.busy)));
    }
    if v.busy_only {
        cells.retain(|c| c.1 >= 0.001);
    }
    if cells.is_empty() {
        return vec![dim("No busy disks")];
    }
    let cw = cells.iter().map(|c| c.0.chars().count()).max().unwrap_or(4) + 7;
    let per_row = (v.width / cw).max(1);
    let mut lines = Vec::new();
    for chunk in cells.chunks(per_row) {
        let mut spans = Vec::new();
        for (name, busy) in chunk {
            let style = if *busy < 0.001 { DIM } else { Style::default().fg(busy_color(*busy)) };
            spans.push(Span::styled(format!("{name:>w$} {:>3.0}%  ", busy * 100.0, w = cw - 7), style));
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn nets(s: &Sample, v: &View) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    let nw = name_width(s.snap.nets.iter().map(|n| n.name.as_str()));
    let mut lines = vec![hdr(format!(
        "{:<nw$}{:>12}{:>12}{:>11}{:>11}{:>10}{:>10}{:>9}{:>9}{:>7} {}",
        "Iface", "Recv-KB/s", "Trans-KB/s", "Pkt-in/s", "Pkt-out/s", "In-B/pkt", "Out-B/pkt", "Errs/s", "Drops/s", "MTU", "Link"
    ))];
    for (n, nr) in s.snap.nets.iter().zip(&r.nets) {
        if v.busy_only && nr.rx_pps + nr.tx_pps < 0.05 {
            continue;
        }
        let style = if n.up { Style::default() } else { DIM };
        lines.push(Line::styled(
            format!(
                "{:<nw$}{:>12.1}{:>12.1}{:>11.1}{:>11.1}{:>10}{:>10}{:>9.1}{:>9.1}{:>7} {}",
                n.name,
                nr.rx_bps / 1024.0,
                nr.tx_bps / 1024.0,
                nr.rx_pps,
                nr.tx_pps,
                pkt_size(nr.rx_bps, nr.rx_pps),
                pkt_size(nr.tx_bps, nr.tx_pps),
                nr.errors_ps,
                nr.drops_ps,
                n.mtu,
                if n.up { "up" } else { "down" }
            ),
            style,
        ));
    }
    lines
}

/// Average packet size, or "-" when no packets moved.
fn pkt_size(bps: f64, pps: f64) -> String {
    if pps < 0.05 { "-".into() } else { format!("{:.0}", bps / pps) }
}

fn tcp(s: &Sample) -> Vec<Line<'static>> {
    let Some(t) = &s.snap.tcp else { return vec![dim("TCP statistics not available")] };
    let mut lines = Vec::new();
    match s.rates.as_ref().and_then(|r| r.tcp) {
        Some(r) => {
            let pct = if r.segs_sent > 0.0 { r.retransmits * 100.0 / r.segs_sent } else { 0.0 };
            let style = if pct >= 2.0 { Style::default().fg(C_SYS) } else { Style::default() };
            lines.push(Line::raw(format!(
                "Segments/s       in {:>10.0}   out {:>10.0}",
                r.segs_received, r.segs_sent
            )));
            lines.push(Line::styled(
                format!("Retransmits/s       {:>10.1}   ({pct:.2}% of segments sent)", r.retransmits),
                style,
            ));
            lines.push(Line::raw(format!(
                "Connections/s accepted {:>7.1}   initiated {:>7.1}   listen-queue overflows/s {:.1}",
                r.accepts, r.conn_attempts, r.listen_drops
            )));
        }
        None => lines.extend(waiting()),
    }
    let mut states: Vec<&(&str, u64)> = t.states.iter().filter(|(_, n)| *n > 0).collect();
    states.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let states = states.iter().map(|(name, n)| format!("{name} {n}")).collect::<Vec<_>>().join("  ");
    lines.push(Line::raw(format!("Connections   {}", if states.is_empty() { "none".into() } else { states })));
    lines.push(dim(format!(
        "Since boot: {} retransmits, {} listen-queue overflows, {} bad checksums, {} dropped connections",
        t.retransmits, t.listen_drops, t.bad_checksums, t.drops
    )));
    lines
}

fn filesystems(snap: &Snapshot, width: usize) -> Vec<Line<'static>> {
    const LABEL: usize = 24 + 8 + 9 * 3 + 7 + 1;
    let bw = width.saturating_sub(LABEL + 1).max(10);
    let mut lines = vec![hdr(format!(
        "{:<24}{:<8}{:>9}{:>9}{:>9}{:>7}|{}|",
        "Mounted on", "Type", "Size", "Used", "Avail", "Use%", scale(bw)
    ))];
    for f in &snap.filesystems {
        let used = f.used();
        // df(1) semantics: percent of space available to users.
        let denom = (used + f.avail).max(1) as f64;
        let frac = used as f64 / denom;
        let color = if frac > 0.9 { C_SYS } else if frac > 0.75 { C_WRITE } else { C_USER };
        let mut mp = f.mountpoint.clone();
        if mp.chars().count() > 23 {
            let tail: String = mp.chars().rev().take(22).collect::<Vec<_>>().into_iter().rev().collect();
            mp = format!("…{tail}");
        }
        let mut spans = vec![Span::raw(format!(
            "{:<24}{:<8}{:>9}{:>9}{:>9}{:>6.1}%|",
            mp,
            f.fstype,
            human(f.total),
            human(used),
            human(f.avail),
            frac * 100.0
        ))];
        spans.extend(bar(&[(frac, '#', color)], bw));
        spans.push(Span::raw("|"));
        lines.push(Line::from(spans));
    }
    lines
}

fn top(s: &Sample, v: &View) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    let snap = &s.snap;
    let mut order: Vec<usize> = (0..snap.processes.len()).collect();
    match v.sort {
        TopSort::Cpu => order.sort_by(|&a, &b| r.proc_cpu[b].total_cmp(&r.proc_cpu[a])),
        TopSort::Mem => order.sort_by(|&a, &b| snap.processes[b].rss.cmp(&snap.processes[a].rss)),
        TopSort::Io => order.sort_by(|&a, &b| r.proc_io[b].total_cmp(&r.proc_io[a])),
    }
    let jail_name = |jid: i32| -> String {
        if jid == 0 {
            "-".into()
        } else {
            snap.jails.iter().find(|j| j.jid == jid).map_or_else(|| jid.to_string(), |j| clip(&j.name, 8))
        }
    };
    let sort = match v.sort {
        TopSort::Cpu => "CPU",
        TopSort::Mem => "memory",
        TopSort::Io => "I/O",
    };
    let mut lines = vec![hdr(format!(
        "{:>7} {:>6} {:>8} {:>8} {:>7} {:>7} {:>6} {:>4} {:<9} {:<10} {:<8} Command   (by {sort}{})",
        "PID",
        "%CPU",
        "RES",
        "VSIZE",
        "IO/s",
        "Flt/s",
        "MajF/s",
        "THR",
        "State",
        "User",
        "Jail",
        v.user_filter.as_ref().map(|u| format!(", user {u}")).unwrap_or_default()
    ))];
    for i in order {
        let p = &snap.processes[i];
        if v.user_filter.as_ref().is_some_and(|u| &p.user != u) {
            continue;
        }
        let cpu = r.proc_cpu[i];
        let io = r.proc_io[i];
        if v.busy_only && cpu < 0.1 && io < 0.05 {
            continue;
        }
        let style = if cpu >= 50.0 {
            Style::default().fg(C_SYS)
        } else if cpu >= 10.0 {
            Style::default().fg(C_WRITE)
        } else {
            Style::default()
        };
        lines.push(Line::styled(
            format!(
                "{:>7} {:>6.1} {:>8} {:>8} {:>7.1} {:>7.0} {:>6.1} {:>4} {:<9} {:<10} {:<8} {}",
                p.pid,
                cpu,
                human(p.rss),
                human(p.vsize),
                io,
                r.proc_faults[i].0 + r.proc_faults[i].1,
                r.proc_faults[i].1,
                p.threads,
                p.state,
                p.user,
                jail_name(p.jid),
                if v.show_args { &p.args } else { &p.command }
            ),
            style,
        ));
    }
    lines
}

fn sensors(snap: &Snapshot, width: usize, peak: Option<(f64, f64)>) -> Vec<Line<'static>> {
    let sn = &snap.sensors;
    let mut lines = Vec::new();
    if sn.cpu_temps.is_empty() {
        lines.push(dim("CPU temperature  not available (kldload coretemp, or amdtemp on AMD)"));
    } else {
        let tj = sn.cpu_tjmax;
        let colored = |t: f64| Span::styled(format!("{t:.0}"), Style::default().fg(temp_color(t, tj)));
        let mut spans = vec![Span::raw("CPU temp °C ")];
        for (i, t) in sn.cpu_temps.iter().enumerate() {
            spans.push(Span::raw(format!(" {i}:")));
            spans.push(colored(*t));
        }
        let now = sn.cpu_temps.iter().cloned().fold(f64::MIN, f64::max);
        spans.push(Span::raw("   now "));
        spans.push(colored(now));
        if let Some((p, at)) = peak {
            spans.push(Span::raw("   peak "));
            spans.push(colored(p));
            spans.push(Span::styled(format!(" at {}", local_time(at)), DIM));
        }
        if let Some(tj) = tj {
            spans.push(Span::styled(format!("   (throttles at {tj:.0})"), DIM));
        }
        lines.push(Line::from(spans));
    }
    if !sn.thermal_zones.is_empty() {
        let mut spans = vec![Span::raw("ACPI zones  ")];
        for (name, t) in &sn.thermal_zones {
            spans.push(Span::raw(format!(" {name}:")));
            spans.push(Span::styled(format!("{t:.1}°C"), Style::default().fg(temp_color(*t, None))));
        }
        lines.push(Line::from(spans));
    }
    let freqs = &sn.cpu_freqs_mhz;
    lines.push(if freqs.len() > 1 && freqs.iter().any(|f| *f != freqs[0]) {
        let per: Vec<String> = freqs.iter().enumerate().map(|(i, f)| format!("{i}:{f}")).collect();
        Line::raw(format!("CPU clock    MHz  {}", per.join(" ")))
    } else {
        match sn.cpu_freq_mhz {
            Some(f) if freqs.len() > 1 => Line::raw(format!("CPU clock    {f} MHz (all {} CPUs)", freqs.len())),
            Some(f) => Line::raw(format!("CPU clock    {f} MHz")),
            None => dim("CPU clock    not reported"),
        }
    });
    match &sn.battery {
        Some(b) => {
            let left = b.minutes_left.map(|m| format!(", {}h {:02}m left", m / 60, m % 60)).unwrap_or_default();
            let color = if b.life < 15.0 { C_SYS } else if b.life < 40.0 { C_WRITE } else { C_USER };
            let label = format!(
                "Battery      {:>3.0}% {}{left}, AC {} |",
                b.life,
                b.state,
                if b.ac_online { "online" } else { "offline" }
            );
            let bw = width.saturating_sub(label.chars().count() + 1).clamp(10, 40);
            let mut spans = vec![Span::raw(label)];
            spans.extend(bar(&[(b.life / 100.0, '#', color)], bw));
            spans.push(Span::raw("|"));
            lines.push(Line::from(spans));
        }
        None => lines.push(dim("Battery      none")),
    }
    lines
}

/// Shortens to `max` characters with a trailing ellipsis (podman names its
/// jails after 64-character container IDs).
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

fn group_rows(lines: &mut Vec<Line<'static>>, groups: &[GroupRate], extra: impl Fn(&GroupRate) -> String, busy_only: bool) {
    for g in groups {
        if busy_only && g.cpu < 0.1 && g.io < 0.05 {
            continue;
        }
        lines.push(Line::raw(format!(
            "{:>5} {:<16} {:>6} {:>7.1} {:>9} {:>8.1}  {}",
            g.id,
            clip(&g.name, 16),
            g.processes,
            g.cpu,
            human(g.rss),
            g.io,
            extra(g)
        )));
    }
}

fn jails(s: &Sample, v: &View) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    let mut lines = Vec::new();
    if r.jails.is_empty() {
        lines.push(dim("No jails running"));
    } else {
        lines.push(hdr(format!(
            "{:>5} {:<16} {:>6} {:>7} {:>9} {:>8}  {}",
            "JID", "Jail", "Procs", "%CPU", "RES", "IO/s", "Hostname"
        )));
        let host = |g: &GroupRate| {
            s.snap.jails.iter().find(|j| j.jid as i64 == g.id).map(|j| j.hostname.clone()).unwrap_or_default()
        };
        group_rows(&mut lines, &r.jails, host, v.busy_only);
    }
    if r.vms.is_empty() {
        lines.push(dim("No bhyve VMs running"));
    } else {
        lines.push(hdr(format!("{:>5} {:<16} {:>6} {:>7} {:>9} {:>8}", "PID", "bhyve VM", "Procs", "%CPU", "RES", "IO/s")));
        group_rows(&mut lines, &r.vms, |_| String::new(), v.busy_only);
    }
    lines
}

fn zfs(s: &Sample) -> Vec<Line<'static>> {
    let Some(z) = &s.snap.zfs else { return vec![dim("ZFS is not loaded")] };
    let zr = s.rates.as_ref().and_then(|r| r.zfs.as_ref());
    let ratio = zr
        .and_then(|r| r.arc_hit_ratio)
        .map(|h| format!("{:.1}%", h * 100.0))
        .unwrap_or_else(|| "-".into());
    let mut lines = vec![Line::raw(format!(
        "ARC {} (target {}, max {})   hit ratio {ratio}   lookups/s {:.0}",
        human(z.arc_size),
        human(z.arc_target),
        human(z.arc_max),
        zr.map_or(0.0, |r| r.arc_lookups)
    ))];
    if z.l2_size > 0 {
        let total = z.l2_hits + z.l2_misses;
        let ratio = if total > 0 { z.l2_hits as f64 * 100.0 / total as f64 } else { 0.0 };
        lines.push(Line::raw(format!("L2ARC {}   hit ratio since boot {ratio:.1}%", human(z.l2_size))));
    }
    if z.pools.is_empty() {
        lines.push(dim("No pools imported"));
        return lines;
    }
    let nw = name_width(z.pools.iter().map(|p| p.name.as_str()));
    lines.push(hdr(format!(
        "{:<nw$}{:<10}{:>9}{:>9}{:>9}{:>6}{:>6}{:>11}{:>11}{:>8}{:>8}",
        "Pool", "Health", "Size", "Alloc", "Free", "Frag", "Cap", "Read-KB/s", "Write-KB/s", "Rd/s", "Wr/s"
    )));
    for (i, p) in z.pools.iter().enumerate() {
        let pr = zr.and_then(|r| r.pools.get(i)).copied().unwrap_or_default();
        let cap = (p.allocated * 100).checked_div(p.size).unwrap_or(0);
        let health = if p.health == "ONLINE" { Style::default().fg(C_USER) } else { Style::default().fg(C_SYS) };
        lines.push(Line::from(vec![
            Span::raw(format!("{:<nw$}", p.name)),
            Span::styled(format!("{:<10}", p.health), health),
            Span::raw(format!(
                "{:>9}{:>9}{:>9}{:>6}{:>5}%{:>11.1}{:>11.1}{:>8.1}{:>8.1}",
                human(p.size),
                human(p.allocated),
                human(p.free),
                p.fragmentation.map(|f| format!("{f}%")).unwrap_or_else(|| "-".into()),
                cap,
                pr.read_bps / 1024.0,
                pr.write_bps / 1024.0,
                pr.read_iops,
                pr.write_iops
            )),
        ]));
    }
    lines
}

fn nfs(s: &Sample) -> Vec<Line<'static>> {
    if s.snap.nfs.is_none() {
        return vec![dim("No NFS activity (no NFS mounts and nfsd is not running)")];
    }
    let Some(n) = s.rates.as_ref().and_then(|r| r.nfs.as_ref()) else { return waiting() };
    let top = |ops: &[(String, f64)]| -> String {
        let busy: Vec<String> =
            ops.iter().filter(|o| o.1 >= 0.05).take(8).map(|(op, r)| format!("{op} {r:.1}")).collect();
        if busy.is_empty() { "idle".into() } else { busy.join("  ") }
    };
    let retry = if n.client_retries > 0.0 || n.client_timeouts > 0.0 { Style::default().fg(C_SYS) } else { Style::default() };
    vec![
        Line::from(vec![
            Span::raw(format!("Client  {:>8.1} ops/s   ", n.client_total)),
            Span::styled(format!("retries/s {:.1}  timeouts/s {:.1}", n.client_retries, n.client_timeouts), retry),
        ]),
        Line::raw(format!("        {}", top(&n.client_ops))),
        Line::raw(format!("Server  {:>8.1} ops/s", n.server_total)),
        Line::raw(format!("        {}", top(&n.server_ops))),
    ]
}

fn vm_detail(s: &Sample) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    let v = &r.vm;
    vec![
        hdr(format!("{:<16}{:>12}{:>12}   {:<16}{:>12}", "per second", "", "", "", "")),
        Line::raw(format!(
            "{:<16}{:>12.0}   {:<22}{:>10.0}   {:<18}{:>10.0}",
            "Page faults", v.faults, "Zero-fill faults", v.zero_fill_faults, "Copy-on-write", v.cow_faults
        )),
        Line::raw(format!(
            "{:<16}{:>12.1}   {:<22}{:>10.1}   {:<18}{:>10.1}",
            "File page-ins", v.vnode_pages_in, "File page-outs", v.vnode_pages_out, "In-transit faults", v.intransit_faults
        )),
        Line::raw(format!(
            "{:<16}{:>12.1}   {:<22}{:>10.1}   {:<18}{:>10.1}",
            "Swap page-ins", v.swap_pages_in, "Swap page-outs", v.swap_pages_out, "Reactivated", v.reactivated
        )),
        Line::raw(format!(
            "{:<16}{:>12.0}   {:<22}{:>10.0}   {:<18}{:>10.1}",
            "Pages freed", v.pages_freed, "Page daemon scanned", v.pageout_scanned, "Daemon wakeups", v.pageout_wakeups
        )),
        dim(format!(
            "Pager operations/s: file in {:.1} out {:.1}, swap in {:.1} out {:.1}",
            v.vnode_ins, v.vnode_outs, v.swap_ins, v.swap_outs
        )),
    ]
}

fn superpages(s: &Sample) -> Vec<Line<'static>> {
    let Some(sp) = &s.snap.superpages else { return vec![dim("Superpage statistics not available")] };
    let mut lines = vec![Line::raw(format!(
        "Superpages {}   since boot: {} mappings, {} promotions, {} demotions, {} failed promotions",
        if sp.enabled { "enabled" } else { "disabled (vm.pmap.pg_ps_enabled=0)" },
        sp.mappings,
        sp.promotions,
        sp.demotions,
        sp.failures
    ))];
    match s.rates.as_ref().and_then(|r| r.superpages) {
        Some(r) => lines.push(Line::raw(format!(
            "per second:  mappings {:.1}   promotions {:.1}   demotions {:.1}   failed promotions {:.1}",
            r.mappings, r.promotions, r.demotions, r.failures
        ))),
        None => lines.extend(waiting()),
    }
    lines
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Ok,
    Warning,
    Danger,
}

/// nmon's verbose mode: each check with its value and an OK / WARNING /
/// DANGER verdict, problems first.
fn checks(s: &Sample) -> Vec<Line<'static>> {
    let Some(r) = &s.rates else { return waiting() };
    let snap = &s.snap;
    let level = |v: f64, warn: f64, danger: f64| {
        if v >= danger {
            Level::Danger
        } else if v >= warn {
            Level::Warning
        } else {
            Level::Ok
        }
    };
    let mut out: Vec<(Level, String)> = Vec::new();
    let busy = 1.0 - r.cpu_total.idle;
    out.push((level(busy, 0.8, 0.95), format!("CPU busy {:.0}% (warn 80, danger 95)", busy * 100.0)));
    let ncpu = s.host.ncpu.max(1) as f64;
    let rq = snap.runq.runnable as f64;
    out.push((level(rq / ncpu, 1.0, 2.0), format!("Run queue {} for {} CPUs (warn > 1x, danger > 2x)", rq, ncpu)));
    let m = &snap.memory;
    if m.total > 0 {
        let avail = (m.free + m.inactive) as f64 / m.total as f64;
        out.push((level(1.0 - avail, 0.9, 0.95), format!("Memory available {:.1}% (free + inactive; warn < 10, danger < 5)", avail * 100.0)));
    }
    let (st, su): (u64, u64) = snap.swap.iter().fold((0, 0), |a, d| (a.0 + d.total, a.1 + d.used));
    if st > 0 {
        let used = su as f64 / st as f64;
        out.push((level(used, 0.2, 0.5), format!("Swap used {:.1}% (warn 20, danger 50)", used * 100.0)));
    }
    if r.vm.swap_pages_out > 0.0 {
        out.push((Level::Warning, format!("Swapping out {:.0} pages/s", r.vm.swap_pages_out)));
    }
    for (d, dr) in snap.disks.iter().zip(&r.disks) {
        out.push((level(dr.busy, 0.7, 0.9), format!("Disk {} busy {:.0}% (warn 70, danger 90)", d.name, dr.busy * 100.0)));
        let lat = dr.read_ms.max(dr.write_ms);
        if lat > 0.0 {
            out.push((level(lat, 20.0, 50.0), format!("Disk {} latency {:.1} ms (warn 20, danger 50)", d.name, lat)));
        }
    }
    for f in &snap.filesystems {
        let total = (f.used() + f.avail).max(1) as f64;
        let used = f.used() as f64 / total;
        out.push((level(used, 0.85, 0.95), format!("Filesystem {} {:.0}% full (warn 85, danger 95)", f.mountpoint, used * 100.0)));
    }
    for (n, nr) in snap.nets.iter().zip(&r.nets) {
        if nr.errors_ps > 0.0 || nr.drops_ps > 0.0 {
            out.push((Level::Warning, format!("Interface {}: {:.1} errors/s, {:.1} drops/s", n.name, nr.errors_ps, nr.drops_ps)));
        }
    }
    if let Some(t) = r.tcp
        && t.segs_sent >= 10.0
    {
        let pct = t.retransmits / t.segs_sent;
        out.push((level(pct, 0.01, 0.05), format!("TCP retransmits {:.2}% of segments sent (warn 1, danger 5)", pct * 100.0)));
        if t.listen_drops > 0.0 {
            out.push((Level::Warning, format!("TCP listen-queue overflows {:.1}/s", t.listen_drops)));
        }
    }
    let sn = &snap.sensors;
    if let Some(hot) = sn.cpu_temps.iter().copied().reduce(f64::max) {
        let lv = match temp_color(hot, sn.cpu_tjmax) {
            C_SYS => Level::Danger,
            C_WRITE => Level::Warning,
            _ => Level::Ok,
        };
        out.push((lv, format!("CPU temperature {hot:.0} °C")));
    }
    if let Some(b) = &sn.battery
        && !b.ac_online
    {
        out.push((level(1.0 - b.life / 100.0, 0.8, 0.9), format!("Battery {:.0}% and discharging", b.life)));
    }
    if let Some(z) = &snap.zfs {
        for p in &z.pools {
            let lv = if p.health == "ONLINE" { Level::Ok } else { Level::Danger };
            out.push((lv, format!("ZFS pool {} {}", p.name, p.health)));
            if p.size > 0 {
                let cap = p.allocated as f64 / p.size as f64;
                out.push((level(cap, 0.8, 0.9), format!("ZFS pool {} {:.0}% allocated (warn 80, danger 90)", p.name, cap * 100.0)));
            }
        }
    }
    if let Some(n) = &r.nfs
        && (n.client_retries > 0.0 || n.client_timeouts > 0.0)
    {
        out.push((Level::Warning, format!("NFS client: {:.1} retries/s, {:.1} timeouts/s", n.client_retries, n.client_timeouts)));
    }
    out.sort_by_key(|(lv, _)| std::cmp::Reverse(*lv));
    let problems = out.iter().filter(|(lv, _)| *lv != Level::Ok).count();
    let mut lines = vec![hdr(if problems == 0 {
        format!("All {} checks OK", out.len())
    } else {
        format!("{problems} of {} checks need attention", out.len())
    })];
    for (lv, text) in out {
        let (label, style) = match lv {
            Level::Danger => ("DANGER ", Style::default().fg(C_SYS).add_modifier(Modifier::BOLD)),
            Level::Warning => ("WARNING", Style::default().fg(C_WRITE).add_modifier(Modifier::BOLD)),
            Level::Ok => ("ok     ", DIM),
        };
        lines.push(Line::from(vec![Span::styled(label, style), Span::raw(format!("  {text}"))]));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn width(spans: &[Span]) -> usize {
        spans.iter().map(|s| s.content.chars().count()).sum()
    }

    #[test]
    fn invalidate_overwrites_leftover_text() {
        // A screen already full of text that a new Terminal knows nothing about.
        let mut before = Terminal::new(TestBackend::new(30, 4)).unwrap();
        before.draw(|f| f.render_widget(Paragraph::new("Welcome to FreeBSD!\nmotd"), f.area())).unwrap();
        let mut t = Terminal::new(before.backend().clone()).unwrap();
        invalidate(&mut t);
        t.draw(|f| f.render_widget(Paragraph::new("jmon"), f.area())).unwrap();
        t.backend().assert_buffer_lines(["jmon                          ", "", "", ""]);
    }

    #[test]
    fn bar_fills_exact_width() {
        for w in [1, 7, 40, 101] {
            assert_eq!(width(&bar(&[(0.333, 'U', C_USER), (0.333, 's', C_SYS), (0.334, 'i', C_INTR)], w)), w);
            assert_eq!(width(&bar(&[(1.5, 'U', C_USER)], w)), w);
            assert_eq!(width(&bar(&[], w)), w);
        }
    }

    #[test]
    fn scale_has_width() {
        assert_eq!(scale(40).chars().count(), 40);
        assert!(scale(40).starts_with("0 "));
        assert_eq!(scale(5).chars().count(), 5);
        assert!(scale(40).ends_with("100"));
    }

    #[test]
    fn help_columns_line_up() {
        let text = |l: &Line| l.spans.iter().map(|s| s.content.to_string()).collect::<String>();
        let rows: Vec<String> = help_lines().iter().map(text).filter(|t| t.starts_with("  ")).collect();
        // The "=" after each key is at the same offset in every column.
        let starts = |r: &String| -> Vec<usize> { r.char_indices().filter(|&(_, c)| c == '=').map(|(i, _)| i).collect() };
        let first = starts(&rows[0]);
        assert_eq!(first.len(), 3);
        for r in &rows {
            let s = starts(r);
            assert_eq!(s, first[..s.len()], "misaligned: {r}");
        }
        // Every panel key in Panel::from_key appears in the help.
        for c in "hrcClmkdnTNjtsJzgoVLv".chars() {
            assert!(HELP_PANELS.iter().any(|(k, _)| k.starts_with(c)) || c == '?', "missing {c}");
        }
    }

    #[test]
    fn peak_marker_sits_beyond_the_bar() {
        let text = |spans: &[Span]| spans.iter().map(|s| s.content.to_string()).collect::<String>();
        let b = bar_with_peak(&[(0.2, 'U', C_USER)], 10, Some(0.6));
        assert_eq!(text(&b), "UU   >    ");
        // A peak inside the current bar isn't drawn.
        assert_eq!(text(&bar_with_peak(&[(0.6, 'U', C_USER)], 10, Some(0.3))), "UUUUUU    ");
        assert_eq!(text(&bar_with_peak(&[(0.0, 'U', C_USER)], 10, Some(1.0))), "         >");
    }

    #[test]
    fn temperature_colours_follow_throttle_point() {
        assert_eq!(temp_color(60.0, Some(100.0)), C_USER);
        assert_eq!(temp_color(72.0, Some(100.0)), C_WRITE);
        assert_eq!(temp_color(86.0, Some(100.0)), C_SYS);
        // A CPU that throttles at 90 is hotter, relatively, at the same reading.
        assert_eq!(temp_color(76.0, Some(90.0)), C_SYS);
        assert_eq!(temp_color(76.0, None), C_WRITE);
    }

    #[test]
    fn temperature_peak_tracks_hottest_reading_and_resets() {
        use crate::model::{HostInfo, Snapshot};
        let host = Arc::new(HostInfo {
            hostname: "h".into(),
            os_type: "freebsd".into(),
            os_release: String::new(),
            machine: String::new(),
            cpu_model: String::new(),
            ncpu: 2,
            physmem: 0,
            pagesize: 4096,
            demo: true,
        });
        let sample = |temps: Vec<f64>, ts: f64| {
            let mut snap = Snapshot::empty();
            snap.timestamp = ts;
            snap.sensors.cpu_temps = temps;
            Sample::derive(1, host.clone(), None, snap)
        };
        let mut app = App::new(Hub::new(Duration::from_secs(2), 0), "s", vec![], LogRing::default());
        app.record(&sample(vec![50.0, 61.0], 100.0));
        app.record(&sample(vec![55.0, 58.0], 200.0));
        assert_eq!(app.temp_peak, Some((61.0, 100.0)));
        app.record(&sample(vec![70.0, 40.0], 300.0));
        assert_eq!(app.temp_peak, Some((70.0, 300.0)));
        app.key(KeyCode::Char('R'), KeyModifiers::NONE);
        assert_eq!(app.temp_peak, None);
    }

    #[test]
    fn user_filter_input() {
        let mut app = App::new(Hub::new(Duration::from_secs(2), 0), "t", vec![], LogRing::default());
        app.key(KeyCode::Char('u'), KeyModifiers::NONE);
        for c in "www".chars() {
            app.key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        // Keys typed into the filter must not toggle panels.
        assert_eq!(app.panels, vec![Panel::Top]);
        app.key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.user_filter.as_deref(), Some("www"));
        app.key(KeyCode::Char('u'), KeyModifiers::NONE);
        for _ in 0..3 {
            app.key(KeyCode::Backspace, KeyModifiers::NONE);
        }
        app.key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.user_filter, None);
    }
}

#[cfg(all(test, not(target_os = "freebsd")))]
mod render_tests {
    use super::*;
    use crate::platform::Collector;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn demo_sample() -> Sample {
        let mut c = Collector::new().unwrap();
        let first = c.collect();
        std::thread::sleep(Duration::from_millis(50));
        Sample::derive(1, c.host(), Some(&first), c.collect())
    }

    #[test]
    fn renders_all_panels_at_various_sizes() {
        let s = demo_sample();
        for (w, h) in [(170, 120), (80, 24), (40, 10)] {
            for (busy, args) in [(false, false), (true, true)] {
                let mut app = App::new(
                    Hub::new(Duration::from_secs(2), 0),
                    "rcClmkdgoGnTNjszJVLvt",
                    vec!["otlp http://x:4317".into()],
                    LogRing::default(),
                );
                app.busy_only = busy;
                app.show_args = args;
                app.show_partitions = busy;
                app.mono = args;
                app.groups = vec!["mirror=nda0,ada0".parse().unwrap(), "data=ada0p1,ada0p2".parse().unwrap()];
                for _ in 0..30 {
                    app.history.push_back(s.rates.as_ref().unwrap().cpu_total);
                }
                let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
                t.draw(|f| app.draw(f, Some(&s))).unwrap();
                if w == 170 && !busy && std::env::var("JMON_DUMP").is_ok() {
                    let buf = t.backend().buffer();
                    for y in 0..h {
                        let line: String = (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect();
                        println!("{}", line.trim_end());
                    }
                }
            }
        }
    }
}

#[cfg(all(test, not(target_os = "freebsd")))]
mod theme_tests {
    use super::*;
    use crate::platform::Collector;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Nothing outside the coloured header badges may force a grey or black,
    /// because those vanish on either dark or light terminal themes.
    #[test]
    fn styles_adapt_to_light_and_dark_themes() {
        let mut c = Collector::new().unwrap();
        let first = c.collect();
        std::thread::sleep(Duration::from_millis(20));
        let s = Sample::derive(1, c.host(), Some(&first), c.collect());
        let app = App::new(Hub::new(Duration::from_secs(2), 0), "rcClmkdgonTNjszJVLvt", vec![], LogRing::default());
        let mut t = Terminal::new(TestBackend::new(170, 120)).unwrap();
        t.draw(|f| app.draw(f, Some(&s))).unwrap();
        let buf = t.backend().buffer();
        let fixed = [Color::Gray, Color::DarkGray, Color::Black];
        for y in 1..120 {
            for x in 0..170 {
                let cell = &buf[(x, y)];
                assert!(!fixed.contains(&cell.fg) && !fixed.contains(&cell.bg), "fixed grey at {x},{y}");
            }
        }
        // Header: reverse video except the version badge.
        assert!(buf[(40, 0)].modifier.contains(Modifier::REVERSED));
        assert!(!buf[(1, 0)].modifier.contains(Modifier::REVERSED));
        // Borders are dimmed; titles are bold and not dimmed.
        assert!(buf[(0, 2)].modifier.contains(Modifier::DIM));
        let title = (0..170).find(|&x| buf[(x, 1)].symbol() == "R").unwrap();
        assert!(buf[(title, 1)].modifier.contains(Modifier::BOLD));
        assert!(!buf[(title, 1)].modifier.contains(Modifier::DIM));
    }
}

#[cfg(all(test, not(target_os = "freebsd")))]
mod alignment_tests {
    use super::*;
    use crate::model::NetIf;
    use crate::platform::Collector;

    fn text(l: &Line) -> String {
        l.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn long_interface_names_keep_columns_aligned() {
        let mut c = Collector::new().unwrap();
        let mut a = c.collect();
        std::thread::sleep(Duration::from_millis(20));
        let mut b = c.collect();
        for name in ["cni-podman0", "vnetfb9ff218"] {
            let n = NetIf { name: name.into(), up: true, mtu: 1500, ..Default::default() };
            a.nets.push(n.clone());
            b.nets.push(n);
        }
        let s = Sample::derive(1, c.host(), Some(&a), b);
        let v = View {
            width: 160,
            show_partitions: false,
            busy_only: false,
            sort: TopSort::Cpu,
            show_args: false,
            user_filter: None,
        };
        let lines: Vec<String> = nets(&s, &v).iter().map(text).collect();
        for l in &lines {
            println!("{l}");
        }
        // Every row ends at the same column, so the MTU/Link columns line up.
        let ends: Vec<usize> = lines.iter().map(|l| l.trim_end_matches(['u', 'p', 'd', 'o', 'w', 'n', 'L', 'i', 'k', ' ']).len()).collect();
        assert!(ends.windows(2).all(|w| w[0] == w[1]), "{ends:?}");
    }
}
