//! Log destinations beyond plain stderr: an in-memory ring the full-screen UI
//! shows in its footer (so warnings don't write over the display), and
//! syslog(3) for running as a service.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

const KEEP: usize = 50;

#[derive(Clone, Default)]
pub struct LogRing(Arc<Mutex<VecDeque<String>>>);

impl LogRing {
    pub fn last(&self) -> Option<String> {
        self.0.lock().unwrap().back().cloned()
    }
}

pub struct RingWriter(LogRing);

impl io::Write for RingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut q = (self.0).0.lock().unwrap();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            if q.len() == KEEP {
                q.pop_front();
            }
            q.push_back(line.trim().to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogRing {
    type Writer = RingWriter;

    fn make_writer(&'a self) -> RingWriter {
        RingWriter(self.clone())
    }
}

/// Sends each event to syslog(3) as one message, at the matching priority.
#[cfg(unix)]
pub struct Syslog;

#[cfg(unix)]
impl Syslog {
    pub fn open() -> Syslog {
        static IDENT: &std::ffi::CStr = c"jmon";
        unsafe { libc::openlog(IDENT.as_ptr(), libc::LOG_PID, libc::LOG_DAEMON) };
        Syslog
    }
}

#[cfg(unix)]
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Syslog {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        use std::fmt::Write;
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if !self.0.is_empty() {
                    self.0.push(' ');
                }
                if field.name() == "message" {
                    let _ = write!(self.0, "{value:?}");
                } else {
                    let _ = write!(self.0, "{}={value:?}", field.name());
                }
            }
        }
        let mut f = Fields(String::new());
        event.record(&mut f);
        let meta = event.metadata();
        let priority = match *meta.level() {
            tracing::Level::ERROR => libc::LOG_ERR,
            tracing::Level::WARN => libc::LOG_WARNING,
            tracing::Level::INFO => libc::LOG_INFO,
            _ => libc::LOG_DEBUG,
        };
        let text = if meta.target().starts_with("jmon") { f.0 } else { format!("{}: {}", meta.target(), f.0) };
        if let Ok(msg) = std::ffi::CString::new(text.replace('\0', " ")) {
            unsafe { libc::syslog(priority, c"%s".as_ptr(), msg.as_ptr()) };
        }
    }
}
