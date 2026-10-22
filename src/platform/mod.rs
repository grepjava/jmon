//! OS-specific collection. FreeBSD is the real target; elsewhere a synthetic
//! source stands in so the screen and exporters can be developed anywhere.

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use freebsd::Collector;

#[cfg(not(target_os = "freebsd"))]
mod demo;
#[cfg(not(target_os = "freebsd"))]
pub use demo::Collector;
