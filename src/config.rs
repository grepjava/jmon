//! TOML config file support. Keys are the long option names; values are
//! turned into command-line arguments placed before the real ones, so
//! anything given on the command line overrides the file.

use crate::Cli;
use anyhow::{Context, Result, bail};
use clap::CommandFactory;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const DEFAULT_PATH: &str = "/usr/local/etc/jmon.conf";

/// The process arguments with config-file options spliced in after argv[0].
pub fn args() -> Result<Vec<OsString>> {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    let explicit = explicit_path(&args).or_else(|| std::env::var_os("JMON_CONFIG").map(PathBuf::from));
    let path = match explicit {
        Some(p) => p,
        None if Path::new(DEFAULT_PATH).exists() => PathBuf::from(DEFAULT_PATH),
        None => return Ok(args),
    };
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading config {}", path.display()))?;
    let extra = to_args(&text).with_context(|| format!("in config {}", path.display()))?;
    let rest = args.split_off(1.min(args.len()));
    args.extend(extra);
    args.extend(rest);
    Ok(args)
}

fn explicit_path(args: &[OsString]) -> Option<PathBuf> {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        let s = a.to_string_lossy();
        if s == "--config" {
            return it.next().map(PathBuf::from);
        }
        if let Some(v) = s.strip_prefix("--config=") {
            return Some(PathBuf::from(v));
        }
    }
    None
}

pub fn to_args(text: &str) -> Result<Vec<OsString>> {
    let table: toml::Table = text.parse()?;
    let cmd = Cli::command();
    let known: Vec<String> = cmd.get_arguments().filter_map(|a| a.get_long().map(str::to_string)).collect();
    let mut out = Vec::new();
    for (key, value) in table {
        if key == "config" || !known.contains(&key) {
            bail!("unknown option `{key}`");
        }
        let flag = OsString::from(format!("--{key}"));
        match value {
            toml::Value::Boolean(true) => out.push(flag),
            toml::Value::Boolean(false) => {}
            toml::Value::String(s) => out.extend([flag, s.into()]),
            toml::Value::Integer(i) => out.extend([flag, i.to_string().into()]),
            toml::Value::Float(f) => out.extend([flag, f.to_string().into()]),
            // Lists repeat the option, e.g. disk-group = ["mirror=ada0,ada1"].
            toml::Value::Array(items) => {
                for item in items {
                    let toml::Value::String(s) = item else { bail!("option `{key}` must be a list of strings") };
                    out.extend([flag.clone(), s.into()]);
                }
            }
            other => bail!("option `{key}` has unsupported value {other}"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn config_values_become_args_and_cli_wins() {
        let extra = to_args("interval = 10\ndaemon = true\notlp-endpoint = \"http://c:4317\"\nonce = false\n").unwrap();
        let mut argv: Vec<OsString> = vec!["jmon".into()];
        argv.extend(extra);
        argv.extend(["-s".into(), "3".into()]);
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.interval, 3.0, "command line overrides the file");
        assert!(cli.daemon);
        assert!(!cli.once);
        assert_eq!(cli.otlp_endpoint.as_deref(), Some("http://c:4317"));
    }

    #[test]
    fn sample_config_is_valid_with_everything_enabled() {
        let sample = include_str!("../contrib/jmon.conf.sample");
        assert!(to_args(sample).is_ok());
        let all: String = sample
            .lines()
            .map(|l| l.strip_prefix('#').filter(|r| r.contains(" = ")).unwrap_or(l))
            .map(|l| format!("{}\n", l.split(" # ").next().unwrap()))
            .collect();
        let mut argv: Vec<OsString> = vec!["jmon".into()];
        argv.extend(to_args(&all).unwrap());
        let cli = Cli::try_parse_from(argv).unwrap();
        assert!(cli.auto_record && cli.rotate);
        assert_eq!(cli.export_top, 10);
    }

    #[test]
    fn lists_repeat_the_option() {
        let mut argv: Vec<OsString> = vec!["jmon".into()];
        argv.extend(to_args("disk-group = [\"mirror=ada0,ada1\", \"data=da0\"]").unwrap());
        let cli = Cli::try_parse_from(argv).unwrap();
        assert_eq!(cli.disk_groups.len(), 2);
        assert_eq!(cli.disk_groups[0].members, vec!["ada0", "ada1"]);
        assert!(to_args("disk-group = [1, 2]").is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(to_args("intreval = 5").is_err());
        assert!(to_args("config = \"/x\"").is_err());
    }
}
