//! `kernel_config` check primitive reading `/boot/config-*`, `/proc/config.gz`, or
//! `/lib/modules/*/build/.config` in memory through [`SystemView`].

use crate::checks::CheckOutcome;
use crate::rules::schema::KernelConfigCheck;
use crate::sys::SystemView;
use flate2::read::GzDecoder;
use std::collections::BTreeMap;
use std::io::Read;

enum ConfigValue {
    Set(String),
    Unset,
}

/// Evaluates kernel compilation options (`CONFIG_*`).
///
/// If no kernel configuration source can be read, returns `WARN` (never `PASS`).
pub fn evaluate(spec: &KernelConfigCheck, view: &dyn SystemView) -> CheckOutcome {
    let (source_path, content) = match load_kernel_config(view) {
        Ok(pair) => pair,
        Err(reason) => {
            return CheckOutcome::warn(
                format!("{} kernel config option(s) verified", spec.options.len()),
                "kernel configuration unavailable",
                vec![reason],
            );
        }
    };

    let parsed = parse_kconfig(&content);
    let mut failed_expected = Vec::new();
    let mut failed_actual = Vec::new();
    let mut details = Vec::new();

    for opt in &spec.options {
        match parsed.get(&opt.name) {
            Some(ConfigValue::Set(actual)) if actual == &opt.expected => {}
            Some(ConfigValue::Set(actual)) => {
                details.push(format!(
                    "{}: expected {}={}, got {}={} (from {source_path})",
                    opt.name, opt.name, opt.expected, opt.name, actual
                ));
                failed_expected.push(format!("{}={}", opt.name, opt.expected));
                failed_actual.push(format!("{}={actual}", opt.name));
            }
            Some(ConfigValue::Unset) => {
                details.push(format!(
                    "{}: expected {}={}, got 'not set' (from {source_path})",
                    opt.name, opt.name, opt.expected
                ));
                failed_expected.push(format!("{}={}", opt.name, opt.expected));
                failed_actual.push(format!("{}=not set", opt.name));
            }
            None => {
                details.push(format!(
                    "{}: expected {}={}, absent from {source_path}",
                    opt.name, opt.name, opt.expected
                ));
                failed_expected.push(format!("{}={}", opt.name, opt.expected));
                failed_actual.push(format!("{}=absent", opt.name));
            }
        }
    }

    if !failed_expected.is_empty() {
        return CheckOutcome::fail(
            failed_expected.join(", "),
            failed_actual.join(", "),
            details,
        );
    }

    CheckOutcome::pass(
        format!("{} kernel config option(s) compliant", spec.options.len()),
        format!(
            "all {} kernel config option(s) compliant (from {source_path})",
            spec.options.len()
        ),
    )
}

fn load_kernel_config(view: &dyn SystemView) -> Result<(String, String), String> {
    let mut attempts = Vec::new();

    if let Ok(release) = view.kernel_release() {
        let boot_cfg = format!("/boot/config-{release}");
        match view.read_to_string(&boot_cfg) {
            Ok(content) => return Ok((boot_cfg, content)),
            Err(err) => attempts.push(format!("{boot_cfg}: {err}")),
        }

        let proc_gz = "/proc/config.gz";
        match view.read_bytes(proc_gz) {
            Ok(bytes) => {
                let text = decompress_gzip(&bytes)
                    .map_err(|e| format!("failed to decompress {proc_gz}: {e}"))?;
                return Ok((proc_gz.to_string(), text));
            }
            Err(err) => attempts.push(format!("{proc_gz}: {err}")),
        }

        let build_cfg = format!("/lib/modules/{release}/build/.config");
        match view.read_to_string(&build_cfg) {
            Ok(content) => return Ok((build_cfg, content)),
            Err(err) => attempts.push(format!("{build_cfg}: {err}")),
        }
    } else {
        let proc_gz = "/proc/config.gz";
        match view.read_bytes(proc_gz) {
            Ok(bytes) => {
                let text = decompress_gzip(&bytes)
                    .map_err(|e| format!("failed to decompress {proc_gz}: {e}"))?;
                return Ok((proc_gz.to_string(), text));
            }
            Err(err) => attempts.push(format!("{proc_gz}: {err}")),
        }
        attempts.push("/proc/sys/kernel/osrelease: not found".to_string());
    }

    Err(format!(
        "could not read kernel config (tried: {})",
        attempts.join("; ")
    ))
}

fn decompress_gzip(bytes: &[u8]) -> Result<String, std::io::Error> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = String::new();
    decoder.read_to_string(&mut out)?;
    Ok(out)
}

fn parse_kconfig(content: &str) -> BTreeMap<String, ConfigValue> {
    let mut map = BTreeMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            if let Some(name) = rest.strip_suffix(" is not set") {
                if name.starts_with("CONFIG_") {
                    map.insert(name.to_string(), ConfigValue::Unset);
                }
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            if key.starts_with("CONFIG_") {
                map.insert(key.to_string(), ConfigValue::Set(val.trim().to_string()));
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::rules::schema::KernelOption;
    use crate::sys::RootFsSystemView;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    fn sample_spec() -> KernelConfigCheck {
        KernelConfigCheck {
            options: vec![
                KernelOption {
                    name: "CONFIG_SECCOMP".to_string(),
                    expected: "y".to_string(),
                },
                KernelOption {
                    name: "CONFIG_MODULE_SIG_HASH".to_string(),
                    expected: "\"sha512\"".to_string(),
                },
            ],
        }
    }

    #[test]
    fn passes_from_boot_config() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("proc/sys/kernel")).expect("mkdir");
        fs::create_dir_all(dir.path().join("boot")).expect("mkdir");
        fs::write(dir.path().join("proc/sys/kernel/osrelease"), "6.8.0-test\n").expect("write");
        fs::write(
            dir.path().join("boot/config-6.8.0-test"),
            "# comment\nCONFIG_SECCOMP=y\nCONFIG_MODULE_SIG_HASH=\"sha512\"\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn passes_from_gzipped_proc_config() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("proc")).expect("mkdir");
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"CONFIG_SECCOMP=y\nCONFIG_MODULE_SIG_HASH=\"sha512\"\n")
            .expect("gz");
        let gz_bytes = enc.finish().expect("finish");
        fs::write(dir.path().join("proc/config.gz"), gz_bytes).expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn fails_when_option_explicitly_unset() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("boot")).expect("mkdir");
        fs::write(
            dir.path().join("boot/config-6.8.0-test"),
            "# CONFIG_SECCOMP is not set\nCONFIG_MODULE_SIG_HASH=\"sha256\"\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.actual.as_deref().unwrap().contains("not set"));
    }

    #[test]
    fn warns_when_no_kernel_config_exists() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Warn);
    }
}
