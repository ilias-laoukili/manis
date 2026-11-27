//! `package_state` check primitive parsing `/var/lib/dpkg/status` directly through [`SystemView`]
//! (no `dpkg` subprocesses, 100% offline-testable via `--root`).

use crate::checks::CheckOutcome;
use crate::rules::schema::{PackageStateCheck, PackageStateMode};
use crate::sys::SystemView;
use std::collections::BTreeSet;

/// Evaluates Debian/Ubuntu package presence or absence from `/var/lib/dpkg/status`.
///
/// Missing or unreadable status database always yields `WARN` (never silent `PASS`).
pub fn evaluate(spec: &PackageStateCheck, view: &dyn SystemView) -> CheckOutcome {
    let expected = describe_expected(spec);

    let content = match view.read_to_string(&spec.dpkg_status_path) {
        Ok(c) => c,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{} unavailable", spec.dpkg_status_path),
                vec![format!("{}: {err}", spec.dpkg_status_path)],
            );
        }
    };

    let installed = parse_installed_dpkg_packages(&content);

    match spec.mode {
        PackageStateMode::AllInstalled => {
            let missing: Vec<String> = spec
                .packages
                .iter()
                .filter(|p| !installed.contains(p.as_str()))
                .cloned()
                .collect();
            if missing.is_empty() {
                CheckOutcome::pass(expected, format!("installed: {}", spec.packages.join(", ")))
            } else {
                let details = missing
                    .iter()
                    .map(|p| format!("package '{p}' is not installed"))
                    .collect();
                CheckOutcome::fail(
                    expected,
                    format!("missing: {}", missing.join(", ")),
                    details,
                )
            }
        }
        PackageStateMode::AnyInstalled => {
            let present: Vec<String> = spec
                .packages
                .iter()
                .filter(|p| installed.contains(p.as_str()))
                .cloned()
                .collect();
            if present.is_empty() {
                CheckOutcome::fail(
                    expected,
                    "none of the required packages are installed",
                    vec![format!(
                        "none of [{}] found with 'Status: install ok installed'",
                        spec.packages.join(", ")
                    )],
                )
            } else {
                CheckOutcome::pass(expected, format!("installed: {}", present.join(", ")))
            }
        }
        PackageStateMode::AllAbsent => {
            let present: Vec<String> = spec
                .packages
                .iter()
                .filter(|p| installed.contains(p.as_str()))
                .cloned()
                .collect();
            if present.is_empty() {
                CheckOutcome::pass(expected, "none installed")
            } else {
                let details = present
                    .iter()
                    .map(|p| format!("forbidden package '{p}' is installed"))
                    .collect();
                CheckOutcome::fail(
                    expected,
                    format!("installed: {}", present.join(", ")),
                    details,
                )
            }
        }
    }
}

fn describe_expected(spec: &PackageStateCheck) -> String {
    match spec.mode {
        PackageStateMode::AllInstalled => {
            format!("package(s) installed: {}", spec.packages.join(", "))
        }
        PackageStateMode::AnyInstalled => {
            format!(
                "at least one package installed: {}",
                spec.packages.join(" | ")
            )
        }
        PackageStateMode::AllAbsent => {
            format!("package(s) absent/purged: {}", spec.packages.join(", "))
        }
    }
}

/// Parses RFC-822 stanzas in `/var/lib/dpkg/status` and returns every package whose status
/// represents an installed (or half-installed/unpacked) package.
fn parse_installed_dpkg_packages(content: &str) -> BTreeSet<String> {
    let mut installed = BTreeSet::new();
    let mut current_pkg: Option<String> = None;
    let mut current_installed = false;

    let flush = |pkg: &mut Option<String>, is_inst: &mut bool, set: &mut BTreeSet<String>| {
        if let Some(name) = pkg.take() {
            if *is_inst {
                set.insert(name);
            }
        }
        *is_inst = false;
    };

    for raw_line in content.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() {
            flush(&mut current_pkg, &mut current_installed, &mut installed);
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        if let Some(val) = line.strip_prefix("Package:") {
            current_pkg = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Status:") {
            let tokens: Vec<&str> = val.split_whitespace().collect();
            // Standard installed stanza: `Status: install ok installed`
            // Also flag unpacked/half-installed states; ignore `deinstall ok config-files` / `not-installed`.
            current_installed = tokens
                .last()
                .is_some_and(|state| matches!(*state, "installed" | "unpacked" | "half-installed"));
        }
    }
    flush(&mut current_pkg, &mut current_installed, &mut installed);

    installed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use tempfile::tempdir;

    const SAMPLE_STATUS: &str = "\
Package: apparmor
Status: install ok installed
Version: 4.0.1

Package: telnet
Status: deinstall ok config-files
Version: 0.17

Package: nis
Status: install ok installed
Version: 4.5
";

    fn make_spec(mode: PackageStateMode, pkgs: &[&str]) -> PackageStateCheck {
        PackageStateCheck {
            mode,
            packages: pkgs.iter().map(|s| (*s).to_string()).collect(),
            dpkg_status_path: "/var/lib/dpkg/status".to_string(),
        }
    }

    #[test]
    fn evaluates_installed_any_and_absent_accurately() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("var/lib/dpkg")).expect("mkdir");
        fs::write(dir.path().join("var/lib/dpkg/status"), SAMPLE_STATUS).expect("write");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");

        assert_eq!(
            evaluate(
                &make_spec(PackageStateMode::AllInstalled, &["apparmor"]),
                &view
            )
            .status,
            Status::Pass
        );
        assert_eq!(
            evaluate(
                &make_spec(
                    PackageStateMode::AllInstalled,
                    &["apparmor", "apparmor-utils"]
                ),
                &view
            )
            .status,
            Status::Fail
        );
        // `telnet` is `deinstall ok config-files` -> treated as absent!
        assert_eq!(
            evaluate(&make_spec(PackageStateMode::AllAbsent, &["telnet"]), &view).status,
            Status::Pass
        );
        // `nis` is installed -> fails AllAbsent
        assert_eq!(
            evaluate(&make_spec(PackageStateMode::AllAbsent, &["nis"]), &view).status,
            Status::Fail
        );
        assert_eq!(
            evaluate(
                &make_spec(PackageStateMode::AnyInstalled, &["ufw", "apparmor"]),
                &view
            )
            .status,
            Status::Pass
        );
    }

    #[test]
    fn warns_instead_of_false_pass_when_dpkg_status_missing() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&make_spec(PackageStateMode::AllAbsent, &["telnet"]), &view);
        assert_eq!(out.status, Status::Warn);
        assert_eq!(out.details.len(), 1);
    }
}
