//! `service_state` check primitive inspecting systemd unit symlinks and `*.wants/` directories
//! directly through [`SystemView`] (no `systemctl` subprocesses).

use crate::checks::CheckOutcome;
use crate::rules::schema::{ServiceStateCheck, ServiceStateMode};
use crate::sys::SystemView;
use std::collections::BTreeSet;

/// Evaluates systemd unit enablement / masking purely from filesystem state.
pub fn evaluate(spec: &ServiceStateCheck, view: &dyn SystemView) -> CheckOutcome {
    let expected = describe_expected(spec);

    let entries = match view.read_dir(&spec.systemd_dir) {
        Ok(list) => list,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{} unavailable", spec.systemd_dir),
                vec![format!("{}: {err}", spec.systemd_dir)],
            );
        }
    };

    let mut unreadable = Vec::new();
    let mut wants_units = BTreeSet::new();

    for entry in &entries {
        let is_systemd_dep_dir = std::path::Path::new(&entry.name)
            .extension()
            .is_some_and(|ext| {
                ext.eq_ignore_ascii_case("wants") || ext.eq_ignore_ascii_case("requires")
            });
        if entry.is_dir && is_systemd_dep_dir {
            match view.read_dir(&entry.path) {
                Ok(sub) => {
                    for item in sub {
                        wants_units.insert(item.name);
                    }
                }
                Err(err) => unreadable.push(format!("{}: {err}", entry.path)),
            }
        }
    }

    let mut enabled_units = Vec::new();
    let mut masked_units = Vec::new();

    for unit in &spec.units {
        let direct_path = format!("{}/{}", spec.systemd_dir.trim_end_matches('/'), unit);
        let is_masked = view
            .read_link(&direct_path)
            .is_ok_and(|target| target == "/dev/null");
        if is_masked {
            masked_units.push(unit.clone());
        } else if wants_units.contains(unit) {
            enabled_units.push(unit.clone());
        }
    }

    match spec.mode {
        ServiceStateMode::AnyEnabled => {
            if !enabled_units.is_empty() {
                CheckOutcome::pass(expected, format!("enabled: {}", enabled_units.join(", ")))
            } else if !unreadable.is_empty() {
                CheckOutcome::warn(
                    expected,
                    "systemd directories partially unreadable",
                    unreadable,
                )
            } else {
                let mut details = vec![format!(
                    "none of [{}] enabled in {}/*.wants",
                    spec.units.join(", "),
                    spec.systemd_dir
                )];
                if !masked_units.is_empty() {
                    details.push(format!("masked: {}", masked_units.join(", ")));
                }
                CheckOutcome::fail(expected, "no required service enabled", details)
            }
        }
        ServiceStateMode::ExactlyOneEnabled => {
            if enabled_units.len() == 1 {
                if !unreadable.is_empty() {
                    return CheckOutcome::warn(
                        expected,
                        format!(
                            "enabled: {}, but {} systemd dir(s) unreadable",
                            enabled_units[0],
                            unreadable.len()
                        ),
                        unreadable,
                    );
                }
                CheckOutcome::pass(expected, format!("enabled: {}", enabled_units[0]))
            } else if enabled_units.is_empty() {
                if !unreadable.is_empty() {
                    return CheckOutcome::warn(
                        expected,
                        "systemd directories partially unreadable",
                        unreadable,
                    );
                }
                CheckOutcome::fail(
                    expected,
                    "0 matching services enabled",
                    vec![format!(
                        "expected exactly 1 of [{}] enabled, found 0",
                        spec.units.join(", ")
                    )],
                )
            } else {
                CheckOutcome::fail(
                    expected,
                    format!(
                        "{} conflicting services enabled: {}",
                        enabled_units.len(),
                        enabled_units.join(", ")
                    ),
                    vec![format!(
                        "multiple services enabled simultaneously: {}",
                        enabled_units.join(", ")
                    )],
                )
            }
        }
        ServiceStateMode::AllDisabledOrMasked => {
            if !enabled_units.is_empty() {
                let details = enabled_units
                    .iter()
                    .map(|u| format!("service '{u}' is enabled in {}/*.wants", spec.systemd_dir))
                    .collect();
                CheckOutcome::fail(
                    expected,
                    format!("enabled: {}", enabled_units.join(", ")),
                    details,
                )
            } else if !unreadable.is_empty() {
                CheckOutcome::warn(
                    expected,
                    format!(
                        "none enabled in readable dirs, but {} dir(s) unreadable",
                        unreadable.len()
                    ),
                    unreadable,
                )
            } else {
                let actual = if masked_units.is_empty() {
                    "all listed units disabled/absent".to_string()
                } else {
                    format!("disabled/masked ({})", masked_units.join(", "))
                };
                CheckOutcome::pass(expected, actual)
            }
        }
    }
}

fn describe_expected(spec: &ServiceStateCheck) -> String {
    match spec.mode {
        ServiceStateMode::AnyEnabled => {
            format!("service enabled: {}", spec.units.join(" | "))
        }
        ServiceStateMode::ExactlyOneEnabled => {
            format!("exactly one service enabled: {}", spec.units.join(" XOR "))
        }
        ServiceStateMode::AllDisabledOrMasked => {
            format!("service(s) disabled or masked: {}", spec.units.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::{rootfs::FIXTURE_META_FILE, RootFsSystemView};
    use std::fs;
    use tempfile::tempdir;

    fn make_spec(mode: ServiceStateMode, units: &[&str]) -> ServiceStateCheck {
        ServiceStateCheck {
            mode,
            units: units.iter().map(|s| (*s).to_string()).collect(),
            systemd_dir: "/etc/systemd/system".to_string(),
        }
    }

    #[test]
    fn detects_enabled_masked_and_conflicting_services() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(
            dir.path()
                .join("etc/systemd/system/multi-user.target.wants"),
        )
        .expect("mkdir");
        fs::write(
            dir.path()
                .join("etc/systemd/system/multi-user.target.wants/chrony.service"),
            "",
        )
        .expect("write");
        fs::write(
            dir.path()
                .join("etc/systemd/system/multi-user.target.wants/cups.service"),
            "",
        )
        .expect("write");
        fs::write(dir.path().join("etc/systemd/system/cups.service"), "").expect("write");
        // Mask cups.service via overlay -> overrides wants entry!
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/etc/systemd/system/cups.service\"]\nsymlink_target = \"/dev/null\"\n",
        )
        .expect("write overlay");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        assert_eq!(
            evaluate(
                &make_spec(
                    ServiceStateMode::ExactlyOneEnabled,
                    &["chrony.service", "systemd-timesyncd.service"]
                ),
                &view
            )
            .status,
            Status::Pass
        );
        assert_eq!(
            evaluate(
                &make_spec(ServiceStateMode::AllDisabledOrMasked, &["cups.service"]),
                &view
            )
            .status,
            Status::Pass
        );
        assert_eq!(
            evaluate(
                &make_spec(ServiceStateMode::AllDisabledOrMasked, &["chrony.service"]),
                &view
            )
            .status,
            Status::Fail
        );
    }

    #[test]
    fn fails_when_both_ntp_daemons_enabled_and_warns_when_systemd_missing() {
        let dir = tempdir().expect("tempdir");
        let empty_view = RootFsSystemView::from_root(dir.path()).expect("view");
        assert_eq!(
            evaluate(
                &make_spec(
                    ServiceStateMode::AllDisabledOrMasked,
                    &["avahi-daemon.service"]
                ),
                &empty_view
            )
            .status,
            Status::Warn
        );

        fs::create_dir_all(
            dir.path()
                .join("etc/systemd/system/multi-user.target.wants"),
        )
        .expect("mkdir");
        fs::write(
            dir.path()
                .join("etc/systemd/system/multi-user.target.wants/chrony.service"),
            "",
        )
        .expect("write");
        fs::write(
            dir.path()
                .join("etc/systemd/system/multi-user.target.wants/systemd-timesyncd.service"),
            "",
        )
        .expect("write");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        assert_eq!(
            evaluate(
                &make_spec(
                    ServiceStateMode::ExactlyOneEnabled,
                    &["chrony.service", "systemd-timesyncd.service"]
                ),
                &view
            )
            .status,
            Status::Fail
        );
    }
}
