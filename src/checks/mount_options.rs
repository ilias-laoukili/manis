//! `mount_options` check primitive parsing `/proc/mounts` through [`SystemView`].

use crate::checks::CheckOutcome;
use crate::rules::schema::MountOptionsCheck;
use crate::sys::SystemView;
use std::collections::{BTreeMap, BTreeSet};

/// Evaluates mount point separation and mount options against `/proc/mounts`.
pub fn evaluate(spec: &MountOptionsCheck, view: &dyn SystemView) -> CheckOutcome {
    let raw = match view.read_to_string("/proc/mounts") {
        Ok(content) => content,
        Err(err) => {
            return CheckOutcome::warn(
                format!("{} mount point(s) verified", spec.mounts.len()),
                "/proc/mounts unavailable",
                vec![format!("/proc/mounts: {err}")],
            );
        }
    };

    let mounts = parse_proc_mounts(&raw);
    let mut failed_expected = Vec::new();
    let mut failed_actual = Vec::new();
    let mut details = Vec::new();

    for req in &spec.mounts {
        let Some(actual_opts) = mounts.get(&req.path) else {
            if req.required_separate {
                failed_expected.push(format!("{} mounted separately", req.path));
                failed_actual.push(format!("{}: not mounted", req.path));
                details.push(format!(
                    "{}: expected a dedicated mount point, but none found in /proc/mounts",
                    req.path
                ));
            }
            continue;
        };

        let mut missing_opts = Vec::new();
        for opt in &req.required_options {
            if !actual_opts.contains(opt) {
                missing_opts.push(opt.clone());
            }
        }

        let mut missing_groups = Vec::new();
        for group in &req.any_of_options {
            if !group.is_empty() && !group.iter().any(|opt| actual_opts.contains(opt)) {
                missing_groups.push(group.join("|"));
            }
        }

        if !missing_opts.is_empty() || !missing_groups.is_empty() {
            let mut req_desc = missing_opts.clone();
            req_desc.extend(missing_groups.iter().map(|g| format!("one of ({g})")));
            let current_list: Vec<&str> = actual_opts.iter().map(String::as_str).collect();
            failed_expected.push(format!("{}: {}", req.path, req_desc.join(", ")));
            failed_actual.push(format!("{}: [{}]", req.path, current_list.join(",")));
            details.push(format!(
                "{}: missing [{}]; active options: {}",
                req.path,
                req_desc.join(", "),
                current_list.join(",")
            ));
        }
    }

    if !failed_expected.is_empty() {
        return CheckOutcome::fail(
            failed_expected.join("; "),
            failed_actual.join("; "),
            details,
        );
    }

    CheckOutcome::pass(
        format!("{} mount point rule(s) satisfied", spec.mounts.len()),
        "all required mount points and mount options are compliant",
    )
}

fn parse_proc_mounts(content: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut map = BTreeMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let _device = fields.next();
        let Some(raw_mountpoint) = fields.next() else {
            continue;
        };
        let _fstype = fields.next();
        let Some(raw_options) = fields.next() else {
            continue;
        };
        let mountpoint = unescape_mount_path(raw_mountpoint);
        let opts: BTreeSet<String> = raw_options
            .split(',')
            .filter(|o| !o.is_empty())
            .map(ToString::to_string)
            .collect();
        // Last mount entry wins (matches kernel mount stacking semantics).
        map.insert(mountpoint, opts);
    }
    map
}

fn unescape_mount_path(raw: &str) -> String {
    raw.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::rules::schema::MountSpec;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use tempfile::tempdir;

    fn sample_spec() -> MountOptionsCheck {
        MountOptionsCheck {
            mounts: vec![
                MountSpec {
                    path: "/tmp".to_string(),
                    required_separate: true,
                    required_options: vec![
                        "nodev".to_string(),
                        "nosuid".to_string(),
                        "noexec".to_string(),
                    ],
                    any_of_options: Vec::new(),
                },
                MountSpec {
                    path: "/proc".to_string(),
                    required_separate: false,
                    required_options: Vec::new(),
                    any_of_options: vec![vec![
                        "hidepid=1".to_string(),
                        "hidepid=2".to_string(),
                        "hidepid=invisible".to_string(),
                    ]],
                },
                MountSpec {
                    path: "/boot".to_string(),
                    required_separate: false,
                    required_options: vec!["nodev".to_string()],
                    any_of_options: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn passes_when_mounts_compliant_and_optional_unmounted() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("proc")).expect("mkdir");
        fs::write(
            dir.path().join("proc/mounts"),
            "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\nproc /proc proc rw,hidepid=invisible 0 0\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn fails_when_required_partition_missing_or_option_absent() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("proc")).expect("mkdir");
        fs::write(
            dir.path().join("proc/mounts"),
            "proc /proc proc rw,relatime 0 0\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.actual.as_deref().unwrap().contains("/tmp: not mounted"));
        assert!(out.expected.as_deref().unwrap().contains("hidepid=2"));
    }

    #[test]
    fn warns_when_proc_mounts_missing() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Warn);
    }
}
