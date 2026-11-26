//! `suid_sgid` check primitive enforcing an explicit SUID/SGID whitelist and forbidding
//! world-writable SUID/SGID binaries.

use crate::checks::CheckOutcome;
use crate::rules::schema::SuidSgidCheck;
use crate::sys::SystemView;
use std::collections::BTreeSet;

/// Evaluates SUID/SGID binaries across the filesystem via [`SystemView::walk_files`].
pub fn evaluate(spec: &SuidSgidCheck, view: &dyn SystemView) -> CheckOutcome {
    let roots: Vec<&str> = spec.search_roots.iter().map(String::as_str).collect();
    let skips: Vec<&str> = spec.skip_dirs.iter().map(String::as_str).collect();
    let whitelist: BTreeSet<&str> = spec.whitelist.iter().map(String::as_str).collect();

    let walk = match view.walk_files(&roots, &skips) {
        Ok(report) => report,
        Err(err) => {
            return CheckOutcome::warn(
                "only whitelisted SUID/SGID binaries and no world-writable SUID/SGID files",
                "filesystem walk failed",
                vec![err.to_string()],
            );
        }
    };

    let mut world_writable = Vec::new();
    let mut unlisted = Vec::new();
    let mut whitelisted_count = 0usize;

    for file in &walk.files {
        if !(file.meta.is_suid() || file.meta.is_sgid()) {
            continue;
        }
        let bits = file.meta.perm_bits();
        let kind = match (file.meta.is_suid(), file.meta.is_sgid()) {
            (true, true) => "SUID+SGID",
            (true, false) => "SUID",
            (false, true) => "SGID",
            (false, false) => unreachable!(),
        };

        if spec.forbid_world_writable && file.meta.is_world_writable() {
            world_writable.push(format!(
                "{} ({kind}, mode {bits:04o}, world-writable)",
                file.path
            ));
        }

        if whitelist.contains(file.path.as_str()) {
            whitelisted_count += 1;
        } else {
            unlisted.push(format!(
                "{} ({kind}, mode {bits:04o}, not whitelisted)",
                file.path
            ));
        }
    }

    let expected = if spec.forbid_world_writable {
        "only whitelisted SUID/SGID binaries and zero world-writable SUID/SGID files"
    } else {
        "only whitelisted SUID/SGID binaries"
    };

    if !world_writable.is_empty() || !unlisted.is_empty() {
        let mut summary_parts = Vec::new();
        if !world_writable.is_empty() {
            summary_parts.push(format!(
                "{} world-writable SUID/SGID file(s)",
                world_writable.len()
            ));
        }
        if !unlisted.is_empty() {
            summary_parts.push(format!(
                "{} non-whitelisted SUID/SGID file(s)",
                unlisted.len()
            ));
        }
        let mut details = Vec::new();
        details.extend(world_writable);
        details.extend(unlisted);
        for unreadable in &walk.unreadable_paths {
            details.push(format!("unreadable path skipped: {unreadable}"));
        }
        return CheckOutcome::fail(expected, summary_parts.join(", "), details);
    }

    if !walk.unreadable_paths.is_empty() {
        return CheckOutcome::warn(
            expected,
            format!(
                "{whitelisted_count} whitelisted SUID/SGID file(s), but {} path(s) unreadable",
                walk.unreadable_paths.len()
            ),
            walk.unreadable_paths
                .into_iter()
                .map(|p| format!("unreadable path: {p}"))
                .collect(),
        );
    }

    CheckOutcome::pass(
        expected,
        format!(
            "{whitelisted_count} SUID/SGID binary(ies), all whitelisted and non-world-writable"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::{rootfs::FIXTURE_META_FILE, RootFsSystemView};
    use std::fs;
    use tempfile::tempdir;

    fn sample_spec() -> SuidSgidCheck {
        SuidSgidCheck {
            search_roots: vec!["/".to_string()],
            skip_dirs: vec!["/proc".to_string(), "/sys".to_string()],
            whitelist: vec!["/usr/bin/passwd".to_string(), "/usr/bin/sudo".to_string()],
            forbid_world_writable: true,
        }
    }

    #[test]
    fn passes_when_only_whitelisted_suid_binaries_exist() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("usr/bin")).expect("mkdir");
        fs::write(dir.path().join("usr/bin/passwd"), b"bin").expect("write");
        fs::write(dir.path().join("usr/bin/ls"), b"bin").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/usr/bin/passwd\"]\nmode = \"4755\"\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn fails_when_non_whitelisted_suid_binary_found() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("usr/local/bin")).expect("mkdir");
        fs::write(dir.path().join("usr/local/bin/rogue"), b"bin").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/usr/local/bin/rogue\"]\nmode = \"4755\"\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.details[0].contains("/usr/local/bin/rogue"));
        assert!(out.details[0].contains("not whitelisted"));
    }

    #[test]
    fn fails_when_whitelisted_suid_binary_is_world_writable() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("usr/bin")).expect("mkdir");
        fs::write(dir.path().join("usr/bin/passwd"), b"bin").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/usr/bin/passwd\"]\nmode = \"4777\"\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.actual.as_deref().unwrap().contains("world-writable"));
    }

    #[test]
    fn warns_when_directory_is_unreadable_and_no_fail_found() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("root")).expect("mkdir");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/root\"]\nunreadable = true\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Warn);
    }
}
