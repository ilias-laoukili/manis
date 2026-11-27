//! `world_writable` check primitive detecting world-writable regular files (`o+w`) and
//! world-writable directories missing the sticky bit (`+t`) through [`SystemView::walk_files`].

use crate::checks::CheckOutcome;
use crate::rules::schema::WorldWritableCheck;
use crate::sys::SystemView;

/// Scans the filesystem for insecure world-writable files and non-sticky directories.
///
/// Unreadable paths yield `WARN` when no violations are found (never silent `PASS`).
pub fn evaluate(spec: &WorldWritableCheck, view: &dyn SystemView) -> CheckOutcome {
    let roots: Vec<&str> = spec.search_roots.iter().map(String::as_str).collect();
    let skips: Vec<&str> = spec.skip_dirs.iter().map(String::as_str).collect();
    let expected = "zero world-writable regular files and sticky bit (+t) set on all world-writable directories";

    let walk = match view.walk_files(&roots, &skips) {
        Ok(report) => report,
        Err(err) => {
            return CheckOutcome::warn(expected, "filesystem walk failed", vec![err.to_string()]);
        }
    };

    if walk.files.is_empty() && walk.dirs.is_empty() && walk.unreadable_paths.is_empty() {
        return CheckOutcome::warn(
            expected,
            "no files or directories found under search roots",
            vec!["filesystem tree is empty; cannot confirm compliance".to_string()],
        );
    }

    let mut ww_files = Vec::new();
    if spec.check_files {
        for file in &walk.files {
            if file.meta.is_world_writable() {
                ww_files.push(format!(
                    "{} (file, mode {:04o}, world-writable)",
                    file.path,
                    file.meta.perm_bits()
                ));
            }
        }
    }

    let mut ww_dirs_no_sticky = Vec::new();
    if spec.check_dirs_without_sticky {
        for dir in &walk.dirs {
            if dir.meta.is_world_writable() && !dir.meta.has_sticky_bit() {
                ww_dirs_no_sticky.push(format!(
                    "{} (dir, mode {:04o}, world-writable without sticky bit)",
                    dir.path,
                    dir.meta.perm_bits()
                ));
            }
        }
    }

    if !ww_files.is_empty() || !ww_dirs_no_sticky.is_empty() {
        let mut summary_parts = Vec::new();
        if !ww_files.is_empty() {
            summary_parts.push(format!("{} world-writable file(s)", ww_files.len()));
        }
        if !ww_dirs_no_sticky.is_empty() {
            summary_parts.push(format!(
                "{} world-writable dir(s) without sticky bit",
                ww_dirs_no_sticky.len()
            ));
        }
        let mut details = Vec::new();
        details.extend(ww_files);
        details.extend(ww_dirs_no_sticky);
        for unreadable in &walk.unreadable_paths {
            details.push(format!("unreadable path skipped: {unreadable}"));
        }
        return CheckOutcome::fail(expected, summary_parts.join(", "), details);
    }

    if !walk.unreadable_paths.is_empty() {
        return CheckOutcome::warn(
            expected,
            format!(
                "no world-writable violations found, but {} path(s) unreadable",
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
            "scanned {} file(s) and {} dir(s): no insecure world-writable entries",
            walk.files.len(),
            walk.dirs.len()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::{RootFsSystemView, rootfs::FIXTURE_META_FILE};
    use std::fs;
    use tempfile::tempdir;

    fn sample_spec() -> WorldWritableCheck {
        WorldWritableCheck {
            search_roots: vec!["/".to_string()],
            skip_dirs: vec![
                "/proc".to_string(),
                "/sys".to_string(),
                "/dev".to_string(),
                "/run".to_string(),
            ],
            check_files: true,
            check_dirs_without_sticky: true,
        }
    }

    #[test]
    fn passes_when_world_writable_dir_has_sticky_bit_and_files_are_safe() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("tmp")).expect("mkdir");
        fs::write(dir.path().join("tmp/readme.txt"), "ok\n").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/tmp\"]\nmode = \"1777\"\n\n[files.\"/tmp/readme.txt\"]\nmode = \"0644\"\n",
        )
        .expect("overlay");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn fails_on_world_writable_file_and_non_sticky_dir() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("var/cache/open")).expect("mkdir");
        fs::write(dir.path().join("var/cache/open/data.txt"), "bad\n").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/var/cache/open\"]\nmode = \"0777\"\n\n[files.\"/var/cache/open/data.txt\"]\nmode = \"0666\"\n",
        )
        .expect("overlay");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert_eq!(out.details.len(), 2);
    }

    #[test]
    fn warns_on_empty_tree_or_unreadable_directory() {
        let empty = tempdir().expect("tempdir");
        let empty_view = RootFsSystemView::from_root(empty.path()).expect("view");
        assert_eq!(evaluate(&sample_spec(), &empty_view).status, Status::Warn);

        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("root")).expect("mkdir");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/root\"]\nunreadable = true\n",
        )
        .expect("overlay");
        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        assert_eq!(evaluate(&sample_spec(), &view).status, Status::Warn);
    }
}
