//! `file_meta` check primitive validating file permissions (`max_mode`) and `uid`/`gid`
//! ownership through [`SystemView::metadata`].

use crate::checks::CheckOutcome;
use crate::model::Status;
use crate::rules::schema::{FileMetaCheck, FileMetaMissingPolicy};
use crate::sys::SystemView;

/// Evaluates permission bits and ownership on a critical file or directory.
pub fn evaluate(spec: &FileMetaCheck, view: &dyn SystemView) -> CheckOutcome {
    let Ok(max_mode) = parse_octal_mode(&spec.max_mode) else {
        return CheckOutcome::error(format!(
            "invalid octal max_mode '{}' for '{}'",
            spec.max_mode, spec.path
        ));
    };

    let expected = format!(
        "{}: mode <= {max_mode:04o}, uid={}, gid in [{}]",
        spec.path,
        spec.expected_uid,
        spec.allowed_gids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let meta = match view.metadata(&spec.path) {
        Ok(m) => m,
        Err(err) if err.is_not_found() => {
            let status = match spec.on_missing {
                FileMetaMissingPolicy::Warn => Status::Warn,
                FileMetaMissingPolicy::Fail => Status::Fail,
                FileMetaMissingPolicy::Skip => Status::Skip,
            };
            return CheckOutcome {
                status,
                expected: Some(expected),
                actual: Some(format!("{} not found", spec.path)),
                details: vec![format!("{}: {err}", spec.path)],
            };
        }
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{} metadata unreadable", spec.path),
                vec![format!("{}: {err}", spec.path)],
            );
        }
    };

    let actual_perm = meta.perm_bits();
    let mut violations = Vec::new();

    if (actual_perm & !max_mode) != 0 {
        violations.push(format!(
            "{}: mode {actual_perm:04o} exceeds maximum allowed {max_mode:04o}",
            spec.path
        ));
    }
    if meta.uid != spec.expected_uid {
        violations.push(format!(
            "{}: owner uid is {} (expected {})",
            spec.path, meta.uid, spec.expected_uid
        ));
    }
    if !spec.allowed_gids.is_empty() && !spec.allowed_gids.contains(&meta.gid) {
        violations.push(format!(
            "{}: group gid is {} (expected one of [{}])",
            spec.path,
            meta.gid,
            spec.allowed_gids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let actual = format!(
        "{}: mode={actual_perm:04o}, uid={}, gid={}",
        spec.path, meta.uid, meta.gid
    );

    if !violations.is_empty() {
        return CheckOutcome::fail(expected, actual, violations);
    }

    CheckOutcome::pass(expected, actual)
}

fn parse_octal_mode(raw: &str) -> Result<u32, std::num::ParseIntError> {
    let stripped = raw.trim().trim_start_matches("0o").trim_start_matches("0O");
    u32::from_str_radix(stripped, 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{RootFsSystemView, rootfs::FIXTURE_META_FILE};
    use std::fs;
    use tempfile::tempdir;

    fn shadow_spec() -> FileMetaCheck {
        FileMetaCheck {
            path: "/etc/shadow".to_string(),
            max_mode: "0640".to_string(),
            expected_uid: 0,
            allowed_gids: vec![0, 42],
            on_missing: FileMetaMissingPolicy::Warn,
        }
    }

    #[test]
    fn passes_when_mode_is_stricter_or_equal_and_owner_matches() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("etc/shadow"), "root:*:19000:0:99999:7:::\n").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/etc/shadow\"]\nmode = \"0600\"\nuid = 0\ngid = 42\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&shadow_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn fails_when_extra_permission_bits_or_wrong_owner_set() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("etc/shadow"), "root:*:19000:0:99999:7:::\n").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/etc/shadow\"]\nmode = \"0644\"\nuid = 1000\ngid = 1000\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&shadow_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert_eq!(out.details.len(), 3);
    }

    #[test]
    fn respects_missing_policy_warn_and_skip() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");

        let out_warn = evaluate(&shadow_spec(), &view);
        assert_eq!(out_warn.status, Status::Warn);

        let mut skip_spec = shadow_spec();
        skip_spec.on_missing = FileMetaMissingPolicy::Skip;
        let out_skip = evaluate(&skip_spec, &view);
        assert_eq!(out_skip.status, Status::Skip);
    }
}
