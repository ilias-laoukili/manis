//! `sudoers` check primitive inspecting `/etc/sudoers` and `/etc/sudoers.d/*`.

use crate::checks::CheckOutcome;
use crate::rules::schema::{SudoersCheck, SudoersMode};
use crate::sys::SystemView;

/// Evaluates sudoers security rules while ensuring unreadable files yield `WARN`, never `PASS`.
pub fn evaluate(spec: &SudoersCheck, view: &dyn SystemView) -> CheckOutcome {
    let mut files_to_check = Vec::new();
    let mut unreadable = Vec::new();
    let mut readable_count = 0usize;

    match view.read_to_string(&spec.file) {
        Ok(content) => {
            readable_count += 1;
            files_to_check.push((spec.file.clone(), content));
        }
        Err(err) if err.is_permission_denied() => {
            unreadable.push(format!("{}: {err}", spec.file));
        }
        Err(err) if err.is_not_found() => {}
        Err(err) => {
            unreadable.push(format!("{}: {err}", spec.file));
        }
    }

    match view.read_dir(&spec.include_dir) {
        Ok(entries) => {
            for entry in entries {
                if !entry.is_file {
                    continue;
                }
                // Match sudo's own rule: files containing '.' or ending with '~' are ignored.
                if entry.name.contains('.') || entry.name.ends_with('~') {
                    continue;
                }
                match view.read_to_string(&entry.path) {
                    Ok(content) => {
                        readable_count += 1;
                        files_to_check.push((entry.path, content));
                    }
                    Err(err) => unreadable.push(format!("{}: {err}", entry.path)),
                }
            }
        }
        Err(err) if err.is_permission_denied() => {
            unreadable.push(format!("{}: {err}", spec.include_dir));
        }
        Err(err) if err.is_not_found() => {}
        Err(err) => {
            unreadable.push(format!("{}: {err}", spec.include_dir));
        }
    }

    let expected = match spec.mode {
        SudoersMode::ForbidBroadRootTargets => {
            "no broad root/ALL sudoers grants for non-exempt principals".to_string()
        }
        SudoersMode::ForbidCommandNegations => {
            "no '!' command negations in sudoers rules".to_string()
        }
    };

    if readable_count == 0 {
        return CheckOutcome::warn(
            expected,
            "sudoers files unavailable or unreadable",
            if unreadable.is_empty() {
                vec![format!("{} not found", spec.file)]
            } else {
                unreadable
            },
        );
    }

    let mut violations = Vec::new();
    for (path, content) in &files_to_check {
        for (line_no, logical_line) in logical_sudoers_lines(content) {
            match spec.mode {
                SudoersMode::ForbidBroadRootTargets => {
                    if is_broad_root_target_rule(&logical_line, &spec.ignore_users) {
                        violations.push(format!("{path}:{line_no}: {logical_line}"));
                    }
                }
                SudoersMode::ForbidCommandNegations => {
                    if has_command_negation(&logical_line) {
                        violations.push(format!("{path}:{line_no}: {logical_line}"));
                    }
                }
            }
        }
    }

    if !violations.is_empty() {
        let actual = format!("{} offending sudoers rule(s)", violations.len());
        let mut details = violations;
        details.extend(unreadable);
        return CheckOutcome::fail(expected, actual, details);
    }

    if !unreadable.is_empty() {
        return CheckOutcome::warn(
            expected,
            format!(
                "no violations in readable files, but {} path(s) unreadable",
                unreadable.len()
            ),
            unreadable,
        );
    }

    CheckOutcome::pass(
        expected,
        format!("{readable_count} sudoers file(s) inspected and compliant"),
    )
}

/// Joins backslash-continued lines, stripping comments and blank lines while preserving the
/// 1-based starting line number of each logical rule.
fn logical_sudoers_lines(content: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start_line = 0usize;

    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();

        if current.is_empty() {
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with("@include")
                || trimmed.starts_with("@includedir")
            {
                continue;
            }
            start_line = line_no;
        }

        if let Some(without_bs) = trimmed.strip_suffix('\\') {
            current.push_str(without_bs.trim_end());
            current.push(' ');
        } else {
            current.push_str(trimmed);
            let cleaned = strip_inline_comment(&current).trim().to_string();
            if !cleaned.is_empty() {
                out.push((start_line, cleaned));
            }
            current.clear();
        }
    }

    if !current.trim().is_empty() {
        let cleaned = strip_inline_comment(&current).trim().to_string();
        if !cleaned.is_empty() {
            out.push((start_line, cleaned));
        }
    }

    out
}

fn strip_inline_comment(line: &str) -> &str {
    // `#` introduces a comment in sudoers unless preceded by `\`.
    let bytes = line.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'#' && (idx == 0 || bytes[idx - 1] != b'\\') {
            return &line[..idx];
        }
    }
    line
}

fn is_defaults_line(line: &str) -> bool {
    line.starts_with("Defaults")
        && match line[8..].chars().next() {
            None => true,
            Some(c) => c.is_whitespace() || matches!(c, '@' | ':' | '>' | '!'),
        }
}

fn is_alias_line(line: &str) -> bool {
    ["User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"]
        .iter()
        .any(|kw| {
            line.starts_with(kw)
                && line[kw.len()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_whitespace)
        })
}

fn is_broad_root_target_rule(line: &str, ignore_users: &[String]) -> bool {
    if is_defaults_line(line) || is_alias_line(line) {
        return false;
    }
    let Some((lhs, rhs)) = line.split_once('=') else {
        return false;
    };
    let Some(principal) = lhs.split_whitespace().next() else {
        return false;
    };
    if ignore_users.iter().any(|u| u == principal) {
        return false;
    }

    let rhs = rhs.trim();
    // Parse optional `(runas)` spec. If omitted in sudoers, default target is `root`!
    let (target_is_broad_root, after_runas) = if let Some(after_open) = rhs.strip_prefix('(') {
        let Some((runas, rest)) = after_open.split_once(')') else {
            return false;
        };
        (runas_targets_root_or_all(runas), rest.trim())
    } else {
        (true, rhs)
    };

    if !target_is_broad_root {
        return false;
    }

    // Split command list by `,` and check whether any entry grants `ALL`.
    for entry in after_runas.split(',') {
        let cmd = strip_sudo_tags(entry.trim());
        if cmd == "ALL" {
            return true;
        }
    }
    false
}

fn runas_targets_root_or_all(runas: &str) -> bool {
    // Runas may be `ALL`, `ALL:ALL`, `root`, `root:root`, `user1, root`, etc.
    let user_part = runas.split(':').next().unwrap_or("").trim();
    user_part
        .split(',')
        .map(str::trim)
        .any(|u| u == "ALL" || u == "root")
}

fn strip_sudo_tags(mut spec: &str) -> &str {
    const TAGS: &[&str] = &[
        "NOPASSWD:",
        "PASSWD:",
        "NOEXEC:",
        "EXEC:",
        "SETENV:",
        "NOSETENV:",
        "LOG_INPUT:",
        "NOLOG_INPUT:",
        "LOG_OUTPUT:",
        "NOLOG_OUTPUT:",
        "FOLLOW:",
        "NOFOLLOW:",
        "MAIL:",
        "NOMAIL:",
    ];

    loop {
        let trimmed = spec.trim_start();
        let mut matched = false;
        for tag in TAGS {
            if let Some(rest) = trimmed.strip_prefix(tag) {
                spec = rest;
                matched = true;
                break;
            }
        }
        if !matched {
            return trimmed;
        }
    }
}

fn has_command_negation(line: &str) -> bool {
    if is_defaults_line(line) {
        return false;
    }
    // Check both user specs and `Cmnd_Alias` lines (skip User/Runas/Host aliases).
    if ["User_Alias", "Runas_Alias", "Host_Alias"]
        .iter()
        .any(|kw| line.starts_with(kw))
    {
        return false;
    }
    let Some((_, rhs)) = line.split_once('=') else {
        return false;
    };

    let after_runas = if let Some(after_open) = rhs.trim_start().strip_prefix('(') {
        after_open.split_once(')').map_or(rhs, |(_, rest)| rest)
    } else {
        rhs
    };

    for entry in after_runas.split(',') {
        let cmd = strip_sudo_tags(entry.trim());
        if let Some(negated) = cmd.strip_prefix('!') {
            let target = negated.trim_start();
            if target.starts_with('/')
                || target
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::{rootfs::FIXTURE_META_FILE, RootFsSystemView};
    use std::fs;
    use tempfile::tempdir;

    fn target_spec() -> SudoersCheck {
        SudoersCheck {
            mode: SudoersMode::ForbidBroadRootTargets,
            file: "/etc/sudoers".to_string(),
            include_dir: "/etc/sudoers.d".to_string(),
            ignore_users: vec!["root".to_string()],
        }
    }

    fn negation_spec() -> SudoersCheck {
        SudoersCheck {
            mode: SudoersMode::ForbidCommandNegations,
            file: "/etc/sudoers".to_string(),
            include_dir: "/etc/sudoers.d".to_string(),
            ignore_users: Vec::new(),
        }
    }

    #[test]
    fn broad_root_targets_passes_when_only_root_and_scoped_rules_exist() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/sudoers.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/sudoers"),
            "# comment\nDefaults env_reset\nroot ALL=(ALL:ALL) ALL\n",
        )
        .expect("write");
        fs::write(
            dir.path().join("etc/sudoers.d/app"),
            "deploy ALL=(www-data) /usr/bin/systemctl reload nginx\n",
        )
        .expect("write");
        // Ignored due to '.' in filename
        fs::write(
            dir.path().join("etc/sudoers.d/README.txt"),
            "%sudo ALL=(ALL:ALL) ALL\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&target_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn broad_root_targets_fails_on_sudo_group_all() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(
            dir.path().join("etc/sudoers"),
            "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&target_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.details[0].contains("/etc/sudoers:2"));
    }

    #[test]
    fn negation_detects_bang_in_user_spec_and_cmnd_alias() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/sudoers.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/sudoers"),
            "Defaults !requiretty\nroot ALL=(ALL:ALL) ALL\n",
        )
        .expect("write");
        fs::write(
            dir.path().join("etc/sudoers.d/ops"),
            "ops ALL=(root) ALL, !/bin/su\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&negation_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.details[0].contains("/etc/sudoers.d/ops:1"));
    }

    #[test]
    fn unreadable_sudoers_warns_instead_of_passing() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("etc/sudoers"), "root ALL=(ALL) ALL\n").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/etc/sudoers\"]\nunreadable = true\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&target_spec(), &view);
        assert_eq!(out.status, Status::Warn);
    }
}
