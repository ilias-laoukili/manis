//! `sudoers` check primitive inspecting `/etc/sudoers` and `/etc/sudoers.d/*`.

use crate::checks::CheckOutcome;
use crate::rules::schema::{SudoersCheck, SudoersMode};
use crate::sys::SystemView;
use std::collections::{BTreeMap, BTreeSet};

/// Evaluates sudoers security rules while ensuring unreadable files yield `WARN`, never `PASS`.
pub fn evaluate(spec: &SudoersCheck, view: &dyn SystemView) -> CheckOutcome {
    let (files_to_check, unreadable) = collect_sudoers_files(spec, view);
    let expected = describe_expected(spec);

    if files_to_check.is_empty() {
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

    if spec.mode == SudoersMode::RequireDefaults {
        return eval_require_defaults(spec, &files_to_check, unreadable, expected);
    }

    let mut violations = Vec::new();
    for (path, content) in &files_to_check {
        for (line_no, logical_line) in logical_sudoers_lines(content) {
            let violated = match spec.mode {
                SudoersMode::ForbidBroadRootTargets => {
                    is_broad_root_target_rule(&logical_line, &spec.ignore_users)
                }
                SudoersMode::ForbidCommandNegations => has_command_negation(&logical_line),
                SudoersMode::ForbidNoPasswd => has_nopasswd_tag(&logical_line),
                SudoersMode::ForbidNoAuthenticate => has_no_authenticate(&logical_line),
                SudoersMode::RequireDefaults => unreachable!(),
            };
            if violated {
                violations.push(format!("{path}:{line_no}: {logical_line}"));
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
        format!(
            "{} sudoers file(s) inspected and compliant",
            files_to_check.len()
        ),
    )
}

fn collect_sudoers_files(
    spec: &SudoersCheck,
    view: &dyn SystemView,
) -> (Vec<(String, String)>, Vec<String>) {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();

    match view.read_to_string(&spec.file) {
        Ok(content) => files.push((spec.file.clone(), content)),
        Err(err) if err.is_not_found() => {}
        Err(err) => unreadable.push(format!("{}: {err}", spec.file)),
    }

    match view.read_dir(&spec.include_dir) {
        Ok(entries) => {
            for entry in entries {
                // Symlinked drop-ins are read through their target; an unreachable target
                // ends up in `unreadable` (WARN), never silently skipped.
                if !(entry.is_file || entry.is_symlink)
                    || entry.name.contains('.')
                    || entry.name.ends_with('~')
                {
                    continue;
                }
                match view.read_to_string(&entry.path) {
                    Ok(content) => files.push((entry.path, content)),
                    Err(err) => unreadable.push(format!("{}: {err}", entry.path)),
                }
            }
        }
        Err(err) if err.is_not_found() => {}
        Err(err) => unreadable.push(format!("{}: {err}", spec.include_dir)),
    }

    (files, unreadable)
}

fn describe_expected(spec: &SudoersCheck) -> String {
    match spec.mode {
        SudoersMode::ForbidBroadRootTargets => {
            "no broad root/ALL sudoers grants for non-exempt principals".to_string()
        }
        SudoersMode::ForbidCommandNegations => {
            "no '!' command negations in sudoers rules".to_string()
        }
        SudoersMode::ForbidNoPasswd => "no NOPASSWD rules in sudoers".to_string(),
        SudoersMode::ForbidNoAuthenticate => {
            "no '!authenticate' directives disabling sudo re-authentication".to_string()
        }
        SudoersMode::RequireDefaults => {
            let mut reqs = Vec::new();
            for flag in &spec.required_defaults {
                reqs.push(format!("Defaults {flag}"));
            }
            for kv in &spec.required_kv_defaults {
                reqs.push(format!("Defaults {kv}=..."));
            }
            if let Some(max_to) = spec.max_timestamp_timeout {
                reqs.push(format!("Defaults timestamp_timeout <= {max_to}"));
            }
            reqs.join(", ")
        }
    }
}

fn eval_require_defaults(
    spec: &SudoersCheck,
    files: &[(String, String)],
    unreadable: Vec<String>,
    expected: String,
) -> CheckOutcome {
    let mut enabled_flags = BTreeSet::new();
    let mut disabled_flags = BTreeSet::new();
    let mut kv_values: BTreeMap<String, String> = BTreeMap::new();

    for (_, content) in files {
        for (_, line) in logical_sudoers_lines(content) {
            if !is_global_defaults_line(&line) {
                continue;
            }
            let body = line[8..].trim();
            for token in split_defaults_entries(body) {
                if let Some((k, v)) = token.split_once('=') {
                    let key = k.trim().trim_end_matches(['+', '-']).to_ascii_lowercase();
                    let val = v.trim().trim_matches('"').to_string();
                    kv_values.insert(key, val);
                } else if let Some(neg) = token.strip_prefix('!') {
                    let key = neg.trim().to_ascii_lowercase();
                    enabled_flags.remove(&key);
                    disabled_flags.insert(key);
                } else {
                    let key = token.trim().to_ascii_lowercase();
                    disabled_flags.remove(&key);
                    enabled_flags.insert(key);
                }
            }
        }
    }

    let mut violations = Vec::new();
    for flag in &spec.required_defaults {
        let lower = flag.to_ascii_lowercase();
        if !enabled_flags.contains(&lower) {
            if disabled_flags.contains(&lower) {
                violations.push(format!("Defaults !{flag} explicitly disables {flag}"));
            } else {
                violations.push(format!("Defaults {flag} is not configured"));
            }
        }
    }

    for kv in &spec.required_kv_defaults {
        let lower = kv.to_ascii_lowercase();
        match kv_values.get(&lower) {
            Some(val) if !val.is_empty() => {}
            _ => violations.push(format!("Defaults {kv}=<path> is not configured")),
        }
    }

    if let Some(max_timeout) = spec.max_timestamp_timeout {
        match kv_values.get("timestamp_timeout") {
            Some(raw) => match raw.parse::<i64>() {
                Ok(val) if (0..=max_timeout).contains(&val) => {}
                Ok(val) => violations.push(format!(
                    "Defaults timestamp_timeout={val} (expected 0..={max_timeout})"
                )),
                Err(_) => violations.push(format!(
                    "Defaults timestamp_timeout='{raw}' is not a valid integer"
                )),
            },
            None => violations.push(format!(
                "Defaults timestamp_timeout is not explicitly configured (expected 0..={max_timeout})"
            )),
        }
    }

    if !violations.is_empty() {
        let actual = violations.join("; ");
        let mut details = violations;
        details.extend(unreadable);
        return CheckOutcome::fail(expected, actual, details);
    }

    if !unreadable.is_empty() {
        return CheckOutcome::warn(
            expected,
            format!(
                "required Defaults found, but {} sudoers path(s) unreadable",
                unreadable.len()
            ),
            unreadable,
        );
    }

    CheckOutcome::pass(expected, "all required sudo Defaults directives configured")
}

fn split_defaults_entries(body: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0usize;
    for (idx, ch) in body.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let slice = body[start..idx].trim();
                if !slice.is_empty() {
                    parts.push(slice);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
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

fn is_global_defaults_line(line: &str) -> bool {
    line.starts_with("Defaults") && line[8..].chars().next().is_some_and(char::is_whitespace)
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

    for entry in after_runas.split(',') {
        let cmd = strip_sudo_tags(entry.trim());
        if cmd == "ALL" {
            return true;
        }
    }
    false
}

fn runas_targets_root_or_all(runas: &str) -> bool {
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

fn has_nopasswd_tag(line: &str) -> bool {
    if is_defaults_line(line) || is_alias_line(line) {
        return false;
    }
    let Some((_, rhs)) = line.split_once('=') else {
        return false;
    };
    rhs.contains("NOPASSWD:")
}

fn has_no_authenticate(line: &str) -> bool {
    if !is_defaults_line(line) {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("!authenticate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::{RootFsSystemView, rootfs::FIXTURE_META_FILE};
    use std::fs;
    use tempfile::tempdir;

    fn base_spec(mode: SudoersMode) -> SudoersCheck {
        SudoersCheck {
            mode,
            file: "/etc/sudoers".to_string(),
            include_dir: "/etc/sudoers.d".to_string(),
            ignore_users: vec!["root".to_string()],
            required_defaults: Vec::new(),
            required_kv_defaults: Vec::new(),
            max_timestamp_timeout: None,
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

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&base_spec(SudoersMode::ForbidBroadRootTargets), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn require_defaults_verifies_use_pty_logfile_and_timeout() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(
            dir.path().join("etc/sudoers"),
            "Defaults use_pty, logfile=\"/var/log/sudo.log\", timestamp_timeout=15\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let mut spec = base_spec(SudoersMode::RequireDefaults);
        spec.required_defaults = vec!["use_pty".to_string()];
        spec.required_kv_defaults = vec!["logfile".to_string()];
        spec.max_timestamp_timeout = Some(15);

        assert_eq!(evaluate(&spec, &view).status, Status::Pass);

        fs::write(
            dir.path().join("etc/sudoers"),
            "Defaults env_reset, timestamp_timeout=30\n",
        )
        .expect("write");
        let fail = evaluate(&spec, &view);
        assert_eq!(fail.status, Status::Fail);
        assert_eq!(fail.details.len(), 3);
    }

    #[test]
    fn detects_nopasswd_and_no_authenticate() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(
            dir.path().join("etc/sudoers"),
            "Defaults !authenticate\nops ALL=(ALL) NOPASSWD: /usr/bin/id\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        assert_eq!(
            evaluate(&base_spec(SudoersMode::ForbidNoPasswd), &view).status,
            Status::Fail
        );
        assert_eq!(
            evaluate(&base_spec(SudoersMode::ForbidNoAuthenticate), &view).status,
            Status::Fail
        );
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

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        let out = evaluate(&base_spec(SudoersMode::ForbidBroadRootTargets), &view);
        assert_eq!(out.status, Status::Warn);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_drop_in_is_inspected_and_dangling_one_warns() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/sudoers.d")).expect("mkdir");
        fs::create_dir_all(dir.path().join("opt/acme")).expect("mkdir");
        fs::write(dir.path().join("etc/sudoers"), "root ALL=(ALL) ALL\n").expect("write");
        fs::write(
            dir.path().join("opt/acme/sudoers"),
            "deploy ALL=(ALL) NOPASSWD: ALL\n",
        )
        .expect("write");
        std::os::unix::fs::symlink("/opt/acme/sudoers", dir.path().join("etc/sudoers.d/acme"))
            .expect("symlink");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&base_spec(SudoersMode::ForbidNoPasswd), &view);
        assert_eq!(out.status, Status::Fail);

        let dangling = tempdir().expect("tempdir");
        fs::create_dir_all(dangling.path().join("etc/sudoers.d")).expect("mkdir");
        fs::write(dangling.path().join("etc/sudoers"), "root ALL=(ALL) ALL\n").expect("write");
        std::os::unix::fs::symlink(
            "/opt/acme/missing",
            dangling.path().join("etc/sudoers.d/acme"),
        )
        .expect("symlink");

        let view = RootFsSystemView::from_root(dangling.path()).expect("view");
        let out = evaluate(&base_spec(SudoersMode::ForbidNoPasswd), &view);
        assert_eq!(out.status, Status::Warn);
    }
}
