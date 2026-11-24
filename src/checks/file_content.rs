//! `file_content` check primitive for shell timeouts (`TMOUT`), `umask`, and regex assertions.

use crate::checks::{expand_virtual_paths, CheckOutcome};
use crate::rules::schema::{FileContentCheck, FileContentMode, RegexMatchMode};
use crate::sys::SystemView;
use regex::Regex;
use std::collections::BTreeSet;

/// Evaluates a `file_content` rule against files read via [`SystemView`].
pub fn evaluate(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    match spec.mode {
        FileContentMode::ShellTimeout => eval_shell_timeout(spec, view),
        FileContentMode::Umask => eval_umask(spec, view),
        FileContentMode::Regex => eval_regex(spec, view),
    }
}

fn eval_shell_timeout(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let (paths, mut unreadable) = expand_virtual_paths(view, &spec.paths);
    let mut existing_files = 0usize;
    let mut assignments: Vec<(String, String)> = Vec::new();
    let mut readonly_seen = false;

    for path in &paths {
        match view.read_to_string(path) {
            Ok(content) => {
                existing_files += 1;
                parse_shell_timeout_file(
                    path,
                    &content,
                    &spec.var,
                    &mut assignments,
                    &mut readonly_seen,
                );
            }
            Err(err) if err.is_not_found() => {}
            Err(err) => unreadable.push(format!("{path}: {err}")),
        }
    }

    let expected = if spec.require_readonly {
        format!(
            "{} configured between 1 and {}s and marked readonly",
            spec.var, spec.max_seconds
        )
    } else {
        format!(
            "{} configured between 1 and {}s",
            spec.var, spec.max_seconds
        )
    };

    if existing_files == 0 {
        return missing_files_warn(
            expected,
            "no target shell configuration files readable",
            "none of the configured shell profile files exist",
            unreadable,
        );
    }

    if assignments.is_empty() {
        return missing_directive_outcome(
            expected,
            &format!("{} is not configured", spec.var),
            &format!(
                "{} was not found in any checked shell profile file",
                spec.var
            ),
            unreadable,
        );
    }

    let (valid_values, mut violations) =
        validate_timeout_assignments(&assignments, &spec.var, spec.max_seconds);
    if spec.require_readonly && !readonly_seen {
        violations.push(format!("{} is not marked readonly", spec.var));
    }

    finalize_content_outcome(expected, &valid_values, violations, unreadable)
}

fn validate_timeout_assignments(
    assignments: &[(String, String)],
    var: &str,
    max_seconds: u64,
) -> (Vec<String>, Vec<String>) {
    let mut valid_values = Vec::new();
    let mut violations = Vec::new();

    for (path, raw_val) in assignments {
        match raw_val.parse::<u64>() {
            Ok(val) if val >= 1 && val <= max_seconds => {
                valid_values.push(format!("{path}: {var}={val}"));
            }
            Ok(0) => {
                violations.push(format!("{path}: {var}=0 disables inactivity timeout"));
            }
            Ok(val) => {
                violations.push(format!(
                    "{path}: {var}={val} exceeds maximum {max_seconds}s"
                ));
            }
            Err(_) => {
                violations.push(format!(
                    "{path}: {var}='{raw_val}' is not a valid positive integer"
                ));
            }
        }
    }

    (valid_values, violations)
}

fn missing_files_warn(
    expected: String,
    actual: &str,
    default_detail: &str,
    unreadable: Vec<String>,
) -> CheckOutcome {
    let details = if unreadable.is_empty() {
        vec![default_detail.to_string()]
    } else {
        unreadable
    };
    CheckOutcome::warn(expected, actual, details)
}

fn missing_directive_outcome(
    expected: String,
    actual_fail: &str,
    detail_fail: &str,
    unreadable: Vec<String>,
) -> CheckOutcome {
    if !unreadable.is_empty() {
        return CheckOutcome::warn(
            expected,
            format!(
                "directive not found in readable files ({} unreadable)",
                unreadable.len()
            ),
            unreadable,
        );
    }
    CheckOutcome::fail(expected, actual_fail, vec![detail_fail.to_string()])
}

fn finalize_content_outcome(
    expected: String,
    compliant: &[String],
    violations: Vec<String>,
    unreadable: Vec<String>,
) -> CheckOutcome {
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
                "compliant in readable files, but {} file(s) unreadable",
                unreadable.len()
            ),
            unreadable,
        );
    }
    CheckOutcome::pass(expected, compliant.join(", "))
}

fn parse_shell_timeout_file(
    path: &str,
    content: &str,
    var: &str,
    assignments: &mut Vec<(String, String)>,
    readonly_seen: &mut bool,
) {
    let assign_prefix = format!("{var}=");
    for raw_line in content.lines() {
        let clean = strip_shell_comment(raw_line).trim();
        if clean.is_empty() {
            continue;
        }
        for stmt in clean.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            let tokens: Vec<&str> = stmt.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            let mut is_readonly_stmt = false;
            let mut idx = 0;

            match tokens[0] {
                "readonly" => {
                    is_readonly_stmt = true;
                    idx = 1;
                }
                "export" => {
                    idx = 1;
                }
                "declare" | "typeset" => {
                    idx = 1;
                    while idx < tokens.len() && tokens[idx].starts_with('-') {
                        if tokens[idx].contains('r') {
                            is_readonly_stmt = true;
                        }
                        idx += 1;
                    }
                }
                _ => {}
            }

            for token in &tokens[idx..] {
                if *token == var && is_readonly_stmt {
                    *readonly_seen = true;
                } else if let Some(raw_val) = token.strip_prefix(&assign_prefix) {
                    let val = trim_quotes(raw_val);
                    assignments.push((path.to_string(), val));
                    if is_readonly_stmt {
                        *readonly_seen = true;
                    }
                }
            }
        }
    }
}

fn eval_umask(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let strict_allowed: BTreeSet<String> = spec
        .strict_allowed
        .iter()
        .filter_map(|v| normalize_umask(v))
        .collect();
    let standard_allowed: BTreeSet<String> = spec
        .standard_allowed
        .iter()
        .filter_map(|v| normalize_umask(v))
        .collect();

    let (strict_files, mut unreadable) = expand_virtual_paths(view, &spec.strict_paths);
    let (std_files, more_unreadable) = expand_virtual_paths(view, &spec.paths);
    unreadable.extend(more_unreadable);
    let (pam_files, pam_unreadable) = expand_virtual_paths(view, &spec.pam_paths);
    unreadable.extend(pam_unreadable);

    let mut state = UmaskAuditState::default();
    inspect_umask_files(
        view,
        &strict_files,
        &strict_allowed,
        "umask",
        |path, content| {
            if path.ends_with("login.defs") {
                extract_login_defs_umask(content)
            } else {
                extract_shell_umask(content)
            }
        },
        &mut state,
    );
    inspect_umask_files(
        view,
        &std_files,
        &standard_allowed,
        "umask",
        |_, content| extract_shell_umask(content),
        &mut state,
    );
    inspect_umask_files(
        view,
        &pam_files,
        &standard_allowed,
        "pam_umask",
        |_, content| extract_pam_umask(content),
        &mut state,
    );

    unreadable.extend(state.unreadable);
    unreadable.sort();
    unreadable.dedup();

    let expected = format!(
        "strict files umask in [{}]; shell/PAM files umask in [{}] with no permissive overrides",
        join_set(&strict_allowed),
        join_set(&standard_allowed)
    );

    if !state.violations.is_empty() {
        return finalize_content_outcome(
            expected,
            &state.found_compliant,
            state.violations,
            unreadable,
        );
    }
    if state.existing_files == 0 {
        return missing_files_warn(
            expected,
            "no umask configuration files readable",
            "none of the configured umask files exist",
            unreadable,
        );
    }
    if state.found_compliant.is_empty() {
        return missing_directive_outcome(
            expected,
            "no umask directive configured",
            "no restrictive umask was configured in any inspected file",
            unreadable,
        );
    }

    finalize_content_outcome(
        expected,
        &state.found_compliant,
        state.violations,
        unreadable,
    )
}

#[derive(Default)]
struct UmaskAuditState {
    existing_files: usize,
    found_compliant: Vec<String>,
    violations: Vec<String>,
    unreadable: Vec<String>,
}

fn inspect_umask_files<F>(
    view: &dyn SystemView,
    paths: &[String],
    allowed: &BTreeSet<String>,
    label: &str,
    extractor: F,
    state: &mut UmaskAuditState,
) where
    F: Fn(&str, &str) -> Vec<String>,
{
    for path in paths {
        match view.read_to_string(path) {
            Ok(content) => {
                state.existing_files += 1;
                for raw in extractor(path, &content) {
                    match normalize_umask(&raw) {
                        Some(norm) if allowed.contains(&norm) => {
                            state.found_compliant.push(format!("{path}: {norm}"));
                        }
                        Some(norm) => state.violations.push(format!(
                            "{path}: {label} {norm} (expected one of [{}])",
                            join_set(allowed)
                        )),
                        None => state.violations.push(format!(
                            "{path}: unrecognized {label} '{raw}' (expected one of [{}])",
                            join_set(allowed)
                        )),
                    }
                }
            }
            Err(err) if err.is_not_found() => {}
            Err(err) => state.unreadable.push(format!("{path}: {err}")),
        }
    }
}

fn eval_regex(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let Some(pattern) = spec.pattern.as_deref() else {
        return CheckOutcome::error("file_content regex mode requires 'pattern'");
    };
    let Ok(re) = Regex::new(pattern) else {
        return CheckOutcome::error(format!("invalid regex pattern '{pattern}'"));
    };

    let (paths, mut unreadable) = expand_virtual_paths(view, &spec.paths);
    let mut existing_files = 0usize;
    let mut matches = Vec::new();

    for path in &paths {
        match view.read_to_string(path) {
            Ok(content) => {
                existing_files += 1;
                for (idx, raw_line) in content.lines().enumerate() {
                    let line = raw_line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if re.is_match(line) {
                        matches.push(format!("{path}:{}: {line}", idx + 1));
                    }
                }
            }
            Err(err) if err.is_not_found() => {}
            Err(err) => unreadable.push(format!("{path}: {err}")),
        }
    }

    if existing_files == 0 {
        return CheckOutcome::warn(
            format!("regex '{pattern}' checked"),
            "no target files readable",
            if unreadable.is_empty() {
                vec!["none of the target files exist".to_string()]
            } else {
                unreadable
            },
        );
    }

    match spec.match_mode {
        RegexMatchMode::AnyLine => {
            if !matches.is_empty() {
                if !unreadable.is_empty() {
                    return CheckOutcome::warn(
                        format!("line matching '{pattern}'"),
                        format!("matched, but {} file(s) unreadable", unreadable.len()),
                        unreadable,
                    );
                }
                CheckOutcome::pass(format!("line matching '{pattern}'"), matches.join("; "))
            } else if !unreadable.is_empty() {
                CheckOutcome::warn(
                    format!("line matching '{pattern}'"),
                    "no match in readable files",
                    unreadable,
                )
            } else {
                CheckOutcome::fail(
                    format!("at least one line matching '{pattern}'"),
                    "no matching line found",
                    vec![format!(
                        "pattern '{pattern}' did not match any checked file"
                    )],
                )
            }
        }
        RegexMatchMode::NoLine => {
            if !matches.is_empty() {
                let actual = matches.join("; ");
                let mut details = matches;
                details.extend(unreadable);
                CheckOutcome::fail(format!("no line matching '{pattern}'"), actual, details)
            } else if !unreadable.is_empty() {
                CheckOutcome::warn(
                    format!("no line matching '{pattern}'"),
                    format!(
                        "clean in readable files, but {} file(s) unreadable",
                        unreadable.len()
                    ),
                    unreadable,
                )
            } else {
                CheckOutcome::pass(
                    format!("no line matching '{pattern}'"),
                    "no forbidden lines found",
                )
            }
        }
    }
}

fn extract_login_defs_umask(content: &str) -> Vec<String> {
    let mut vals = Vec::new();
    for raw_line in content.lines() {
        let line = strip_shell_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() == Some("UMASK") {
            if let Some(val) = parts.next() {
                vals.push(val.to_string());
            }
        }
    }
    vals
}

fn extract_shell_umask(content: &str) -> Vec<String> {
    let mut vals = Vec::new();
    for raw_line in content.lines() {
        let line = strip_shell_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        for stmt in line.split(';') {
            let mut parts = stmt.split_whitespace();
            if parts.next() == Some("umask") {
                if let Some(arg) = parts.next() {
                    if !arg.starts_with('-') {
                        vals.push(trim_quotes(arg));
                    } else if let Some(val) = parts.next() {
                        vals.push(trim_quotes(val));
                    }
                }
            }
        }
    }
    vals
}

fn extract_pam_umask(content: &str) -> Vec<String> {
    let mut vals = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains("pam_umask.so") {
            continue;
        }
        for token in line.split_whitespace() {
            if let Some(val) = token.strip_prefix("umask=") {
                vals.push(trim_quotes(val));
            }
        }
    }
    vals
}

fn normalize_umask(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    let val = u32::from_str_radix(trimmed, 8).ok()?;
    if val > 0o777 {
        return None;
    }
    Some(format!("{val:03o}"))
}

fn strip_shell_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn trim_quotes(raw: &str) -> String {
    raw.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn join_set(set: &BTreeSet<String>) -> String {
    let items: Vec<&str> = set.iter().map(String::as_str).collect();
    items.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use tempfile::tempdir;

    fn timeout_spec() -> FileContentCheck {
        FileContentCheck {
            mode: FileContentMode::ShellTimeout,
            paths: vec![
                "/etc/profile".to_string(),
                "/etc/profile.d/*.sh".to_string(),
            ],
            var: "TMOUT".to_string(),
            max_seconds: 600,
            require_readonly: true,
            strict_paths: Vec::new(),
            strict_allowed: Vec::new(),
            standard_allowed: Vec::new(),
            pam_paths: Vec::new(),
            pattern: None,
            match_mode: RegexMatchMode::AnyLine,
        }
    }

    fn umask_spec() -> FileContentCheck {
        FileContentCheck {
            mode: FileContentMode::Umask,
            paths: vec![
                "/etc/profile.d/*.sh".to_string(),
                "/etc/bash.bashrc".to_string(),
            ],
            var: "TMOUT".to_string(),
            max_seconds: 600,
            require_readonly: true,
            strict_paths: vec!["/etc/login.defs".to_string(), "/etc/profile".to_string()],
            strict_allowed: vec!["077".to_string()],
            standard_allowed: vec!["027".to_string(), "077".to_string()],
            pam_paths: vec!["/etc/pam.d/common-session".to_string()],
            pattern: None,
            match_mode: RegexMatchMode::AnyLine,
        }
    }

    #[test]
    fn timeout_passes_when_within_limit_and_readonly() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/profile.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/profile.d/tmout.sh"),
            "# Shell timeout\nreadonly TMOUT=600 # 10 min\nexport TMOUT\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&timeout_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn timeout_fails_when_exceeding_max_seconds() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/profile.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/profile.d/tmout.sh"),
            "TMOUT=900\nreadonly TMOUT\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&timeout_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.actual.as_deref().unwrap().contains("exceeds maximum"));
    }

    #[test]
    fn timeout_warns_when_no_files_exist() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&timeout_spec(), &view);
        assert_eq!(out.status, Status::Warn);
    }

    #[test]
    fn umask_fails_when_weak_override_present_alongside_strict() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("etc/login.defs"), "UMASK 077\n").expect("write");
        fs::write(dir.path().join("etc/bash.bashrc"), "umask 022\n").expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&umask_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.actual.as_deref().unwrap().contains("022"));
    }

    #[test]
    fn umask_passes_when_all_directives_compliant() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/pam.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/login.defs"),
            "# UMASK 022\nUMASK 0077\n",
        )
        .expect("write");
        fs::write(
            dir.path().join("etc/pam.d/common-session"),
            "session optional pam_umask.so umask=0027\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&umask_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }
}
