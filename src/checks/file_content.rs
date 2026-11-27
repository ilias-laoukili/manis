//! `file_content` check primitive for shell timeouts (`TMOUT`), `umask`, `key_value_bound`,
//! account integrity (`/etc/passwd`, `/etc/shadow`), login banners, and regex assertions.

use crate::checks::{CheckOutcome, expand_virtual_paths};
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
        FileContentMode::KeyValueBound => eval_key_value_bound(spec, view),
        FileContentMode::PasswdUidZero => eval_passwd_uid_zero(spec, view),
        FileContentMode::ShadowEmptyPasswords => eval_shadow_empty_passwords(spec, view),
        FileContentMode::Banner => eval_banner(spec, view),
        FileContentMode::ApparmorProfiles => eval_apparmor_profiles(spec, view),
        FileContentMode::SystemAccountsNologin => eval_system_accounts_nologin(spec, view),
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
            Ok(0) => violations.push(format!("{path}: {var}=0 disables inactivity timeout")),
            Ok(val) => violations.push(format!(
                "{path}: {var}={val} exceeds maximum {max_seconds}s"
            )),
            Err(_) => violations.push(format!(
                "{path}: {var}='{raw_val}' is not a valid positive integer"
            )),
        }
    }

    (valid_values, violations)
}

fn eval_key_value_bound(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let Some(key) = spec.key.as_deref() else {
        return CheckOutcome::error("file_content key_value_bound mode requires 'key'");
    };
    let expected = format_bound_expected(key, spec.min, spec.max, spec.allow_zero);
    let (paths, mut unreadable) = expand_virtual_paths(view, &spec.paths);
    let mut existing = 0usize;
    let mut last_value: Option<(String, String)> = None;

    for path in &paths {
        match view.read_to_string(path) {
            Ok(content) => {
                existing += 1;
                for raw_line in content.lines() {
                    let line = strip_shell_comment(raw_line).trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = parse_kv_line(line) {
                        if k == key {
                            last_value = Some((path.clone(), v.to_string()));
                        }
                    }
                }
            }
            Err(err) if err.is_not_found() => {}
            Err(err) => unreadable.push(format!("{path}: {err}")),
        }
    }

    if existing == 0 {
        return missing_files_warn(
            expected,
            "target configuration file unavailable",
            "none of the configured target files exist",
            unreadable,
        );
    }

    let Some((src, raw)) = last_value else {
        return missing_directive_outcome(
            expected,
            &format!("{key} is not configured"),
            &format!("{key} was not found in checked files"),
            unreadable,
        );
    };

    match raw.parse::<i64>() {
        Ok(val) => {
            let compliant = (spec.allow_zero && val == 0)
                || (spec.min.is_none_or(|m| val >= m) && spec.max.is_none_or(|m| val <= m));
            if compliant {
                finalize_content_outcome(
                    expected,
                    &[format!("{src}: {key}={val}")],
                    Vec::new(),
                    unreadable,
                )
            } else {
                finalize_content_outcome(
                    expected,
                    &[],
                    vec![format!("{src}: {key}={val}")],
                    unreadable,
                )
            }
        }
        Err(_) => finalize_content_outcome(
            expected,
            &[],
            vec![format!("{src}: {key}='{raw}' is not an integer")],
            unreadable,
        ),
    }
}

fn parse_kv_line(line: &str) -> Option<(&str, &str)> {
    if let Some((k, v)) = line.split_once('=') {
        let key = k.trim();
        let val = v.trim().trim_matches('"').trim_matches('\'');
        if !key.is_empty() && !val.is_empty() && !key.contains(char::is_whitespace) {
            return Some((key, val));
        }
    }
    let mut parts = line.split_whitespace();
    let key = parts.next()?;
    let val = parts.next()?;
    Some((key, val))
}

fn format_bound_expected(
    key: &str,
    min: Option<i64>,
    max: Option<i64>,
    allow_zero: bool,
) -> String {
    let base = match (min, max) {
        (Some(lo), Some(hi)) => format!("{key} in [{lo}..={hi}]"),
        (Some(lo), None) => format!("{key} >= {lo}"),
        (None, Some(hi)) => format!("{key} <= {hi}"),
        (None, None) => format!("{key} configured"),
    };
    if allow_zero {
        format!("{key} = 0 or {base}")
    } else {
        base
    }
}

fn eval_apparmor_profiles(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let path = spec
        .paths
        .first()
        .map_or("/sys/kernel/security/apparmor/profiles", String::as_str);
    let expected = if spec.require_enforce {
        "AppArmor profiles loaded and all in enforce mode".to_string()
    } else {
        "AppArmor profiles loaded and all in enforce or complain mode".to_string()
    };

    let content = match view.read_to_string(path) {
        Ok(c) => c,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{path} unavailable"),
                vec![format!("{path}: {err}")],
            );
        }
    };

    let mut total = 0usize;
    let mut enforce_count = 0usize;
    let mut complain_profiles = Vec::new();
    let mut other_profiles = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        total += 1;
        if line.ends_with("(enforce)") {
            enforce_count += 1;
        } else if line.ends_with("(complain)") {
            complain_profiles.push(line.to_string());
        } else {
            other_profiles.push(line.to_string());
        }
    }

    if total == 0 {
        return CheckOutcome::fail(
            expected,
            "0 AppArmor profiles loaded",
            vec![format!("{path} contains no loaded AppArmor profiles")],
        );
    }

    let mut violations = Vec::new();
    for p in &other_profiles {
        violations.push(format!("profile not in enforce/complain mode: {p}"));
    }
    if spec.require_enforce {
        for p in &complain_profiles {
            violations.push(format!("profile in complain mode (enforce required): {p}"));
        }
    }

    if !violations.is_empty() {
        return CheckOutcome::fail(
            expected,
            format!(
                "{total} profile(s) loaded: {enforce_count} enforce, {} complain, {} other",
                complain_profiles.len(),
                other_profiles.len()
            ),
            violations,
        );
    }

    CheckOutcome::pass(
        expected,
        format!(
            "{total} profile(s) loaded ({enforce_count} enforce, {} complain)",
            complain_profiles.len()
        ),
    )
}

fn eval_system_accounts_nologin(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    const EXEMPT_ACCOUNTS: &[&str] = &["root", "sync", "shutdown", "halt"];
    let path = spec.paths.first().map_or("/etc/passwd", String::as_str);
    let expected = "all system accounts (UID < 1000, excluding root/sync/shutdown/halt) use a non-interactive shell (nologin/false)";

    let content = match view.read_to_string(path) {
        Ok(c) => c,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{path} unavailable"),
                vec![format!("{path}: {err}")],
            );
        }
    };

    let mut checked = 0usize;
    let mut violations = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let user = fields[0];
        let Ok(uid) = fields[2].parse::<u32>() else {
            continue;
        };
        let shell = fields[6].trim();

        if uid >= 1000 || EXEMPT_ACCOUNTS.contains(&user) {
            continue;
        }
        checked += 1;
        let is_non_interactive = shell.ends_with("/nologin") || shell.ends_with("/false");
        if !is_non_interactive {
            violations.push(format!(
                "{path}: system account '{user}' (UID {uid}) has interactive shell '{shell}'"
            ));
        }
    }

    if !violations.is_empty() {
        return CheckOutcome::fail(
            expected,
            format!(
                "{} system account(s) have a valid login shell",
                violations.len()
            ),
            violations,
        );
    }

    CheckOutcome::pass(
        expected,
        format!("{checked} system account(s) checked: all use non-interactive shells"),
    )
}

fn eval_passwd_uid_zero(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let path = spec.paths.first().map_or("/etc/passwd", String::as_str);
    let expected = "only 'root' has UID 0 in /etc/passwd".to_string();

    let content = match view.read_to_string(path) {
        Ok(c) => c,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{path} unavailable"),
                vec![format!("{path}: {err}")],
            );
        }
    };

    let mut uid_zero_accounts = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[2] == "0" {
            uid_zero_accounts.push(fields[0].to_string());
        }
    }

    let non_root: Vec<String> = uid_zero_accounts
        .iter()
        .filter(|u| u.as_str() != "root")
        .cloned()
        .collect();

    if !non_root.is_empty() {
        return CheckOutcome::fail(
            expected,
            format!("additional UID 0 account(s): {}", non_root.join(", ")),
            non_root
                .into_iter()
                .map(|u| format!("{path}: non-root account '{u}' has UID 0"))
                .collect(),
        );
    }

    if uid_zero_accounts.is_empty() {
        return CheckOutcome::warn(
            expected,
            "no UID 0 account found in /etc/passwd",
            vec![format!("{path}: expected 'root' entry with UID 0")],
        );
    }

    CheckOutcome::pass(expected, "only 'root' has UID 0")
}

fn eval_shadow_empty_passwords(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let path = spec.paths.first().map_or("/etc/shadow", String::as_str);
    let expected = "no accounts with empty password fields in /etc/shadow".to_string();

    let content = match view.read_to_string(path) {
        Ok(c) => c,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{path} unavailable or unreadable"),
                vec![format!("{path}: {err}")],
            );
        }
    };

    let mut empty_accounts = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 2 && fields[1].is_empty() {
            empty_accounts.push(fields[0].to_string());
        }
    }

    if !empty_accounts.is_empty() {
        return CheckOutcome::fail(
            expected,
            format!(
                "{} account(s) with empty password field",
                empty_accounts.len()
            ),
            empty_accounts
                .into_iter()
                .map(|u| format!("{path}: account '{u}' has an empty password field"))
                .collect(),
        );
    }

    CheckOutcome::pass(expected, "all accounts have non-empty password fields")
}

fn eval_banner(spec: &FileContentCheck, view: &dyn SystemView) -> CheckOutcome {
    let path = spec.paths.first().map_or("/etc/issue", String::as_str);
    let expected = format!(
        "{path} contains a non-empty legal warning banner without OS leak escapes (\\m, \\r, \\s, \\v)"
    );

    let content = match view.read_to_string(path) {
        Ok(c) => c,
        Err(err) if err.is_not_found() => {
            return CheckOutcome::fail(
                expected,
                format!("{path} is missing"),
                vec![format!("{path}: banner file does not exist")],
            );
        }
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                format!("{path} unreadable"),
                vec![format!("{path}: {err}")],
            );
        }
    };

    let trimmed = content.trim();
    if trimmed.is_empty() {
        return CheckOutcome::fail(
            expected,
            format!("{path} is empty"),
            vec![format!("{path}: no warning banner text configured")],
        );
    }

    let mut leaks = Vec::new();
    for seq in ["\\m", "\\r", "\\s", "\\v"] {
        if content.contains(seq) {
            leaks.push(seq);
        }
    }
    if !leaks.is_empty() {
        return CheckOutcome::fail(
            expected,
            format!("{path} exposes OS escape sequence(s): {}", leaks.join(", ")),
            vec![format!(
                "{path}: remove OS information escapes ({})",
                leaks.join(", ")
            )],
        );
    }

    CheckOutcome::pass(
        expected,
        format!("{path} configured without OS leak escapes"),
    )
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
            if matches.is_empty() {
                missing_directive_outcome(
                    format!("at least one line matching '{pattern}'"),
                    "no matching line found",
                    &format!("pattern '{pattern}' did not match any checked file"),
                    unreadable,
                )
            } else {
                finalize_content_outcome(
                    format!("line matching '{pattern}'"),
                    &matches,
                    Vec::new(),
                    unreadable,
                )
            }
        }
        RegexMatchMode::NoLine => finalize_content_outcome(
            format!("no line matching '{pattern}'"),
            &["no forbidden lines found".to_string()],
            matches,
            unreadable,
        ),
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
    use crate::sys::{RootFsSystemView, rootfs::FIXTURE_META_FILE};
    use std::fs;
    use tempfile::tempdir;

    fn base_spec(mode: FileContentMode) -> FileContentCheck {
        FileContentCheck {
            mode,
            paths: Vec::new(),
            var: "TMOUT".to_string(),
            max_seconds: 600,
            require_readonly: true,
            strict_paths: Vec::new(),
            strict_allowed: Vec::new(),
            standard_allowed: Vec::new(),
            pam_paths: Vec::new(),
            pattern: None,
            match_mode: RegexMatchMode::AnyLine,
            key: None,
            min: None,
            max: None,
            allow_zero: false,
            require_enforce: false,
        }
    }

    #[test]
    fn key_value_bound_supports_equals_and_allow_zero_for_faillock() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/security")).expect("mkdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");

        let mut spec = base_spec(FileContentMode::KeyValueBound);
        spec.paths = vec!["/etc/security/faillock.conf".to_string()];
        spec.key = Some("unlock_time".to_string());
        spec.min = Some(900);
        spec.allow_zero = true;

        fs::write(
            dir.path().join("etc/security/faillock.conf"),
            "unlock_time = 0\n",
        )
        .expect("w");
        assert_eq!(evaluate(&spec, &view).status, Status::Pass);

        fs::write(
            dir.path().join("etc/security/faillock.conf"),
            "unlock_time = 900\n",
        )
        .expect("w");
        assert_eq!(evaluate(&spec, &view).status, Status::Pass);

        fs::write(
            dir.path().join("etc/security/faillock.conf"),
            "unlock_time = 300\n",
        )
        .expect("w");
        assert_eq!(evaluate(&spec, &view).status, Status::Fail);
    }

    #[test]
    fn apparmor_profiles_distinguishes_l1_complain_and_l2_enforce() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("sys/kernel/security/apparmor")).expect("mkdir");
        fs::write(
            dir.path().join("sys/kernel/security/apparmor/profiles"),
            "/usr/sbin/sshd (enforce)\n/usr/bin/tcpdump (complain)\n",
        )
        .expect("write");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");

        let mut l1 = base_spec(FileContentMode::ApparmorProfiles);
        l1.paths = vec!["/sys/kernel/security/apparmor/profiles".to_string()];
        l1.require_enforce = false;
        assert_eq!(evaluate(&l1, &view).status, Status::Pass);

        let mut l2 = l1.clone();
        l2.require_enforce = true;
        assert_eq!(evaluate(&l2, &view).status, Status::Fail);
    }

    #[test]
    fn system_accounts_nologin_flags_interactive_shell_and_allows_exempt() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let mut spec = base_spec(FileContentMode::SystemAccountsNologin);
        spec.paths = vec!["/etc/passwd".to_string()];

        assert_eq!(evaluate(&spec, &view).status, Status::Warn);

        fs::write(
            dir.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www:/var/www:/bin/false\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n",
        )
        .expect("write");
        assert_eq!(evaluate(&spec, &view).status, Status::Pass);

        fs::write(
            dir.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/bash\n",
        )
        .expect("write");
        let fail = evaluate(&spec, &view);
        assert_eq!(fail.status, Status::Fail);
        assert_eq!(fail.details.len(), 1);
    }

    #[test]
    fn key_value_bound_validates_login_defs_pass_max_days() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("etc/login.defs"), "PASS_MAX_DAYS 365\n").expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let mut spec = base_spec(FileContentMode::KeyValueBound);
        spec.paths = vec!["/etc/login.defs".to_string()];
        spec.key = Some("PASS_MAX_DAYS".to_string());
        spec.min = Some(1);
        spec.max = Some(365);

        assert_eq!(evaluate(&spec, &view).status, Status::Pass);

        fs::write(dir.path().join("etc/login.defs"), "PASS_MAX_DAYS 99999\n").expect("write");
        assert_eq!(evaluate(&spec, &view).status, Status::Fail);
    }

    #[test]
    fn passwd_uid_zero_and_shadow_empty_passwords() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(
            dir.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nrogue:x:0:0::/tmp:/bin/sh\n",
        )
        .expect("write");
        fs::write(
            dir.path().join("etc/shadow"),
            "root:*:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let mut pspec = base_spec(FileContentMode::PasswdUidZero);
        pspec.paths = vec!["/etc/passwd".to_string()];
        assert_eq!(evaluate(&pspec, &view).status, Status::Fail);

        let mut sspec = base_spec(FileContentMode::ShadowEmptyPasswords);
        sspec.paths = vec!["/etc/shadow".to_string()];
        assert_eq!(evaluate(&sspec, &view).status, Status::Fail);

        // Unreadable /etc/shadow must WARN, never PASS.
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/etc/shadow\"]\nunreadable = true\n",
        )
        .expect("write");
        let view2 = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        assert_eq!(evaluate(&sspec, &view2).status, Status::Warn);
    }

    #[test]
    fn banner_rejects_os_escape_sequences() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("etc/issue"), "Ubuntu 24.04 \\n \\l \\r\n").expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let mut spec = base_spec(FileContentMode::Banner);
        spec.paths = vec!["/etc/issue".to_string()];
        assert_eq!(evaluate(&spec, &view).status, Status::Fail);

        fs::write(
            dir.path().join("etc/issue"),
            "Authorized access only. All activity may be monitored.\n",
        )
        .expect("write");
        assert_eq!(evaluate(&spec, &view).status, Status::Pass);
    }
}
