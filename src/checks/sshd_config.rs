//! `sshd_config` check primitive implementing OpenSSH first-match-wins parsing with
//! `Include` support (`/etc/ssh/sshd_config.d/*.conf`).

use crate::checks::{expand_virtual_paths, CheckOutcome};
use crate::rules::schema::{SshdConfigCheck, SshdOp, SshdParam};
use crate::sys::SystemView;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default)]
struct ParsedSshdConfig {
    /// First-match-wins global directives keyed by lowercase option name.
    directives: BTreeMap<String, (String, String)>,
    /// Files skipped due to permission errors.
    unreadable: Vec<String>,
    /// Whether any conditional `Match` block was encountered.
    has_match_blocks: bool,
}

/// Evaluates OpenSSH server directives using OpenSSH first-match-wins semantics.
pub fn evaluate(spec: &SshdConfigCheck, view: &dyn SystemView) -> CheckOutcome {
    let mut parsed = ParsedSshdConfig::default();
    let mut visited = BTreeSet::new();

    match view.read_to_string(&spec.file) {
        Ok(content) => {
            visited.insert(spec.file.clone());
            parse_sshd_file(&spec.file, &content, view, &mut visited, &mut parsed, 0);
        }
        Err(err) => {
            return CheckOutcome::warn(
                format!("{} sshd_config directive(s) compliant", spec.params.len()),
                format!("{} unavailable", spec.file),
                vec![format!("{}: {err}", spec.file)],
            );
        }
    }

    let mut failed_expected = Vec::new();
    let mut failed_actual = Vec::new();
    let mut details = Vec::new();

    for param in &spec.params {
        let key_lower = param.key.to_ascii_lowercase();
        let expected_desc = format_expected(param);

        if let Some((actual_val, source)) = parsed.directives.get(&key_lower) {
            if !eval_sshd_param(param, actual_val) {
                failed_expected.push(format!("{} {expected_desc}", param.key));
                failed_actual.push(format!("{}={actual_val}", param.key));
                details.push(format!(
                    "{}: expected {expected_desc}, got '{actual_val}' (from {source})",
                    param.key
                ));
            }
        } else {
            failed_expected.push(format!("{} {expected_desc}", param.key));
            failed_actual.push(format!("{}=<unset>", param.key));
            details.push(format!(
                "{}: not explicitly configured in {} (expected {expected_desc})",
                param.key, spec.file
            ));
        }
    }

    if !failed_expected.is_empty() {
        details.extend(parsed.unreadable);
        if parsed.has_match_blocks {
            details.push(
                "Note: conditional Match blocks were skipped during global evaluation.".to_string(),
            );
        }
        return CheckOutcome::fail(
            failed_expected.join(", "),
            failed_actual.join(", "),
            details,
        );
    }

    if !parsed.unreadable.is_empty() {
        return CheckOutcome::warn(
            format!("{} sshd_config directive(s) compliant", spec.params.len()),
            format!(
                "readable directives compliant, but {} included file(s) unreadable",
                parsed.unreadable.len()
            ),
            parsed.unreadable,
        );
    }

    let mut out = CheckOutcome::pass(
        format!("{} sshd_config directive(s) compliant", spec.params.len()),
        format!(
            "all {} sshd_config directive(s) compliant",
            spec.params.len()
        ),
    );
    if parsed.has_match_blocks {
        out.details.push(
            "Note: global directives compliant; conditional Match blocks exist in sshd_config."
                .to_string(),
        );
    }
    out
}

fn parse_sshd_file(
    path: &str,
    content: &str,
    view: &dyn SystemView,
    visited: &mut BTreeSet<String>,
    parsed: &mut ParsedSshdConfig,
    depth: usize,
) {
    // Guard against deeply nested include cycles.
    if depth > 8 {
        return;
    }

    for (idx, raw_line) in content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, val)) = split_sshd_directive(trimmed) else {
            continue;
        };
        let key_lower = key.to_ascii_lowercase();

        if key_lower == "match" {
            // In OpenSSH, everything from `Match` until the end of the file (or another Match)
            // is conditional; stop parsing global options for this file.
            parsed.has_match_blocks = true;
            break;
        }

        if key_lower == "include" {
            for raw_pattern in val.split_whitespace() {
                let pattern = if raw_pattern.starts_with('/') {
                    raw_pattern.to_string()
                } else {
                    format!("/etc/ssh/{raw_pattern}")
                };
                let (matched_files, unreadable) = expand_virtual_paths(view, &[pattern]);
                parsed.unreadable.extend(unreadable);
                for inc_path in matched_files {
                    if !visited.insert(inc_path.clone()) {
                        continue;
                    }
                    match view.read_to_string(&inc_path) {
                        Ok(inc_content) => {
                            parse_sshd_file(
                                &inc_path,
                                &inc_content,
                                view,
                                visited,
                                parsed,
                                depth + 1,
                            );
                        }
                        Err(err) if err.is_not_found() => {}
                        Err(err) => parsed.unreadable.push(format!("{inc_path}: {err}")),
                    }
                }
            }
            continue;
        }

        // OpenSSH first-match-wins: insert only if not already set by an earlier directive/Include.
        parsed
            .directives
            .entry(key_lower)
            .or_insert_with(|| (val.to_string(), format!("{path}:{}", idx + 1)));
    }
}

fn split_sshd_directive(line: &str) -> Option<(&str, &str)> {
    // OpenSSH accepts `Key Value`, `Key=Value`, or `Key = Value`.
    let split_pos = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..split_pos].trim();
    let rest = line[split_pos..]
        .trim_start()
        .strip_prefix('=')
        .map_or_else(|| line[split_pos..].trim_start(), str::trim_start);
    let val = strip_inline_sshd_comment(rest).trim().trim_matches('"');
    if key.is_empty() || val.is_empty() {
        None
    } else {
        Some((key, val))
    }
}

fn strip_inline_sshd_comment(raw: &str) -> &str {
    let mut in_quotes = false;
    for (idx, ch) in raw.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &raw[..idx],
            _ => {}
        }
    }
    raw
}

fn eval_sshd_param(param: &SshdParam, actual: &str) -> bool {
    match param.op {
        SshdOp::Eq => param
            .value
            .as_deref()
            .is_some_and(|exp| actual.eq_ignore_ascii_case(exp)),
        SshdOp::Le => {
            let Some(max) = param.value.as_deref().and_then(|s| s.parse::<i64>().ok()) else {
                return false;
            };
            let Ok(cur) = actual.parse::<i64>() else {
                return false;
            };
            let min_ok = param.min_value.map_or(true, |min| cur >= min);
            min_ok && cur <= max
        }
        SshdOp::Ge => {
            let Some(min) = param.value.as_deref().and_then(|s| s.parse::<i64>().ok()) else {
                return false;
            };
            actual.parse::<i64>().is_ok_and(|cur| cur >= min)
        }
        SshdOp::In => param.values.iter().any(|v| actual.eq_ignore_ascii_case(v)),
        SshdOp::NotIn => !param.values.iter().any(|v| actual.eq_ignore_ascii_case(v)),
        SshdOp::Present => !actual.is_empty() && !actual.eq_ignore_ascii_case("none"),
        SshdOp::SubsetOf => {
            let items: Vec<&str> = actual
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            !items.is_empty()
                && items.iter().all(|item| {
                    param
                        .values
                        .iter()
                        .any(|allowed| item.eq_ignore_ascii_case(allowed))
                })
        }
    }
}

fn format_expected(param: &SshdParam) -> String {
    match param.op {
        SshdOp::Eq => format!("= {}", param.value.as_deref().unwrap_or("")),
        SshdOp::Le => match param.min_value {
            Some(min) => format!("in [{min}..={}]", param.value.as_deref().unwrap_or("")),
            None => format!("<= {}", param.value.as_deref().unwrap_or("")),
        },
        SshdOp::Ge => format!(">= {}", param.value.as_deref().unwrap_or("")),
        SshdOp::In => format!("in [{}]", param.values.join(", ")),
        SshdOp::NotIn => format!("not in [{}]", param.values.join(", ")),
        SshdOp::Present => "configured (non-'none')".to_string(),
        SshdOp::SubsetOf => format!("subset of [{}]", param.values.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use tempfile::tempdir;

    fn param(key: &str, op: SshdOp, value: &str) -> SshdParam {
        SshdParam {
            key: key.to_string(),
            op,
            value: Some(value.to_string()),
            min_value: None,
            values: Vec::new(),
        }
    }

    #[test]
    fn first_match_wins_across_include_dropins() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/ssh/sshd_config.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/ssh/sshd_config"),
            "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMaxAuthTries 4\n",
        )
        .expect("write main");
        fs::write(
            dir.path().join("etc/ssh/sshd_config.d/01-hardening.conf"),
            "PermitRootLogin no\n",
        )
        .expect("write dropin");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SshdConfigCheck {
            file: "/etc/ssh/sshd_config".to_string(),
            params: vec![
                param("PermitRootLogin", SshdOp::Eq, "no"),
                SshdParam {
                    key: "MaxAuthTries".to_string(),
                    op: SshdOp::Le,
                    value: Some("4".to_string()),
                    min_value: Some(1),
                    values: Vec::new(),
                },
            ],
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn stops_global_parsing_at_match_block_and_fails_missing_global_option() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/ssh")).expect("mkdir");
        fs::write(
            dir.path().join("etc/ssh/sshd_config"),
            "Match User admin\n  PermitRootLogin no\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SshdConfigCheck {
            file: "/etc/ssh/sshd_config".to_string(),
            params: vec![param("PermitRootLogin", SshdOp::Eq, "no")],
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.actual.as_deref().unwrap().contains("<unset>"));
    }

    #[test]
    fn validates_subset_of_strong_ciphers() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/ssh")).expect("mkdir");
        fs::write(
            dir.path().join("etc/ssh/sshd_config"),
            "Ciphers aes256-gcm@openssh.com,3des-cbc\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SshdConfigCheck {
            file: "/etc/ssh/sshd_config".to_string(),
            params: vec![SshdParam {
                key: "Ciphers".to_string(),
                op: SshdOp::SubsetOf,
                value: None,
                min_value: None,
                values: vec![
                    "chacha20-poly1305@openssh.com".to_string(),
                    "aes256-gcm@openssh.com".to_string(),
                    "aes128-gcm@openssh.com".to_string(),
                ],
            }],
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Fail);
    }

    #[test]
    fn warns_when_sshd_config_missing() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SshdConfigCheck {
            file: "/etc/ssh/sshd_config".to_string(),
            params: vec![param("PermitRootLogin", SshdOp::Eq, "no")],
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Warn);
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinked_include_drop_ins() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/ssh/sshd_config.d")).expect("mkdir");
        fs::create_dir_all(dir.path().join("usr/share/ssh")).expect("mkdir");
        fs::write(
            dir.path().join("etc/ssh/sshd_config"),
            "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n",
        )
        .expect("write main");
        fs::write(
            dir.path().join("usr/share/ssh/00-vendor.conf"),
            "PermitRootLogin yes\n",
        )
        .expect("write vendor drop-in");
        std::os::unix::fs::symlink(
            "/usr/share/ssh/00-vendor.conf",
            dir.path().join("etc/ssh/sshd_config.d/00-vendor.conf"),
        )
        .expect("symlink");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SshdConfigCheck {
            file: "/etc/ssh/sshd_config".to_string(),
            params: vec![param("PermitRootLogin", SshdOp::Eq, "no")],
        };
        // First match wins: the symlinked drop-in, included first, sets `yes`.
        assert_eq!(evaluate(&spec, &view).status, Status::Fail);
    }
}
