//! `sysctl` check primitive reading `/proc/sys/...` through [`SystemView`].

use crate::checks::CheckOutcome;
use crate::model::Status;
use crate::rules::schema::{MissingPolicy, SysctlCheck, SysctlOp, SysctlParam};
use crate::sys::SystemView;

enum ParamEval {
    Pass { actual: String },
    Fail { expected: String, actual: String },
    Missing { expected: String, reason: String },
}

/// Evaluates a declarative `sysctl` check.
///
/// Missing or unreadable keys never silently pass: they yield `WARN` (or `FAIL` when
/// `on_missing = "fail"`).
pub fn evaluate(spec: &SysctlCheck, view: &dyn SystemView) -> CheckOutcome {
    // Optional boot cmdline short-circuit (e.g. `ipv6.disable=1` for R13).
    if !spec.pass_if_cmdline_contains.is_empty() {
        if let Ok(cmdline) = view.read_to_string("/proc/cmdline") {
            let tokens: Vec<&str> = cmdline.split_whitespace().collect();
            for required_token in &spec.pass_if_cmdline_contains {
                if tokens.iter().any(|t| t == required_token) {
                    let mut outcome = CheckOutcome::pass(
                        format!("boot parameter '{required_token}' or hardened sysctl values"),
                        format!("/proc/cmdline contains '{required_token}'"),
                    );
                    outcome.details.push(format!(
                        "Control satisfied via kernel boot parameter '{required_token}'."
                    ));
                    return outcome;
                }
            }
        }
    }

    // Optional alternative sysctl short-circuit (e.g. `net.ipv6.conf.all.disable_ipv6 = 1`).
    for alt in &spec.pass_if_sysctl {
        if let ParamEval::Pass { actual } = eval_param(alt, view) {
            let expected = format_expected(alt);
            let mut outcome = CheckOutcome::pass(
                format!("{expected} (or all hardening parameters compliant)"),
                format!("{} = {actual}", alt.key),
            );
            outcome.details.push(format!(
                "Control satisfied via alternative condition: {} = {actual}.",
                alt.key
            ));
            return outcome;
        }
    }

    let mut failed_expected = Vec::new();
    let mut failed_actual = Vec::new();
    let mut missing_expected = Vec::new();
    let mut missing_details = Vec::new();
    let mut details = Vec::new();

    for param in &spec.params {
        match eval_param(param, view) {
            ParamEval::Pass { .. } => {}
            ParamEval::Fail { expected, actual } => {
                details.push(format!("{}: expected {expected}, got {actual}", param.key));
                failed_expected.push(format!("{} {expected}", param.key));
                failed_actual.push(format!("{}={actual}", param.key));
            }
            ParamEval::Missing { expected, reason } => {
                missing_details.push(format!("{}: {reason} (expected {expected})", param.key));
                missing_expected.push(format!("{} {expected}", param.key));
            }
        }
    }

    if !failed_expected.is_empty() {
        details.extend(missing_details);
        return CheckOutcome::fail(
            failed_expected.join(", "),
            failed_actual.join(", "),
            details,
        );
    }

    if !missing_details.is_empty() {
        let status = match spec.on_missing {
            MissingPolicy::Warn => Status::Warn,
            MissingPolicy::Fail => Status::Fail,
        };
        return CheckOutcome {
            status,
            expected: Some(missing_expected.join(", ")),
            actual: Some(format!(
                "{} sysctl parameter(s) missing or unreadable",
                missing_details.len()
            )),
            details: missing_details,
        };
    }

    CheckOutcome::pass(
        format!("{} sysctl parameter(s) compliant", spec.params.len()),
        format!("all {} sysctl parameter(s) compliant", spec.params.len()),
    )
}

fn eval_param(param: &SysctlParam, view: &dyn SystemView) -> ParamEval {
    let path = sysctl_key_to_path(&param.key);
    let expected = format_expected(param);

    let raw = match view.read_to_string(&path) {
        Ok(content) => content.trim().to_string(),
        Err(err) => {
            return ParamEval::Missing {
                expected,
                reason: err.to_string(),
            };
        }
    };

    if raw.is_empty() {
        return ParamEval::Missing {
            expected,
            reason: format!("empty value at {path}"),
        };
    }

    let compliant = match param.op {
        SysctlOp::Eq => param.value.as_deref() == Some(raw.as_str()),
        SysctlOp::Ge => compare_int(&raw, param.value.as_deref(), |cur, exp| cur >= exp),
        SysctlOp::Le => compare_int(&raw, param.value.as_deref(), |cur, exp| cur <= exp),
        SysctlOp::In => param.values.iter().any(|v| v == &raw),
    };

    if compliant {
        ParamEval::Pass { actual: raw }
    } else {
        ParamEval::Fail {
            expected,
            actual: raw,
        }
    }
}

fn compare_int(raw: &str, expected: Option<&str>, pred: impl FnOnce(i64, i64) -> bool) -> bool {
    let Some(exp_str) = expected else {
        return false;
    };
    let (Ok(cur), Ok(exp)) = (raw.parse::<i64>(), exp_str.parse::<i64>()) else {
        return false;
    };
    pred(cur, exp)
}

fn sysctl_key_to_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

fn format_expected(param: &SysctlParam) -> String {
    match param.op {
        SysctlOp::Eq => format!("= {}", param.value.as_deref().unwrap_or("")),
        SysctlOp::Ge => format!(">= {}", param.value.as_deref().unwrap_or("")),
        SysctlOp::Le => format!("<= {}", param.value.as_deref().unwrap_or("")),
        SysctlOp::In => format!("in [{}]", param.values.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use tempfile::tempdir;

    fn make_param(key: &str, op: SysctlOp, value: &str) -> SysctlParam {
        SysctlParam {
            key: key.to_string(),
            op,
            value: Some(value.to_string()),
            values: Vec::new(),
        }
    }

    #[test]
    fn passes_when_all_params_compliant() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("proc/sys/kernel")).expect("mkdir");
        fs::write(dir.path().join("proc/sys/kernel/dmesg_restrict"), "1\n").expect("write");
        fs::write(
            dir.path().join("proc/sys/kernel/perf_event_paranoid"),
            "3\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SysctlCheck {
            params: vec![
                make_param("kernel.dmesg_restrict", SysctlOp::Eq, "1"),
                make_param("kernel.perf_event_paranoid", SysctlOp::Ge, "2"),
            ],
            on_missing: MissingPolicy::Warn,
            pass_if_cmdline_contains: Vec::new(),
            pass_if_sysctl: Vec::new(),
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn fails_with_expected_and_actual_when_non_compliant() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("proc/sys/kernel")).expect("mkdir");
        fs::write(dir.path().join("proc/sys/kernel/dmesg_restrict"), "0\n").expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SysctlCheck {
            params: vec![make_param("kernel.dmesg_restrict", SysctlOp::Eq, "1")],
            on_missing: MissingPolicy::Warn,
            pass_if_cmdline_contains: Vec::new(),
            pass_if_sysctl: Vec::new(),
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.expected.as_deref().unwrap().contains("= 1"));
        assert!(out.actual.as_deref().unwrap().contains("=0"));
    }

    #[test]
    fn warns_instead_of_false_pass_when_key_missing() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SysctlCheck {
            params: vec![make_param("kernel.kptr_restrict", SysctlOp::Eq, "2")],
            on_missing: MissingPolicy::Warn,
            pass_if_cmdline_contains: Vec::new(),
            pass_if_sysctl: Vec::new(),
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Warn);
        assert_eq!(out.details.len(), 1);
    }

    #[test]
    fn passes_via_cmdline_or_alternative_sysctl_for_ipv6_disabled() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("proc")).expect("mkdir");
        fs::write(
            dir.path().join("proc/cmdline"),
            "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ipv6.disable=1 quiet\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let spec = SysctlCheck {
            params: vec![make_param("net.ipv6.conf.all.accept_ra", SysctlOp::Eq, "0")],
            on_missing: MissingPolicy::Warn,
            pass_if_cmdline_contains: vec!["ipv6.disable=1".to_string()],
            pass_if_sysctl: vec![make_param(
                "net.ipv6.conf.all.disable_ipv6",
                SysctlOp::Eq,
                "1",
            )],
        };

        let out = evaluate(&spec, &view);
        assert_eq!(out.status, Status::Pass);
    }
}
