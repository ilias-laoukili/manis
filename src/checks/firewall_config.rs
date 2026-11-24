//! `firewall_config` check primitive inspecting UFW and nftables configuration files directly
//! through [`SystemView`] (no `ufw` or `nft` subprocesses).

use crate::checks::CheckOutcome;
use crate::rules::schema::{FirewallConfigCheck, FirewallConfigMode};
use crate::sys::SystemView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveFirewall {
    Ufw,
    Nftables,
}

/// Evaluates host firewall enablement, default deny input policy, and loopback rules.
pub fn evaluate(spec: &FirewallConfigCheck, view: &dyn SystemView) -> CheckOutcome {
    let ufw_conf = view.read_to_string("/etc/ufw/ufw.conf");
    let nft_conf = view.read_to_string("/etc/nftables.conf");

    let ufw_present = ufw_conf.is_ok();
    let nft_present = nft_conf.is_ok();

    if !ufw_present && !nft_present {
        let mut details = Vec::new();
        if let Err(err) = ufw_conf {
            details.push(format!("/etc/ufw/ufw.conf: {err}"));
        }
        if let Err(err) = nft_conf {
            details.push(format!("/etc/nftables.conf: {err}"));
        }
        return CheckOutcome::warn(
            expected_label(spec.mode),
            "no UFW or nftables configuration files found",
            details,
        );
    }

    let ufw_enabled = ufw_conf.as_deref().is_ok_and(is_ufw_enabled);
    let nft_enabled = nft_conf
        .as_deref()
        .is_ok_and(|c| is_nftables_active(c, view));

    match spec.mode {
        FirewallConfigMode::SingleFirewallEnabled => eval_single_enabled(ufw_enabled, nft_enabled),
        FirewallConfigMode::DefaultDenyInput => {
            let Some(active) = pick_active(ufw_enabled, nft_enabled) else {
                return CheckOutcome::fail(
                    expected_label(spec.mode),
                    "no active host firewall enabled",
                    vec![
                        "enable either UFW or nftables with a default deny input policy"
                            .to_string(),
                    ],
                );
            };
            match active {
                ActiveFirewall::Ufw => eval_ufw_default_deny(view),
                ActiveFirewall::Nftables => {
                    eval_nft_default_deny(nft_conf.as_deref().unwrap_or(""))
                }
            }
        }
        FirewallConfigMode::LoopbackConfigured => {
            let Some(active) = pick_active(ufw_enabled, nft_enabled) else {
                return CheckOutcome::fail(
                    expected_label(spec.mode),
                    "no active host firewall enabled",
                    vec![
                        "enable either UFW or nftables with loopback rules configured".to_string(),
                    ],
                );
            };
            match active {
                ActiveFirewall::Ufw => eval_ufw_loopback(view),
                ActiveFirewall::Nftables => eval_nft_loopback(nft_conf.as_deref().unwrap_or("")),
            }
        }
    }
}

fn expected_label(mode: FirewallConfigMode) -> &'static str {
    match mode {
        FirewallConfigMode::SingleFirewallEnabled => {
            "exactly one host firewall enabled (UFW or nftables)"
        }
        FirewallConfigMode::DefaultDenyInput => {
            "active host firewall enforces default input policy DROP or REJECT"
        }
        FirewallConfigMode::LoopbackConfigured => {
            "active host firewall allows loopback (lo) and drops spoofed 127.0.0.0/8 traffic"
        }
    }
}

fn pick_active(ufw_enabled: bool, nft_enabled: bool) -> Option<ActiveFirewall> {
    if ufw_enabled {
        Some(ActiveFirewall::Ufw)
    } else if nft_enabled {
        Some(ActiveFirewall::Nftables)
    } else {
        None
    }
}

fn eval_single_enabled(ufw_enabled: bool, nft_enabled: bool) -> CheckOutcome {
    let expected = expected_label(FirewallConfigMode::SingleFirewallEnabled);
    match (ufw_enabled, nft_enabled) {
        (true, false) => CheckOutcome::pass(expected, "UFW enabled (ENABLED=yes)"),
        (false, true) => CheckOutcome::pass(expected, "nftables enabled (/etc/nftables.conf + service)"),
        (true, true) => CheckOutcome::fail(
            expected,
            "both UFW and nftables are enabled simultaneously",
            vec!["disable either UFW or nftables to avoid conflicting netfilter rulesets".to_string()],
        ),
        (false, false) => CheckOutcome::fail(
            expected,
            "neither UFW nor nftables is enabled",
            vec![
                "UFW is not enabled (ENABLED=yes missing in /etc/ufw/ufw.conf) and nftables.service is not enabled"
                    .to_string(),
            ],
        ),
    }
}

fn is_ufw_enabled(content: &str) -> bool {
    content.lines().any(|raw| {
        let line = raw.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = line.split_once('=') {
            k.trim().eq_ignore_ascii_case("ENABLED")
                && v.trim().trim_matches('"').eq_ignore_ascii_case("yes")
        } else {
            false
        }
    })
}

fn is_nftables_active(content: &str, view: &dyn SystemView) -> bool {
    let has_table = content.lines().any(|raw| {
        let line = raw.split('#').next().unwrap_or("").trim();
        line.starts_with("table ")
    });
    if !has_table {
        return false;
    }
    let masked = view
        .read_link("/etc/systemd/system/nftables.service")
        .is_ok_and(|t| t == "/dev/null");
    if masked {
        return false;
    }
    view.exists("/etc/systemd/system/sysinit.target.wants/nftables.service")
        || view.exists("/etc/systemd/system/multi-user.target.wants/nftables.service")
}

fn eval_ufw_default_deny(view: &dyn SystemView) -> CheckOutcome {
    let expected = expected_label(FirewallConfigMode::DefaultDenyInput);
    let content = match view.read_to_string("/etc/default/ufw") {
        Ok(c) => c,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                "/etc/default/ufw unavailable",
                vec![format!("/etc/default/ufw: {err}")],
            );
        }
    };

    let mut policy: Option<String> = None;
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "DEFAULT_INPUT_POLICY" {
                policy = Some(v.trim().trim_matches('"').trim_matches('\'').to_string());
            }
        }
    }

    match policy.as_deref() {
        Some(p) if p.eq_ignore_ascii_case("DROP") || p.eq_ignore_ascii_case("REJECT") => {
            CheckOutcome::pass(expected, format!("DEFAULT_INPUT_POLICY={p}"))
        }
        Some(p) => CheckOutcome::fail(
            expected,
            format!("DEFAULT_INPUT_POLICY={p}"),
            vec![format!(
                "/etc/default/ufw sets DEFAULT_INPUT_POLICY=\"{p}\" instead of DROP or REJECT"
            )],
        ),
        None => CheckOutcome::fail(
            expected,
            "DEFAULT_INPUT_POLICY not set in /etc/default/ufw",
            vec!["DEFAULT_INPUT_POLICY directive missing in /etc/default/ufw".to_string()],
        ),
    }
}

fn eval_nft_default_deny(content: &str) -> CheckOutcome {
    let expected = expected_label(FirewallConfigMode::DefaultDenyInput);
    let has_drop_input = content.lines().any(|raw| {
        let line = raw.split('#').next().unwrap_or("").to_ascii_lowercase();
        line.contains("hook input")
            && (line.contains("policy drop") || line.contains("policy reject"))
    });
    if has_drop_input {
        CheckOutcome::pass(expected, "nftables input chain uses drop/reject policy")
    } else {
        CheckOutcome::fail(
            expected,
            "nftables input chain does not enforce policy drop/reject",
            vec!["/etc/nftables.conf is missing 'hook input ... policy drop;'".to_string()],
        )
    }
}

fn eval_ufw_loopback(view: &dyn SystemView) -> CheckOutcome {
    let expected = expected_label(FirewallConfigMode::LoopbackConfigured);
    let content = match view.read_to_string("/etc/ufw/before.rules") {
        Ok(c) => c,
        Err(err) => {
            return CheckOutcome::warn(
                expected,
                "/etc/ufw/before.rules unavailable",
                vec![format!("/etc/ufw/before.rules: {err}")],
            );
        }
    };

    let allows_lo = content.lines().any(|raw| {
        let line = raw.split('#').next().unwrap_or("").trim();
        line.contains("-i lo") && line.contains("-j ACCEPT")
    });
    let drops_spoof = content.lines().any(|raw| {
        let line = raw.split('#').next().unwrap_or("").trim();
        line.contains("127.0.0.0/8") && (line.contains("-j DROP") || line.contains("-j REJECT"))
    });

    if allows_lo && drops_spoof {
        CheckOutcome::pass(
            expected,
            "UFW before.rules allows lo and drops spoofed 127.0.0.0/8",
        )
    } else {
        let mut details = Vec::new();
        if !allows_lo {
            details.push("/etc/ufw/before.rules is missing '-i lo -j ACCEPT'".to_string());
        }
        if !drops_spoof {
            details.push(
                "/etc/ufw/before.rules is missing spoofed loopback drop for 127.0.0.0/8"
                    .to_string(),
            );
        }
        CheckOutcome::fail(expected, "UFW loopback rules incomplete", details)
    }
}

fn eval_nft_loopback(content: &str) -> CheckOutcome {
    let expected = expected_label(FirewallConfigMode::LoopbackConfigured);
    let lower = content.to_ascii_lowercase();
    let allows_lo = lower.contains("iif \"lo\" accept") || lower.contains("iifname \"lo\" accept");
    let drops_spoof = lower.contains("127.0.0.0/8") && lower.contains("drop");

    if allows_lo && drops_spoof {
        CheckOutcome::pass(expected, "nftables allows lo and drops spoofed 127.0.0.0/8")
    } else {
        CheckOutcome::fail(
            expected,
            "nftables loopback rules incomplete",
            vec![
                "/etc/nftables.conf must allow 'iif \"lo\" accept' and drop spoofed '127.0.0.0/8'"
                    .to_string(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn evaluates_ufw_enabled_default_deny_and_loopback() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/ufw")).expect("mkdir");
        fs::create_dir_all(dir.path().join("etc/default")).expect("mkdir");
        fs::write(dir.path().join("etc/ufw/ufw.conf"), "ENABLED=yes\n").expect("write");
        fs::write(
            dir.path().join("etc/default/ufw"),
            "DEFAULT_INPUT_POLICY=\"DROP\"\n",
        )
        .expect("write");
        fs::write(
            dir.path().join("etc/ufw/before.rules"),
            "-A ufw-before-input -i lo -j ACCEPT\n-A ufw-before-input -s 127.0.0.0/8 ! -i lo -j DROP\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        for mode in [
            FirewallConfigMode::SingleFirewallEnabled,
            FirewallConfigMode::DefaultDenyInput,
            FirewallConfigMode::LoopbackConfigured,
        ] {
            assert_eq!(
                evaluate(&FirewallConfigCheck { mode }, &view).status,
                Status::Pass
            );
        }
    }

    #[test]
    fn evaluates_nftables_and_flags_conflict_when_both_enabled() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/systemd/system/sysinit.target.wants"))
            .expect("mkdir");
        fs::write(
            dir.path()
                .join("etc/systemd/system/sysinit.target.wants/nftables.service"),
            "",
        )
        .expect("write");
        fs::write(
            dir.path().join("etc/nftables.conf"),
            "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    iif \"lo\" accept\n    iif != \"lo\" ip saddr 127.0.0.0/8 drop\n  }\n}\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        assert_eq!(
            evaluate(
                &FirewallConfigCheck {
                    mode: FirewallConfigMode::SingleFirewallEnabled
                },
                &view
            )
            .status,
            Status::Pass
        );
        assert_eq!(
            evaluate(
                &FirewallConfigCheck {
                    mode: FirewallConfigMode::DefaultDenyInput
                },
                &view
            )
            .status,
            Status::Pass
        );
        assert_eq!(
            evaluate(
                &FirewallConfigCheck {
                    mode: FirewallConfigMode::LoopbackConfigured
                },
                &view
            )
            .status,
            Status::Pass
        );

        // Enable UFW alongside nftables -> conflict FAIL!
        fs::create_dir_all(dir.path().join("etc/ufw")).expect("mkdir");
        fs::write(dir.path().join("etc/ufw/ufw.conf"), "ENABLED=yes\n").expect("write");
        assert_eq!(
            evaluate(
                &FirewallConfigCheck {
                    mode: FirewallConfigMode::SingleFirewallEnabled
                },
                &view
            )
            .status,
            Status::Fail
        );
    }

    #[test]
    fn warns_when_no_firewall_config_present() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        assert_eq!(
            evaluate(
                &FirewallConfigCheck {
                    mode: FirewallConfigMode::SingleFirewallEnabled
                },
                &view
            )
            .status,
            Status::Warn
        );
    }
}
