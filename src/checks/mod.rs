//! Check primitive implementations and evaluation dispatch.

pub mod file_content;
pub mod file_meta;
pub mod firewall_config;
pub mod kernel_config;
pub mod manual;
pub mod mount_options;
pub mod package_repos;
pub mod package_state;
pub mod service_state;
pub mod sshd_config;
pub mod sudoers;
pub mod suid_sgid;
pub mod sysctl;
pub mod world_writable;

use crate::config::OverridesConfig;
use crate::model::{RuleResult, Status};
use crate::rules::schema::{CheckSpec, RuleSpec};
use crate::sys::SystemView;

/// Internal outcome returned by each check primitive before attaching rule metadata.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub status: Status,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub details: Vec<String>,
}

impl CheckOutcome {
    pub fn pass(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            expected: Some(expected.into()),
            actual: Some(actual.into()),
            details: Vec::new(),
        }
    }

    pub fn fail(
        expected: impl Into<String>,
        actual: impl Into<String>,
        details: Vec<String>,
    ) -> Self {
        Self {
            status: Status::Fail,
            expected: Some(expected.into()),
            actual: Some(actual.into()),
            details,
        }
    }

    pub fn warn(
        expected: impl Into<String>,
        actual: impl Into<String>,
        details: Vec<String>,
    ) -> Self {
        Self {
            status: Status::Warn,
            expected: Some(expected.into()),
            actual: Some(actual.into()),
            details,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: Status::Error,
            expected: None,
            actual: Some(message.into()),
            details: Vec::new(),
        }
    }
}

/// Evaluates a single [`RuleSpec`] against `view` using optional [`OverridesConfig`].
pub fn evaluate_rule(
    rule: &RuleSpec,
    view: &dyn SystemView,
    overrides: &OverridesConfig,
) -> RuleResult {
    let outcome = match &rule.check {
        CheckSpec::Sysctl(spec) => sysctl::evaluate(spec, view),
        CheckSpec::KernelConfig(spec) => kernel_config::evaluate(spec, view),
        CheckSpec::MountOptions(spec) => mount_options::evaluate(spec, view),
        CheckSpec::SshdConfig(spec) => sshd_config::evaluate(spec, view),
        CheckSpec::FileMeta(spec) => file_meta::evaluate(spec, view),
        CheckSpec::FileContent(spec) => file_content::evaluate(spec, view),
        CheckSpec::Sudoers(spec) => sudoers::evaluate(spec, view),
        CheckSpec::SuidSgid(spec) => {
            if overrides.suid_sgid.extra_whitelist.is_empty() {
                suid_sgid::evaluate(spec, view)
            } else {
                let mut merged = spec.clone();
                merged
                    .whitelist
                    .extend(overrides.suid_sgid.extra_whitelist.iter().cloned());
                suid_sgid::evaluate(&merged, view)
            }
        }
        CheckSpec::WorldWritable(spec) => world_writable::evaluate(spec, view),
        CheckSpec::PackageRepos(spec) => {
            if overrides.package_repos.extra_trusted_domains.is_empty() {
                package_repos::evaluate(spec, view)
            } else {
                let mut merged = spec.clone();
                merged.trusted_domains.extend(
                    overrides
                        .package_repos
                        .extra_trusted_domains
                        .iter()
                        .cloned(),
                );
                package_repos::evaluate(&merged, view)
            }
        }
        CheckSpec::PackageState(spec) => package_state::evaluate(spec, view),
        CheckSpec::ServiceState(spec) => service_state::evaluate(spec, view),
        CheckSpec::FirewallConfig(spec) => firewall_config::evaluate(spec, view),
        CheckSpec::Manual(spec) => manual::evaluate(spec),
    };

    RuleResult {
        id: rule.id.clone(),
        title: rule.title.clone(),
        status: outcome.status,
        severity: rule.severity,
        references: rule.references.clone(),
        artifact_uri: Some(rule.resolved_artifact_uri()),
        expected: outcome.expected,
        actual: outcome.actual,
        details: outcome.details,
        remediation: rule.remediation.trim().to_string(),
    }
}

/// Expands a list of virtual paths, supporting a single `*` wildcard in the final path component
/// (e.g. `/etc/profile.d/*.sh`), while recording any permission-denied directories.
pub(crate) fn expand_virtual_paths(
    view: &dyn SystemView,
    patterns: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();

    for pattern in patterns {
        if let Some((dir, glob)) = split_wildcard_pattern(pattern) {
            match view.read_dir(dir) {
                Ok(entries) => {
                    for entry in entries {
                        if entry.is_file && matches_simple_wildcard(&entry.name, glob) {
                            files.push(entry.path);
                        }
                    }
                }
                Err(err) if err.is_permission_denied() => {
                    unreadable.push(format!("{dir}: {err}"));
                }
                Err(_) => {}
            }
        } else {
            files.push(pattern.clone());
        }
    }

    files.sort();
    files.dedup();
    unreadable.sort();
    unreadable.dedup();
    (files, unreadable)
}

fn split_wildcard_pattern(pattern: &str) -> Option<(&str, &str)> {
    if !pattern.contains('*') {
        return None;
    }
    let idx = pattern.rfind('/')?;
    let dir = if idx == 0 { "/" } else { &pattern[..idx] };
    let file_glob = &pattern[idx + 1..];
    Some((dir, file_glob))
}

fn matches_simple_wildcard(name: &str, pattern: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        name.len() >= prefix.len() + suffix.len()
            && name.starts_with(prefix)
            && name.ends_with(suffix)
    } else {
        name == pattern
    }
}
