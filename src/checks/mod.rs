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

/// Returns every path a check may read: the paths written in the rule plus the implicit
/// defaults of its primitive (e.g. `/var/lib/dpkg/status`, APT source files, UFW configuration).
///
/// Wildcards are kept as written (e.g. `/etc/profile.d/*.sh`), and release-dependent kernel
/// paths use `*` for the release. Profile invariants such as `linux-generic` having no
/// distribution-specific dependency are enforced on this list.
pub fn referenced_paths(check: &CheckSpec) -> Vec<String> {
    let owned = |paths: &[&str]| paths.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut paths = match check {
        CheckSpec::Sysctl(spec) => {
            let mut paths: Vec<String> = spec
                .params
                .iter()
                .chain(&spec.pass_if_sysctl)
                .map(|param| sysctl::sysctl_key_to_path(&param.key))
                .collect();
            if !spec.pass_if_cmdline_contains.is_empty() {
                paths.push("/proc/cmdline".to_string());
            }
            paths
        }
        CheckSpec::KernelConfig(_) => owned(&[
            "/boot/config-*",
            "/proc/config.gz",
            "/lib/modules/*/build/.config",
            "/proc/sys/kernel/osrelease",
        ]),
        CheckSpec::MountOptions(_) => owned(&["/proc/mounts"]),
        CheckSpec::SshdConfig(spec) => vec![spec.file.clone()],
        CheckSpec::FileMeta(spec) => vec![spec.path.clone()],
        CheckSpec::FileContent(spec) => spec
            .paths
            .iter()
            .chain(&spec.strict_paths)
            .chain(&spec.pam_paths)
            .cloned()
            .collect(),
        CheckSpec::Sudoers(spec) => vec![spec.file.clone(), spec.include_dir.clone()],
        CheckSpec::SuidSgid(spec) => spec.search_roots.clone(),
        CheckSpec::WorldWritable(spec) => spec.search_roots.clone(),
        CheckSpec::PackageRepos(_) => [
            package_repos::APT_LIST_PATTERNS,
            package_repos::APT_DEB822_PATTERNS,
            package_repos::YUM_REPO_PATTERNS,
            package_repos::APT_CONF_PATTERNS,
            package_repos::YUM_GLOBAL_CONF_PATHS,
        ]
        .concat()
        .iter()
        .map(ToString::to_string)
        .collect(),
        CheckSpec::PackageState(spec) => vec![spec.dpkg_status_path.clone()],
        CheckSpec::ServiceState(spec) => vec![spec.systemd_dir.clone()],
        CheckSpec::FirewallConfig(_) => owned(firewall_config::CONFIG_PATHS),
        CheckSpec::Manual(_) => Vec::new(),
    };
    paths.sort();
    paths.dedup();
    paths
}

/// Expands a list of virtual paths, supporting a single `*` wildcard in the final path component
/// (e.g. `/etc/profile.d/*.sh`), while recording any permission-denied directories.
///
/// Symlinked entries are kept so their target is read (resolved inside the root in `--root`
/// mode). A link whose target cannot be reached (dangling, loop) is recorded as unreadable,
/// never silently skipped.
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
                        if !matches_simple_wildcard(&entry.name, glob) {
                            continue;
                        }
                        if entry.is_file {
                            files.push(entry.path);
                        } else if entry.is_symlink {
                            if view.exists(&entry.path) {
                                files.push(entry.path);
                            } else {
                                unreadable.push(format!(
                                    "{}: symbolic link target unavailable",
                                    entry.path
                                ));
                            }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::rules::schema::PackageReposCheck;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use tempfile::tempdir;

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, content).expect("write");
    }

    fn link(root: &Path, rel: &str, target: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        symlink(target, path).expect("symlink");
    }

    fn debian_repos_spec() -> PackageReposCheck {
        PackageReposCheck {
            trusted_domains: vec!["debian.org".to_string()],
            check_gpg: true,
        }
    }

    #[test]
    fn expands_symlinked_drop_ins_and_reports_unreachable_targets() {
        let root = tempdir().expect("tempdir");
        write(root.path(), "etc/apt/sources.list.d/real.sources", "x");
        write(root.path(), "srv/repos/extra.sources", "x");
        link(
            root.path(),
            "etc/apt/sources.list.d/extra.sources",
            "/srv/repos/extra.sources",
        );
        link(
            root.path(),
            "etc/apt/sources.list.d/dangling.sources",
            "/srv/repos/missing.sources",
        );
        link(
            root.path(),
            "etc/apt/sources.list.d/loop.sources",
            "loop.sources",
        );
        link(
            root.path(),
            "etc/apt/sources.list.d/other.list",
            "/srv/repos/extra.sources",
        );

        let view = RootFsSystemView::from_root(root.path()).expect("view");
        let (files, unreadable) =
            expand_virtual_paths(&view, &["/etc/apt/sources.list.d/*.sources".to_string()]);
        assert_eq!(
            files,
            vec![
                "/etc/apt/sources.list.d/extra.sources",
                "/etc/apt/sources.list.d/real.sources",
            ]
        );
        assert_eq!(
            unreadable,
            vec![
                "/etc/apt/sources.list.d/dangling.sources: symbolic link target unavailable",
                "/etc/apt/sources.list.d/loop.sources: symbolic link target unavailable",
            ]
        );
    }

    #[test]
    fn symlinked_untrusted_apt_source_is_inspected() {
        let root = tempdir().expect("tempdir");
        write(
            root.path(),
            "srv/repos/evil.sources",
            "Types: deb\nURIs: http://evil.example.com/debian\nSuites: bookworm\nComponents: main\n",
        );
        link(
            root.path(),
            "etc/apt/sources.list.d/evil.sources",
            "/srv/repos/evil.sources",
        );

        let view = RootFsSystemView::from_root(root.path()).expect("view");
        let out = package_repos::evaluate(&debian_repos_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert!(out.details[0].contains("http://evil.example.com/debian"));
    }

    #[test]
    fn dangling_apt_source_link_warns_instead_of_passing() {
        // Typical offline image: a drop-in points into /run, which only exists at runtime.
        let root = tempdir().expect("tempdir");
        write(
            root.path(),
            "etc/apt/sources.list.d/debian.sources",
            "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm\nComponents: main\n",
        );
        link(
            root.path(),
            "etc/apt/sources.list.d/cloud.sources",
            "/run/cloud/cloud.sources",
        );

        let view = RootFsSystemView::from_root(root.path()).expect("view");
        let out = package_repos::evaluate(&debian_repos_spec(), &view);
        assert_eq!(out.status, Status::Warn);
        assert!(out
            .details
            .iter()
            .any(|d| d.contains("cloud.sources: symbolic link target unavailable")));
    }
}
