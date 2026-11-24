//! Declarative TOML rule and profile schema definitions.

use crate::model::{BenchmarkRefs, Severity};
use serde::{Deserialize, Serialize};

/// Top-level profile catalog parsed from `rules/profiles.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfilesFile {
    pub profiles: Vec<ProfileSpec>,
}

/// Metadata describing a named compliance profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSpec {
    pub name: String,
    pub description: String,
}

/// Declarative rule specification parsed from an embedded TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub profiles: Vec<String>,
    #[serde(default)]
    pub references: BenchmarkRefs,
    pub remediation: String,
    pub check: CheckSpec,
}

impl RuleSpec {
    /// Returns `true` if `query` matches this rule's canonical ID, an ANSSI alias, or a CIS ID
    /// (case-insensitive).
    pub fn matches_identifier(&self, query: &str) -> bool {
        let q = query.trim();
        if self.id.eq_ignore_ascii_case(q) {
            return true;
        }
        if self
            .references
            .anssi
            .iter()
            .any(|a| a.eq_ignore_ascii_case(q))
        {
            return true;
        }
        if self.references.cis.iter().any(|c| {
            c.eq_ignore_ascii_case(q)
                || q.strip_prefix("CIS ")
                    .or_else(|| q.strip_prefix("cis "))
                    .or_else(|| q.strip_prefix("CIS-"))
                    .or_else(|| q.strip_prefix("cis-"))
                    .is_some_and(|stripped| c.eq_ignore_ascii_case(stripped.trim()))
        }) {
            return true;
        }
        false
    }
}

/// Tagged union of all supported declarative check primitives.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckSpec {
    Sysctl(SysctlCheck),
    KernelConfig(KernelConfigCheck),
    MountOptions(MountOptionsCheck),
    FileContent(FileContentCheck),
    Sudoers(SudoersCheck),
    SuidSgid(SuidSgidCheck),
    PackageRepos(PackageReposCheck),
}

/// Behavior when a checked parameter is absent or unreadable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MissingPolicy {
    /// Report `WARN` (default — never silently `PASS`).
    #[default]
    Warn,
    /// Report `FAIL`.
    Fail,
}

/// Comparison operator for `sysctl` parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SysctlOp {
    Eq,
    Ge,
    Le,
    In,
}

/// Single `sysctl` parameter assertion.
#[derive(Debug, Clone, Deserialize)]
pub struct SysctlParam {
    pub key: String,
    pub op: SysctlOp,
    /// Expected scalar value for `eq`, `ge`, or `le`.
    #[serde(default)]
    pub value: Option<String>,
    /// Allowed values for `in`.
    #[serde(default)]
    pub values: Vec<String>,
}

/// Declarative `sysctl` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct SysctlCheck {
    pub params: Vec<SysctlParam>,
    #[serde(default)]
    pub on_missing: MissingPolicy,
    /// If any token is present in `/proc/cmdline`, the rule immediately passes (e.g. `ipv6.disable=1`).
    #[serde(default)]
    pub pass_if_cmdline_contains: Vec<String>,
    /// If any of these sysctl assertions holds, the rule immediately passes (e.g. `disable_ipv6 = 1`).
    #[serde(default)]
    pub pass_if_sysctl: Vec<SysctlParam>,
}

/// Single kernel build configuration assertion (`CONFIG_*`).
#[derive(Debug, Clone, Deserialize)]
pub struct KernelOption {
    pub name: String,
    pub expected: String,
}

/// Declarative `kernel_config` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct KernelConfigCheck {
    pub options: Vec<KernelOption>,
}

/// Mount point requirement for `mount_options`.
#[derive(Debug, Clone, Deserialize)]
pub struct MountSpec {
    pub path: String,
    /// If `true`, the mount point must exist as a dedicated entry in `/proc/mounts`.
    /// If `false`, options are enforced only when it is mounted separately.
    #[serde(default)]
    pub required_separate: bool,
    /// Mount options that must all be present.
    #[serde(default)]
    pub required_options: Vec<String>,
    /// Groups of alternative options where at least one option from each group must be present
    /// (e.g. `[["hidepid=1", "hidepid=2", "hidepid=invisible", "hidepid=ptraceable"]]`).
    #[serde(default)]
    pub any_of_options: Vec<Vec<String>>,
}

/// Declarative `mount_options` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct MountOptionsCheck {
    pub mounts: Vec<MountSpec>,
}

/// Evaluation mode for `file_content`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileContentMode {
    ShellTimeout,
    Umask,
    Regex,
}

/// Regex matching mode when `file_content.mode == "regex"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegexMatchMode {
    #[default]
    AnyLine,
    NoLine,
}

/// Declarative `file_content` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct FileContentCheck {
    pub mode: FileContentMode,
    /// Target file paths (supports single `*` wildcard in basename, e.g. `/etc/profile.d/*.sh`).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Variable name for `shell_timeout` (default: `TMOUT`).
    #[serde(default = "default_tmout_var")]
    pub var: String,
    /// Maximum allowed timeout in seconds for `shell_timeout`.
    #[serde(default = "default_max_timeout")]
    pub max_seconds: u64,
    /// Require the variable to be marked `readonly` for `shell_timeout`.
    #[serde(default = "default_true")]
    pub require_readonly: bool,
    /// Strict files for `umask` (e.g. `/etc/login.defs`, `/etc/profile`).
    #[serde(default)]
    pub strict_paths: Vec<String>,
    /// Allowed octal umask values for `strict_paths` (e.g. `["077"]`).
    #[serde(default)]
    pub strict_allowed: Vec<String>,
    /// Allowed octal umask values for `paths` and `pam_paths` (e.g. `["027", "077"]`).
    #[serde(default)]
    pub standard_allowed: Vec<String>,
    /// PAM session files checked for `pam_umask.so umask=...`.
    #[serde(default)]
    pub pam_paths: Vec<String>,
    /// Regular expression pattern for `regex` mode.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Matching mode for `regex` mode.
    #[serde(default)]
    pub match_mode: RegexMatchMode,
}

/// Evaluation mode for `sudoers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SudoersMode {
    ForbidBroadRootTargets,
    ForbidCommandNegations,
}

/// Declarative `sudoers` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct SudoersCheck {
    pub mode: SudoersMode,
    #[serde(default = "default_sudoers_file")]
    pub file: String,
    #[serde(default = "default_sudoers_dir")]
    pub include_dir: String,
    /// Principals intentionally exempted from broad-root-target checks (e.g. `["root"]`).
    #[serde(default)]
    pub ignore_users: Vec<String>,
}

/// Declarative `suid_sgid` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct SuidSgidCheck {
    #[serde(default = "default_suid_roots")]
    pub search_roots: Vec<String>,
    #[serde(default = "default_suid_skips")]
    pub skip_dirs: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default = "default_true")]
    pub forbid_world_writable: bool,
}

/// Declarative `package_repos` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct PackageReposCheck {
    pub trusted_domains: Vec<String>,
    #[serde(default = "default_true")]
    pub check_gpg: bool,
}

const fn default_true() -> bool {
    true
}

fn default_tmout_var() -> String {
    "TMOUT".to_string()
}

const fn default_max_timeout() -> u64 {
    600
}

fn default_sudoers_file() -> String {
    "/etc/sudoers".to_string()
}

fn default_sudoers_dir() -> String {
    "/etc/sudoers.d".to_string()
}

fn default_suid_roots() -> Vec<String> {
    vec!["/".to_string()]
}

fn default_suid_skips() -> Vec<String> {
    vec![
        "/proc".to_string(),
        "/sys".to_string(),
        "/dev".to_string(),
        "/run".to_string(),
    ]
}
