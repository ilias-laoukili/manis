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
    /// Optional explicit relative artifact path for SARIF 2.1.0 locations.
    #[serde(default)]
    pub artifact_uri: Option<String>,
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

    /// Returns a clean, deterministic relative URI representing the system artifact inspected
    /// by this rule (used for SARIF 2.1.0 `physicalLocation.artifactLocation.uri`).
    pub fn resolved_artifact_uri(&self) -> String {
        if let Some(ref explicit) = self.artifact_uri {
            let trimmed = explicit.trim().trim_start_matches('/');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        self.check.default_artifact_uri()
    }
}

/// Tagged union of all supported declarative check primitives.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckSpec {
    Sysctl(SysctlCheck),
    KernelConfig(KernelConfigCheck),
    MountOptions(MountOptionsCheck),
    SshdConfig(SshdConfigCheck),
    FileMeta(FileMetaCheck),
    FileContent(FileContentCheck),
    Sudoers(SudoersCheck),
    SuidSgid(SuidSgidCheck),
    PackageRepos(PackageReposCheck),
    Manual(ManualCheck),
}

impl CheckSpec {
    /// Derives a default relative artifact URI from the check specification.
    pub fn default_artifact_uri(&self) -> String {
        match self {
            Self::Sysctl(s) => s.params.first().map_or_else(
                || "etc/sysctl.conf".to_string(),
                |p| format!("proc/sys/{}", p.key.replace('.', "/")),
            ),
            Self::KernelConfig(_) => "boot/config".to_string(),
            Self::MountOptions(_) => "proc/mounts".to_string(),
            Self::SshdConfig(s) => s.file.trim_start_matches('/').to_string(),
            Self::FileMeta(s) => s.path.trim_start_matches('/').to_string(),
            Self::FileContent(s) => s
                .strict_paths
                .first()
                .or_else(|| s.paths.first())
                .or_else(|| s.pam_paths.first())
                .map_or_else(
                    || "etc".to_string(),
                    |p| p.trim_start_matches('/').replace('*', "conf"),
                ),
            Self::Sudoers(s) => s.file.trim_start_matches('/').to_string(),
            Self::SuidSgid(_) => "usr/bin".to_string(),
            Self::PackageRepos(_) => "etc/apt/sources.list".to_string(),
            Self::Manual(_) => "system/manual-control".to_string(),
        }
    }
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

/// Missing-file policy for `file_meta` checks (allows `skip` for optional backup files).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileMetaMissingPolicy {
    /// Report `WARN` (default).
    #[default]
    Warn,
    /// Report `FAIL`.
    Fail,
    /// Report `SKIP` when an optional file (e.g., `/etc/shadow-`) does not exist.
    Skip,
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
    /// Groups of alternative options where at least one option from each group must be present.
    #[serde(default)]
    pub any_of_options: Vec<Vec<String>>,
}

/// Declarative `mount_options` check primitive.
#[derive(Debug, Clone, Deserialize)]
pub struct MountOptionsCheck {
    pub mounts: Vec<MountSpec>,
}

/// Comparison operator for `sshd_config` directives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshdOp {
    /// Case-insensitive exact value match.
    Eq,
    /// Integer `<= value` (and `>= min_value` if specified).
    Le,
    /// Integer `>= value`.
    Ge,
    /// Case-insensitive membership in `values`.
    In,
    /// Case-insensitive exclusion from `values`.
    NotIn,
    /// Directive must be present and non-empty (and not `"none"`).
    Present,
    /// Comma-separated list where every algorithm must belong to `values`.
    SubsetOf,
}

/// Single OpenSSH directive assertion.
#[derive(Debug, Clone, Deserialize)]
pub struct SshdParam {
    pub key: String,
    pub op: SshdOp,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub min_value: Option<i64>,
    #[serde(default)]
    pub values: Vec<String>,
}

/// Declarative `sshd_config` check primitive (OpenSSH first-match-wins with `Include` support).
#[derive(Debug, Clone, Deserialize)]
pub struct SshdConfigCheck {
    #[serde(default = "default_sshd_config_file")]
    pub file: String,
    pub params: Vec<SshdParam>,
}

/// Declarative `file_meta` check primitive for permissions and ownership.
#[derive(Debug, Clone, Deserialize)]
pub struct FileMetaCheck {
    pub path: String,
    /// Maximum allowed octal permission mask (e.g. `"0644"`, `"0640"`, `"0600"`, `"0700"`).
    pub max_mode: String,
    /// Required owner UID (default `0` = root).
    #[serde(default)]
    pub expected_uid: u32,
    /// Allowed owner GIDs (default `[0]` = root).
    #[serde(default = "default_root_gids")]
    pub allowed_gids: Vec<u32>,
    #[serde(default)]
    pub on_missing: FileMetaMissingPolicy,
}

/// Evaluation mode for `file_content`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileContentMode {
    ShellTimeout,
    Umask,
    Regex,
    KeyValueBound,
    PasswdUidZero,
    ShadowEmptyPasswords,
    Banner,
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
    /// Directive key for `key_value_bound` mode (e.g. `PASS_MAX_DAYS`).
    #[serde(default)]
    pub key: Option<String>,
    /// Inclusive lower bound for `key_value_bound`.
    #[serde(default)]
    pub min: Option<i64>,
    /// Inclusive upper bound for `key_value_bound`.
    #[serde(default)]
    pub max: Option<i64>,
}

/// Evaluation mode for `sudoers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SudoersMode {
    ForbidBroadRootTargets,
    ForbidCommandNegations,
    RequireDefaults,
    ForbidNoPasswd,
    ForbidNoAuthenticate,
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
    /// Boolean Defaults flags that must be enabled (e.g. `["use_pty"]`) in `require_defaults` mode.
    #[serde(default)]
    pub required_defaults: Vec<String>,
    /// Key-value Defaults that must be assigned (e.g. `["logfile"]`) in `require_defaults` mode.
    #[serde(default)]
    pub required_kv_defaults: Vec<String>,
    /// Maximum allowed `timestamp_timeout` in minutes when checked in `require_defaults` mode.
    #[serde(default)]
    pub max_timestamp_timeout: Option<i64>,
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

/// Explicit non-automatable benchmark control.
#[derive(Debug, Clone, Deserialize)]
pub struct ManualCheck {
    pub verification_steps: Vec<String>,
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

fn default_sshd_config_file() -> String {
    "/etc/ssh/sshd_config".to_string()
}

fn default_root_gids() -> Vec<u32> {
    vec![0]
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
