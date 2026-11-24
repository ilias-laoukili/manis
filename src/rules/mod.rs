//! Embedded rule registry and profile filtering.

pub mod schema;

use crate::error::ManisError;
use schema::{ProfileSpec, ProfilesFile, RuleSpec};
use std::collections::BTreeSet;

const EMBEDDED_PROFILES: &str = include_str!("../../rules/profiles.toml");

macro_rules! embed_rules {
    ($($path:literal),* $(,)?) => {
        &[
            $(
                ($path, include_str!(concat!("../../", $path))),
            )*
        ]
    };
}

const EMBEDDED_RULES: &[(&str, &str)] = embed_rules!(
    "rules/auth/auth_001_tmout.toml",
    "rules/auth/auth_002_umask.toml",
    "rules/auth/auth_003_pass_max_days.toml",
    "rules/auth/auth_004_pass_min_days.toml",
    "rules/auth/auth_005_uid_zero.toml",
    "rules/auth/auth_006_empty_shadow.toml",
    "rules/auth/auth_007_issue_banner.toml",
    "rules/auth/auth_008_issue_net_banner.toml",
    "rules/filesystem/file_001_passwd_perms.toml",
    "rules/filesystem/file_002_passwd_bak_perms.toml",
    "rules/filesystem/file_003_group_perms.toml",
    "rules/filesystem/file_004_group_bak_perms.toml",
    "rules/filesystem/file_005_shadow_perms.toml",
    "rules/filesystem/file_006_shadow_bak_perms.toml",
    "rules/filesystem/file_007_gshadow_perms.toml",
    "rules/filesystem/file_008_gshadow_bak_perms.toml",
    "rules/filesystem/file_009_crontab_perms.toml",
    "rules/filesystem/file_010_cron_d_perms.toml",
    "rules/filesystem/fs_001_partitioning.toml",
    "rules/filesystem/fs_002_suid_sgid.toml",
    "rules/filesystem/fs_003_cramfs_disabled.toml",
    "rules/filesystem/fs_004_freevxfs_disabled.toml",
    "rules/filesystem/fs_005_hfs_disabled.toml",
    "rules/filesystem/fs_006_hfsplus_disabled.toml",
    "rules/filesystem/fs_007_jffs2_disabled.toml",
    "rules/filesystem/fs_008_udf_disabled.toml",
    "rules/kernel/kern_001_sysctl.toml",
    "rules/kernel/kern_002_disable_modules.toml",
    "rules/kernel/kern_003_module_signature.toml",
    "rules/kernel/kern_004_security_primitives.toml",
    "rules/kernel/kern_005_ptrace_scope.toml",
    "rules/kernel/kern_006_core_dumps.toml",
    "rules/kernel/kern_007_fs_protections.toml",
    "rules/manual/man_001_firmware_boot.toml",
    "rules/manual/man_002_disk_encryption.toml",
    "rules/manual/man_003_physical_access.toml",
    "rules/network/net_001_ipv4.toml",
    "rules/network/net_002_ipv6.toml",
    "rules/packages/pkg_001_trusted_repos.toml",
    "rules/ssh/ssh_001_config_perms.toml",
    "rules/ssh/ssh_002_permit_root_login.toml",
    "rules/ssh/ssh_003_permit_empty_passwords.toml",
    "rules/ssh/ssh_004_max_auth_tries.toml",
    "rules/ssh/ssh_005_login_grace_time.toml",
    "rules/ssh/ssh_006_client_alive.toml",
    "rules/ssh/ssh_007_log_level.toml",
    "rules/ssh/ssh_008_rhosts_hostbased.toml",
    "rules/ssh/ssh_009_user_env_pam.toml",
    "rules/ssh/ssh_010_forwarding_banner.toml",
    "rules/ssh/ssh_011_strong_crypto.toml",
    "rules/sudo/sudo_001_target_users.toml",
    "rules/sudo/sudo_002_negations.toml",
    "rules/sudo/sudo_003_defaults.toml",
    "rules/sudo/sudo_004_no_nopasswd.toml",
    "rules/sudo/sudo_005_reauth.toml",
);

/// In-memory catalog of all embedded profiles and rules, sorted deterministically by rule ID.
#[derive(Debug, Clone)]
pub struct RuleRegistry {
    profiles: Vec<ProfileSpec>,
    rules: Vec<RuleSpec>,
}

impl RuleRegistry {
    /// Loads and validates all embedded TOML profiles and rules.
    pub fn load_embedded() -> Result<Self, ManisError> {
        let profiles_file: ProfilesFile = toml::from_str(EMBEDDED_PROFILES).map_err(|e| {
            ManisError::Config(format!("failed to parse embedded profiles.toml: {e}"))
        })?;
        let valid_profiles: BTreeSet<&str> = profiles_file
            .profiles
            .iter()
            .map(|p| p.name.as_str())
            .collect();

        let mut rules = Vec::with_capacity(EMBEDDED_RULES.len());
        let mut seen_ids = BTreeSet::new();

        for (source, raw) in EMBEDDED_RULES {
            let rule: RuleSpec = toml::from_str(raw).map_err(|e| {
                ManisError::Config(format!("failed to parse embedded rule '{source}': {e}"))
            })?;
            if rule.id.trim().is_empty() {
                return Err(ManisError::Config(format!(
                    "rule '{source}' has an empty id"
                )));
            }
            if !seen_ids.insert(rule.id.clone()) {
                return Err(ManisError::Config(format!(
                    "duplicate embedded rule id '{}'",
                    rule.id
                )));
            }
            if rule.remediation.trim().is_empty() {
                return Err(ManisError::Config(format!(
                    "rule '{}' is missing remediation guidance",
                    rule.id
                )));
            }
            for prof in &rule.profiles {
                if !valid_profiles.contains(prof.as_str()) {
                    return Err(ManisError::Config(format!(
                        "rule '{}' references unknown profile '{prof}'",
                        rule.id
                    )));
                }
            }
            rules.push(rule);
        }

        // Deterministic canonical order by rule ID.
        rules.sort_by(|a, b| a.id.cmp(&b.id));

        Ok(Self {
            profiles: profiles_file.profiles,
            rules,
        })
    }

    /// Returns all registered compliance profiles.
    pub fn profiles(&self) -> &[ProfileSpec] {
        &self.profiles
    }

    /// Returns all rules in deterministic sorted order.
    pub fn all_rules(&self) -> &[RuleSpec] {
        &self.rules
    }

    /// Selects rules matching `profile_name` (`"all"` returns every embedded rule).
    pub fn rules_for_profile(&self, profile_name: &str) -> Result<Vec<&RuleSpec>, ManisError> {
        if !self.profiles.iter().any(|p| p.name == profile_name) {
            return Err(ManisError::UnknownProfile(profile_name.to_string()));
        }
        if profile_name == "all" {
            return Ok(self.rules.iter().collect());
        }
        Ok(self
            .rules
            .iter()
            .filter(|r| r.profiles.iter().any(|p| p == profile_name))
            .collect())
    }

    /// Finds rules matching a canonical ID (e.g. `KERN-001`), an ANSSI alias (e.g. `R9`),
    /// or a CIS control ID (e.g. `5.1.20`).
    pub fn find_by_identifier(&self, query: &str) -> Vec<&RuleSpec> {
        if let Some(exact) = self
            .rules
            .iter()
            .find(|r| r.id.eq_ignore_ascii_case(query.trim()))
        {
            return vec![exact];
        }
        self.rules
            .iter()
            .filter(|r| r.matches_identifier(query))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_loads_all_55_rules_validly() {
        let reg = RuleRegistry::load_embedded().expect("embedded rules should parse");
        assert_eq!(reg.all_rules().len(), 55);
        assert!(reg.profiles().len() >= 5);
        // Every rule produces a non-empty relative artifact URI for SARIF 2.1.0.
        for rule in reg.all_rules() {
            let uri = rule.resolved_artifact_uri();
            assert!(!uri.is_empty() && !uri.starts_with('/'));
        }
    }

    #[test]
    fn lookup_supports_canonical_anssi_and_cis_identifiers() {
        let reg = RuleRegistry::load_embedded().expect("registry");

        assert_eq!(reg.find_by_identifier("SSH-002")[0].id, "SSH-002");
        assert_eq!(reg.find_by_identifier("5.1.20")[0].id, "SSH-002");
        assert_eq!(reg.find_by_identifier("CIS 7.1.5")[0].id, "FILE-005");
        assert!(reg
            .find_by_identifier("R9")
            .iter()
            .any(|r| r.id == "KERN-001"));
    }

    #[test]
    fn profile_filtering_rejects_unknown_profile() {
        let reg = RuleRegistry::load_embedded().expect("registry");
        assert!(reg.rules_for_profile("nonexistent").is_err());
        assert_eq!(reg.rules_for_profile("all").unwrap().len(), 55);
        assert!(reg.rules_for_profile("cis-l1-server").unwrap().len() >= 45);
        assert!(reg.rules_for_profile("anssi-minimal").unwrap().len() >= 10);
    }
}
