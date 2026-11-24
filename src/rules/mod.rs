//! Embedded rule registry and profile filtering.

pub mod schema;

use crate::error::ManisError;
use schema::{ProfileSpec, ProfilesFile, RuleSpec};
use std::collections::BTreeSet;

const EMBEDDED_PROFILES: &str = include_str!("../../rules/profiles.toml");

const EMBEDDED_RULES: &[(&str, &str)] = &[
    (
        "rules/anssi/r09_kernel_sysctl.toml",
        include_str!("../../rules/anssi/r09_kernel_sysctl.toml"),
    ),
    (
        "rules/anssi/r10_disable_modules.toml",
        include_str!("../../rules/anssi/r10_disable_modules.toml"),
    ),
    (
        "rules/anssi/r12_network_ipv4.toml",
        include_str!("../../rules/anssi/r12_network_ipv4.toml"),
    ),
    (
        "rules/anssi/r13_network_ipv6.toml",
        include_str!("../../rules/anssi/r13_network_ipv6.toml"),
    ),
    (
        "rules/anssi/r18_module_signature.toml",
        include_str!("../../rules/anssi/r18_module_signature.toml"),
    ),
    (
        "rules/anssi/r20_security_primitives.toml",
        include_str!("../../rules/anssi/r20_security_primitives.toml"),
    ),
    (
        "rules/anssi/r28_partitioning.toml",
        include_str!("../../rules/anssi/r28_partitioning.toml"),
    ),
    (
        "rules/anssi/r32_session_timeout.toml",
        include_str!("../../rules/anssi/r32_session_timeout.toml"),
    ),
    (
        "rules/anssi/r36_umask.toml",
        include_str!("../../rules/anssi/r36_umask.toml"),
    ),
    (
        "rules/anssi/r40_sudo_target_users.toml",
        include_str!("../../rules/anssi/r40_sudo_target_users.toml"),
    ),
    (
        "rules/anssi/r42_sudo_negations.toml",
        include_str!("../../rules/anssi/r42_sudo_negations.toml"),
    ),
    (
        "rules/anssi/r56_suid_sgid.toml",
        include_str!("../../rules/anssi/r56_suid_sgid.toml"),
    ),
    (
        "rules/anssi/r59_trusted_repos.toml",
        include_str!("../../rules/anssi/r59_trusted_repos.toml"),
    ),
];

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
    /// or a CIS control ID (e.g. `1.5.1`).
    pub fn find_by_identifier(&self, query: &str) -> Vec<&RuleSpec> {
        // Exact canonical ID match takes priority if present.
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
    fn embedded_catalog_loads_all_13_rules_validly() {
        let reg = RuleRegistry::load_embedded().expect("embedded rules should parse");
        assert_eq!(reg.all_rules().len(), 13);
        assert!(reg.profiles().len() >= 5);
    }

    #[test]
    fn lookup_supports_canonical_anssi_and_cis_identifiers() {
        let reg = RuleRegistry::load_embedded().expect("registry");

        let by_id = reg.find_by_identifier("KERN-001");
        assert_eq!(by_id.len(), 1);
        assert_eq!(by_id[0].id, "KERN-001");

        let by_anssi = reg.find_by_identifier("r9");
        assert_eq!(by_anssi.len(), 1);
        assert_eq!(by_anssi[0].id, "KERN-001");

        let by_cis = reg.find_by_identifier("5.4.3.2");
        assert_eq!(by_cis.len(), 1);
        assert_eq!(by_cis[0].id, "AUTH-001");

        let by_cis_prefixed = reg.find_by_identifier("CIS 7.1.13");
        assert_eq!(by_cis_prefixed.len(), 1);
        assert_eq!(by_cis_prefixed[0].id, "FS-002");
    }

    #[test]
    fn profile_filtering_rejects_unknown_profile() {
        let reg = RuleRegistry::load_embedded().expect("registry");
        assert!(reg.rules_for_profile("nonexistent").is_err());
        assert_eq!(reg.rules_for_profile("all").unwrap().len(), 13);
        assert!(!reg.rules_for_profile("cis-l1-server").unwrap().is_empty());
        assert!(!reg.rules_for_profile("anssi-minimal").unwrap().is_empty());
    }
}
