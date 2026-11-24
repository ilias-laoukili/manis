//! User configuration (`manis.toml`): rule waivers with optional expiration and
//! additive whitelist/trusted-domain overrides.

use crate::error::ManisError;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Lightweight calendar date (`YYYY-MM-DD`) used for deterministic waiver expiration checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SimpleDate {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl SimpleDate {
    /// Constructs a validated calendar date.
    pub fn new(year: i32, month: u32, day: u32) -> Result<Self, ManisError> {
        if !(1..=12).contains(&month) {
            return Err(ManisError::Config(format!(
                "invalid month '{month}' in date (expected 01..12)"
            )));
        }
        let max_day = days_in_month(year, month);
        if day == 0 || day > max_day {
            return Err(ManisError::Config(format!(
                "invalid day '{day}' for {year:04}-{month:02}"
            )));
        }
        Ok(Self { year, month, day })
    }

    /// Parses an ISO-8601 `YYYY-MM-DD` date string.
    pub fn parse(raw: &str) -> Result<Self, ManisError> {
        let mut parts = raw.trim().split('-');
        let (Some(y), Some(m), Some(d), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ManisError::Config(format!(
                "invalid date '{raw}' (expected YYYY-MM-DD)"
            )));
        };
        if y.len() != 4 || m.len() != 2 || d.len() != 2 {
            return Err(ManisError::Config(format!(
                "invalid date '{raw}' (expected YYYY-MM-DD)"
            )));
        }
        let year = y
            .parse::<i32>()
            .map_err(|_| ManisError::Config(format!("invalid year in date '{raw}'")))?;
        let month = m
            .parse::<u32>()
            .map_err(|_| ManisError::Config(format!("invalid month in date '{raw}'")))?;
        let day = d
            .parse::<u32>()
            .map_err(|_| ManisError::Config(format!("invalid day in date '{raw}'")))?;
        Self::new(year, month, day)
    }

    /// Returns today's UTC date using the standard library clock (Howard Hinnant's civil-from-days).
    pub fn today_utc() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let days = i64::try_from(secs / 86_400).unwrap_or(0);
        civil_from_unix_days(days)
    }
}

impl fmt::Display for SimpleDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn civil_from_unix_days(days_since_epoch: i64) -> SimpleDate {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = i32::try_from(y + i64::from(m <= 2)).unwrap_or(1970);
    let month = u32::try_from(m).unwrap_or(1);
    let day = u32::try_from(d).unwrap_or(1);
    SimpleDate { year, month, day }
}

/// Raw TOML representation of `manis.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
struct RawUserConfig {
    #[serde(default)]
    waivers: BTreeMap<String, RawWaiverEntry>,
    #[serde(default)]
    overrides: OverridesConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct RawWaiverEntry {
    reason: String,
    #[serde(default)]
    expires: Option<String>,
}

/// Validated rule waiver entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiver {
    pub reason: String,
    pub expires: Option<SimpleDate>,
}

/// Result of resolving a waiver for a rule against a reference date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaiverState<'a> {
    None,
    Active {
        reason: &'a str,
    },
    Expired {
        reason: &'a str,
        expires: SimpleDate,
    },
}

/// Additive overrides for check primitives (e.g. organization-specific SUID binaries or mirrors).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OverridesConfig {
    #[serde(default)]
    pub suid_sgid: SuidSgidOverride,
    #[serde(default)]
    pub package_repos: PackageReposOverride,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SuidSgidOverride {
    #[serde(default)]
    pub extra_whitelist: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PackageReposOverride {
    #[serde(default)]
    pub extra_trusted_domains: Vec<String>,
}

/// Validated user configuration loaded via `--config <path>`.
#[derive(Debug, Clone, Default)]
pub struct UserConfig {
    /// Waivers indexed by uppercase canonical rule ID.
    pub waivers: BTreeMap<String, Waiver>,
    pub overrides: OverridesConfig,
}

impl UserConfig {
    /// Loads and validates a `manis.toml` file from disk.
    pub fn load(path: &Path) -> Result<Self, ManisError> {
        let raw = fs::read_to_string(path).map_err(|e| {
            ManisError::Config(format!("failed to read config '{}': {e}", path.display()))
        })?;
        Self::parse(&raw)
    }

    /// Parses and validates a `manis.toml` string.
    pub fn parse(raw: &str) -> Result<Self, ManisError> {
        let parsed: RawUserConfig = toml::from_str(raw)
            .map_err(|e| ManisError::Config(format!("invalid manis.toml: {e}")))?;

        let mut waivers = BTreeMap::new();
        for (rule_id, entry) in parsed.waivers {
            let reason = entry.reason.trim().to_string();
            if reason.is_empty() {
                return Err(ManisError::Config(format!(
                    "waiver for rule '{rule_id}' must specify a non-empty 'reason'"
                )));
            }
            let expires = match entry.expires {
                Some(ref raw_date) => Some(SimpleDate::parse(raw_date)?),
                None => None,
            };
            waivers.insert(
                rule_id.trim().to_ascii_uppercase(),
                Waiver { reason, expires },
            );
        }

        Ok(Self {
            waivers,
            overrides: parsed.overrides,
        })
    }

    /// Resolves whether `rule_id` has an active or expired waiver on `today`.
    pub fn waiver_state(&self, rule_id: &str, today: SimpleDate) -> WaiverState<'_> {
        let key = rule_id.to_ascii_uppercase();
        let Some(waiver) = self.waivers.get(&key) else {
            return WaiverState::None;
        };
        if let Some(exp) = waiver.expires {
            if today > exp {
                return WaiverState::Expired {
                    reason: &waiver.reason,
                    expires: exp,
                };
            }
        }
        WaiverState::Active {
            reason: &waiver.reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dates_and_civil_conversion_accurately() {
        assert_eq!(
            civil_from_unix_days(0),
            SimpleDate {
                year: 1970,
                month: 1,
                day: 1
            }
        );
        assert_eq!(
            civil_from_unix_days(20_512),
            SimpleDate {
                year: 2026,
                month: 2,
                day: 28
            }
        );
        assert!(SimpleDate::parse("2026-02-29").is_err());
        assert!(SimpleDate::parse("2024-02-29").is_ok());
    }

    #[test]
    fn resolves_active_and_expired_waivers_deterministically() {
        let cfg = UserConfig::parse(
            r#"
[waivers.KERN-002]
reason = "eBPF agent requires runtime module loading"
expires = "2026-06-01"

[waivers.SSH-001]
reason = "Legacy bastion exemption"

[overrides.suid_sgid]
extra_whitelist = ["/opt/corp/helper"]

[overrides.package_repos]
extra_trusted_domains = ["packages.internal.corp"]
"#,
        )
        .expect("parse config");

        let before = SimpleDate::parse("2026-05-15").unwrap();
        let on_day = SimpleDate::parse("2026-06-01").unwrap();
        let after = SimpleDate::parse("2026-06-02").unwrap();

        assert!(matches!(
            cfg.waiver_state("KERN-002", before),
            WaiverState::Active { .. }
        ));
        assert!(matches!(
            cfg.waiver_state("KERN-002", on_day),
            WaiverState::Active { .. }
        ));
        assert!(matches!(
            cfg.waiver_state("KERN-002", after),
            WaiverState::Expired { .. }
        ));
        assert!(matches!(
            cfg.waiver_state("SSH-001", after),
            WaiverState::Active { .. }
        ));
        assert_eq!(
            cfg.overrides.suid_sgid.extra_whitelist,
            vec!["/opt/corp/helper"]
        );
        assert_eq!(
            cfg.overrides.package_repos.extra_trusted_domains,
            vec!["packages.internal.corp"]
        );
    }

    #[test]
    fn rejects_empty_waiver_reason() {
        let err = UserConfig::parse(
            r#"
[waivers.KERN-002]
reason = "   "
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("reason"));
    }
}
