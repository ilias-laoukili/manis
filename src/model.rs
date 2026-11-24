//! Core domain models for rules, statuses, severities, and audit reports.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Result status of evaluating a single hardening rule.
///
/// Missing or unreadable system values must never silently map to [`Status::Pass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    /// Checked value is present and compliant.
    Pass,
    /// Checked value is present and non-compliant.
    Fail,
    /// Value could not be fully verified (e.g., missing key or insufficient permissions).
    Warn,
    /// Rule was explicitly waived or is not applicable to the target OS.
    Skip,
    /// Control cannot be reliably automated and requires manual verification.
    Manual,
    /// Unexpected internal or collector failure.
    Error,
}

impl Status {
    /// Returns the canonical uppercase label used in CLI tables and structured reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::Skip => "SKIP",
            Self::Manual => "MANUAL",
            Self::Error => "ERROR",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Severity level assigned to a hardening control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns the canonical lowercase label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!(
                "invalid severity '{s}' (expected: low, medium, high, critical)"
            )),
        }
    }
}

/// Verified cross-framework benchmark references for a hardening rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkRefs {
    /// CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 control identifiers.
    #[serde(default)]
    pub cis: Vec<String>,
    /// ANSSI-BP-028 v2.0 recommendation identifiers (e.g., `R9`, `R28`).
    #[serde(default)]
    pub anssi: Vec<String>,
    /// NIST SP 800-53 Rev. 5 control identifiers (e.g., `CM-6`, `AC-6`).
    #[serde(default)]
    pub nist: Vec<String>,
}

impl BenchmarkRefs {
    /// Formats a concise, international-oriented reference label for terminal tables
    /// (e.g. `CIS 1.5.1, R9` or `R10`).
    pub fn compact_label(&self) -> String {
        let mut parts = Vec::new();
        if let Some(first_cis) = self.cis.first() {
            if self.cis.len() > 1 {
                parts.push(format!("CIS {first_cis}+"));
            } else {
                parts.push(format!("CIS {first_cis}"));
            }
        }
        for anssi in &self.anssi {
            parts.push(anssi.clone());
        }
        if parts.is_empty() {
            for nist in &self.nist {
                parts.push(format!("NIST {nist}"));
            }
        }
        if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Evaluation outcome for a single hardening rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleResult {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub severity: Severity,
    pub references: BenchmarkRefs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
    pub remediation: String,
}

/// Aggregate counts of rule evaluation statuses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub skip: usize,
    pub manual: usize,
    pub error: usize,
}

impl AuditSummary {
    /// Computes aggregate counts from a slice of [`RuleResult`]s.
    pub fn from_results(results: &[RuleResult]) -> Self {
        let mut summary = Self {
            total: results.len(),
            ..Self::default()
        };
        for r in results {
            match r.status {
                Status::Pass => summary.pass += 1,
                Status::Fail => summary.fail += 1,
                Status::Warn => summary.warn += 1,
                Status::Skip => summary.skip += 1,
                Status::Manual => summary.manual += 1,
                Status::Error => summary.error += 1,
            }
        }
        summary
    }
}

/// Complete, deterministic audit report produced by the evaluation engine.
///
/// Intentionally omits wall-clock timestamps so repeated runs against the same
/// fixture produce byte-for-byte identical JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub schema_version: String,
    pub tool_version: String,
    pub profile: String,
    pub root: String,
    pub summary: AuditSummary,
    pub results: Vec<RuleResult>,
}

impl AuditReport {
    /// Returns `true` if any rule failed with severity greater than or equal to `threshold`.
    pub fn has_failure_at_or_above(&self, threshold: Severity) -> bool {
        self.results
            .iter()
            .any(|r| r.status == Status::Fail && r.severity >= threshold)
    }

    /// Returns `true` if any rule produced an internal [`Status::Error`].
    pub fn has_errors(&self) -> bool {
        self.results.iter().any(|r| r.status == Status::Error)
    }
}
