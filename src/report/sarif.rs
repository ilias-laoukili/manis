//! Deterministic SARIF 2.1.0 report formatter compatible with GitHub Code Scanning.

use crate::error::ManisError;
use crate::model::{AuditReport, RuleResult, Severity, Status};
use serde::Serialize;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_INFO_URI: &str = "https://github.com/ilias-laoukili/manis";

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    help: SarifHelp,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifDefaultConfig,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifHelp {
    text: String,
    markdown: String,
}

#[derive(Serialize)]
struct SarifDefaultConfig {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

/// Renders an [`AuditReport`] as deterministic, GitHub Code Scanning-compatible SARIF 2.1.0 JSON.
pub fn render(report: &AuditReport) -> Result<String, ManisError> {
    let rules: Vec<SarifRule> = report.results.iter().map(build_sarif_rule).collect();

    let results: Vec<SarifResult> = report
        .results
        .iter()
        .filter(|r| matches!(r.status, Status::Fail | Status::Warn | Status::Error))
        .map(build_sarif_result)
        .collect();

    let log = SarifLog {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "manis",
                    version: report.tool_version.clone(),
                    information_uri: TOOL_INFO_URI,
                    rules,
                },
            },
            results,
        }],
    };

    let mut json = serde_json::to_string_pretty(&log)
        .map_err(|e| ManisError::Io(format!("failed to serialize SARIF report: {e}")))?;
    json.push('\n');
    Ok(json)
}

fn build_sarif_rule(r: &RuleResult) -> SarifRule {
    let mut tags = vec!["security".to_string(), "linux-hardening".to_string()];
    for cis in &r.references.cis {
        tags.push(format!("CIS-{cis}"));
    }
    for anssi in &r.references.anssi {
        tags.push(format!("ANSSI-{anssi}"));
    }
    for nist in &r.references.nist {
        tags.push(format!("NIST-{nist}"));
    }

    let refs = r.references.compact_label();
    let help_md = format!(
        "### {} — {}\n\n**References:** {}\n\n**Remediation:**\n```\n{}\n```",
        r.id, r.title, refs, r.remediation
    );

    SarifRule {
        id: r.id.clone(),
        short_description: SarifMessage {
            text: r.title.clone(),
        },
        help: SarifHelp {
            text: r.remediation.clone(),
            markdown: help_md,
        },
        default_configuration: SarifDefaultConfig {
            level: severity_to_sarif_level(r.severity),
        },
        properties: SarifRuleProperties {
            tags,
            security_severity: severity_to_score(r.severity),
        },
    }
}

fn build_sarif_result(r: &RuleResult) -> SarifResult {
    let level = match r.status {
        Status::Fail => severity_to_sarif_level(r.severity),
        Status::Warn => "warning",
        Status::Error => "error",
        Status::Pass | Status::Skip | Status::Manual => "note",
    };

    let mut msg_parts = vec![format!("[{}] {}", r.status.as_str(), r.title)];
    if let Some(ref exp) = r.expected {
        msg_parts.push(format!("Expected: {exp}"));
    }
    if let Some(ref act) = r.actual {
        msg_parts.push(format!("Actual: {act}"));
    }
    if !r.details.is_empty() {
        msg_parts.push(format!("Details: {}", r.details.join("; ")));
    }

    let uri = r
        .artifact_uri
        .as_deref()
        .map(|s| s.trim_start_matches('/'))
        .filter(|s| !s.is_empty())
        .unwrap_or("etc/os-release")
        .to_string();

    SarifResult {
        rule_id: r.id.clone(),
        level,
        message: SarifMessage {
            text: msg_parts.join(" | "),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation { uri },
                region: SarifRegion { start_line: 1 },
            },
        }],
    }
}

const fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

const fn severity_to_score(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.0",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
    }
}
