//! Deterministic rule evaluation engine with `manis.toml` waiver & override support.

use crate::checks::evaluate_rule;
use crate::config::{SimpleDate, UserConfig, WaiverState};
use crate::error::ManisError;
use crate::model::{AuditReport, AuditSummary, RuleResult, Status};
use crate::rules::RuleRegistry;
use crate::sys::SystemView;

/// Schema version emitted in structured JSON reports.
pub const REPORT_SCHEMA_VERSION: &str = "0.2";

/// Runs all rules belonging to `profile` against `view` using default empty configuration.
pub fn run_audit(
    registry: &RuleRegistry,
    profile: &str,
    view: &dyn SystemView,
) -> Result<AuditReport, ManisError> {
    run_audit_with_config(registry, profile, view, &UserConfig::default(), None)
}

/// Runs all rules belonging to `profile` against `view`, applying waivers and overrides from
/// `config`. When `today` is `None`, waiver expiration uses [`SimpleDate::today_utc`].
pub fn run_audit_with_config(
    registry: &RuleRegistry,
    profile: &str,
    view: &dyn SystemView,
    config: &UserConfig,
    today: Option<SimpleDate>,
) -> Result<AuditReport, ManisError> {
    let selected = registry.rules_for_profile(profile)?;
    let reference_date = today.unwrap_or_else(SimpleDate::today_utc);

    let mut results: Vec<RuleResult> = selected
        .into_iter()
        .map(|rule| match config.waiver_state(&rule.id, reference_date) {
            WaiverState::Active { reason } => RuleResult {
                id: rule.id.clone(),
                title: rule.title.clone(),
                status: Status::Skip,
                severity: rule.severity,
                references: rule.references.clone(),
                artifact_uri: Some(rule.resolved_artifact_uri()),
                expected: None,
                actual: Some("waived via config".to_string()),
                details: vec![format!("waived via config: {reason}")],
                remediation: rule.remediation.trim().to_string(),
            },
            WaiverState::Expired { reason, expires } => {
                let mut res = evaluate_rule(rule, view, &config.overrides);
                res.details.push(format!(
                    "waiver expired on {expires} (original reason: {reason})"
                ));
                res
            }
            WaiverState::None => evaluate_rule(rule, view, &config.overrides),
        })
        .collect();

    // Guarantee deterministic rule ordering regardless of input registration order.
    results.sort_by(|a, b| a.id.cmp(&b.id));

    let summary = AuditSummary::from_results(&results);

    Ok(AuditReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        profile: profile.to_string(),
        root: view.display_root().to_string(),
        summary,
        results,
    })
}
