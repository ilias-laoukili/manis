//! Deterministic rule evaluation engine.

use crate::checks::evaluate_rule;
use crate::error::ManisError;
use crate::model::{AuditReport, AuditSummary};
use crate::rules::RuleRegistry;
use crate::sys::SystemView;

/// Schema version emitted in structured JSON reports.
pub const REPORT_SCHEMA_VERSION: &str = "0.1";

/// Runs all rules belonging to `profile` against `view` and returns a deterministic [`AuditReport`].
pub fn run_audit(
    registry: &RuleRegistry,
    profile: &str,
    view: &dyn SystemView,
) -> Result<AuditReport, ManisError> {
    let selected = registry.rules_for_profile(profile)?;
    let mut results: Vec<_> = selected
        .into_iter()
        .map(|rule| evaluate_rule(rule, view))
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
