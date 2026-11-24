//! Deterministic JSON report formatter.

use crate::error::ManisError;
use crate::model::AuditReport;

/// Serializes `report` to deterministic, pretty-printed JSON.
pub fn render(report: &AuditReport) -> Result<String, ManisError> {
    let mut json = serde_json::to_string_pretty(report)
        .map_err(|e| ManisError::Io(format!("failed to serialize JSON report: {e}")))?;
    json.push('\n');
    Ok(json)
}
