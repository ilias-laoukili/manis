//! Output report formatters (`table` and `json`).

pub mod json;
pub mod table;

use crate::error::ManisError;
use crate::model::AuditReport;
use clap::ValueEnum;

/// Supported report output formats in `v0.1.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
}

/// Renders an [`AuditReport`] into the requested [`OutputFormat`].
pub fn render_report(report: &AuditReport, format: OutputFormat) -> Result<String, ManisError> {
    match format {
        OutputFormat::Table => Ok(table::render(report)),
        OutputFormat::Json => json::render(report),
    }
}
