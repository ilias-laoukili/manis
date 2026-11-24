//! Output report formatters (`table`, `json`, `sarif`, `markdown`).

pub mod json;
pub mod markdown;
pub mod sarif;
pub mod table;

use crate::error::ManisError;
use crate::model::AuditReport;
use clap::ValueEnum;

/// Supported audit report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
    Markdown,
}

/// Supported diff report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiffFormat {
    Table,
    Json,
    Markdown,
}

/// Renders an [`AuditReport`] into the requested [`OutputFormat`].
pub fn render_report(report: &AuditReport, format: OutputFormat) -> Result<String, ManisError> {
    match format {
        OutputFormat::Table => Ok(table::render(report)),
        OutputFormat::Json => json::render(report),
        OutputFormat::Sarif => sarif::render(report),
        OutputFormat::Markdown => Ok(markdown::render(report)),
    }
}
