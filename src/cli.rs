//! Command-line interface definitions (`clap` derive).

use crate::model::Severity;
use crate::report::OutputFormat;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Declarative, read-only Linux hardening audit CLI mapped to CIS Benchmarks,
/// ANSSI-BP-028 v2.0, and NIST SP 800-53.
#[derive(Debug, Parser)]
#[command(name = "manis", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run hardening compliance checks against the live host or a `--root` fixture.
    Audit(AuditArgs),
    /// List available hardening rules and profiles.
    List(ListArgs),
    /// Show benchmark references, description, and remediation for a rule.
    Explain(ExplainArgs),
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Compliance profile to evaluate (e.g. all, cis-l1-server, anssi-minimal,
    /// anssi-intermediary, anssi-reinforced).
    #[arg(long, default_value = "all")]
    pub profile: String,

    /// Output format for the audit report.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Minimum failure severity that triggers exit code 1.
    #[arg(long, default_value = "low")]
    pub fail_on: Severity,

    /// Alternate filesystem root directory for offline or fixture auditing.
    #[arg(long)]
    pub root: Option<PathBuf>,

    /// Write the report to a file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Optional profile filter.
    #[arg(long)]
    pub profile: Option<String>,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// Canonical rule ID (e.g. KERN-001), ANSSI alias (e.g. R9), or CIS ID (e.g. 5.4.3.2).
    pub rule_id: String,
}
