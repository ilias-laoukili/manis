//! Command-line interface definitions (`clap` derive).

use crate::model::Severity;
use crate::report::{DiffFormat, OutputFormat};
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
    /// Compare two JSON audit reports for hardening drift.
    Diff(DiffArgs),
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Compliance profile to evaluate (cis-l1-server, all, anssi-minimal,
    /// anssi-intermediary, anssi-reinforced, linux-generic).
    #[arg(long, default_value = "cis-l1-server")]
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

    /// Apply `<ROOT>/.manis-meta.toml` (simulated modes, ownership, unreadable files and
    /// symlinks for test fixtures). The file rewrites the audited tree's own metadata: never use
    /// this flag on untrusted images.
    #[arg(long, requires = "root")]
    pub fixture_meta: bool,

    /// Optional user configuration file (`manis.toml`) for waivers and overrides.
    #[arg(long)]
    pub config: Option<PathBuf>,

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
    /// Canonical rule ID (e.g. SSH-002), ANSSI alias (e.g. R9), or CIS ID (e.g. 5.1.20).
    pub rule_id: String,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Path to the baseline JSON audit report.
    pub baseline: PathBuf,

    /// Path to the current JSON audit report.
    pub current: PathBuf,

    /// Output format for the drift report.
    #[arg(long, value_enum, default_value_t = DiffFormat::Table)]
    pub format: DiffFormat,

    /// Exit with status 0 even when hardening regressions are detected.
    #[arg(long)]
    pub no_fail: bool,

    /// Write the diff report to a file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
}
