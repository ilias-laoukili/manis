use clap::Parser;
use manis::cli::{AuditArgs, Cli, Command, DiffArgs, ExplainArgs, ListArgs};
use manis::config::UserConfig;
use manis::diff::{compute_diff, load_report, render_diff};
use manis::engine::run_audit_with_config;
use manis::error::ManisError;
use manis::report::{render_report, table};
use manis::rules::RuleRegistry;
use manis::sys::RootFsSystemView;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("manis: {err}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: Cli) -> Result<ExitCode, ManisError> {
    match cli.command {
        Command::Audit(args) => {
            let registry = RuleRegistry::load_embedded()?;
            run_audit_cmd(&registry, &args)
        }
        Command::List(args) => {
            let registry = RuleRegistry::load_embedded()?;
            run_list_cmd(&registry, &args)
        }
        Command::Explain(args) => {
            let registry = RuleRegistry::load_embedded()?;
            run_explain_cmd(&registry, &args)
        }
        Command::Diff(args) => run_diff_cmd(&args),
    }
}

fn run_audit_cmd(registry: &RuleRegistry, args: &AuditArgs) -> Result<ExitCode, ManisError> {
    let view = match &args.root {
        Some(path) => RootFsSystemView::from_root(path)?,
        None => RootFsSystemView::live(),
    };

    let config = match &args.config {
        Some(path) => UserConfig::load(path)?,
        None => UserConfig::default(),
    };

    let report = run_audit_with_config(registry, &args.profile, &view, &config, None)?;
    let rendered = render_report(&report, args.format)?;
    if emit_output(args.output.as_deref(), &rendered)? {
        return Ok(ExitCode::SUCCESS);
    }

    if report.has_errors() {
        Ok(ExitCode::from(2))
    } else if report.has_failure_at_or_above(args.fail_on) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_list_cmd(registry: &RuleRegistry, args: &ListArgs) -> Result<ExitCode, ManisError> {
    let rendered = if let Some(ref profile) = args.profile {
        let rules = registry.rules_for_profile(profile)?;
        table::render_rule_list(None, &rules, Some(profile))
    } else {
        let rules: Vec<_> = registry.all_rules().iter().collect();
        table::render_rule_list(Some(registry.profiles()), &rules, None)
    };
    let _ = write_stdout(&rendered)?;
    Ok(ExitCode::SUCCESS)
}

fn run_explain_cmd(registry: &RuleRegistry, args: &ExplainArgs) -> Result<ExitCode, ManisError> {
    let matches = registry.find_by_identifier(&args.rule_id);
    if matches.is_empty() {
        return Err(ManisError::UnknownRule(args.rule_id.clone()));
    }
    let _ = write_stdout(&table::render_explain(&matches))?;
    Ok(ExitCode::SUCCESS)
}

fn run_diff_cmd(args: &DiffArgs) -> Result<ExitCode, ManisError> {
    let baseline = load_report(&args.baseline)?;
    let current = load_report(&args.current)?;
    let diff = compute_diff(&baseline, &current);
    let rendered = render_diff(&diff, args.format)?;
    if emit_output(args.output.as_deref(), &rendered)? {
        return Ok(ExitCode::SUCCESS);
    }

    if !args.no_fail && diff.has_regressions() {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Writes output to a file or stdout. Returns `Ok(true)` when stdout closed with `BrokenPipe`.
fn emit_output(output_path: Option<&Path>, content: &str) -> Result<bool, ManisError> {
    if let Some(path) = output_path {
        fs::write(path, content).map_err(|e| {
            ManisError::Io(format!(
                "failed to write report to '{}': {e}",
                path.display()
            ))
        })?;
        Ok(false)
    } else {
        write_stdout(content)
    }
}

/// Writes `content` to stdout, returning `Ok(true)` on [`io::ErrorKind::BrokenPipe`]
/// so pipelines such as `manis audit ... | head` exit cleanly without panicking.
fn write_stdout(content: &str) -> Result<bool, ManisError> {
    let mut stdout = io::stdout().lock();
    match stdout.write_all(content.as_bytes()) {
        Ok(()) => Ok(false),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(true),
        Err(err) => Err(ManisError::Io(format!("failed to write to stdout: {err}"))),
    }
}
