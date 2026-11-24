use clap::Parser;
use manis::cli::{AuditArgs, Cli, Command, ExplainArgs, ListArgs};
use manis::engine::run_audit;
use manis::error::ManisError;
use manis::report::{render_report, table};
use manis::rules::RuleRegistry;
use manis::sys::RootFsSystemView;
use std::fs;
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
    let registry = RuleRegistry::load_embedded()?;
    match cli.command {
        Command::Audit(args) => run_audit_cmd(&registry, &args),
        Command::List(args) => run_list_cmd(&registry, &args),
        Command::Explain(args) => run_explain_cmd(&registry, &args),
    }
}

fn run_audit_cmd(registry: &RuleRegistry, args: &AuditArgs) -> Result<ExitCode, ManisError> {
    let view = match &args.root {
        Some(path) => RootFsSystemView::from_root(path)?,
        None => RootFsSystemView::live(),
    };

    let report = run_audit(registry, &args.profile, &view)?;
    let rendered = render_report(&report, args.format)?;

    if let Some(ref output_path) = args.output {
        fs::write(output_path, &rendered).map_err(|e| {
            ManisError::Io(format!(
                "failed to write report to '{}': {e}",
                output_path.display()
            ))
        })?;
    } else {
        print!("{rendered}");
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
    print!("{rendered}");
    Ok(ExitCode::SUCCESS)
}

fn run_explain_cmd(registry: &RuleRegistry, args: &ExplainArgs) -> Result<ExitCode, ManisError> {
    let matches = registry.find_by_identifier(&args.rule_id);
    if matches.is_empty() {
        return Err(ManisError::UnknownRule(args.rule_id.clone()));
    }
    print!("{}", table::render_explain(&matches));
    Ok(ExitCode::SUCCESS)
}
