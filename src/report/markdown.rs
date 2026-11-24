//! Deterministic GitHub-flavored Markdown report formatter.

use crate::model::{AuditReport, Status};
use std::fmt::Write as _;

/// Renders an [`AuditReport`] as deterministic GitHub-flavored Markdown.
pub fn render(report: &AuditReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# manis Hardening Audit Report\n");
    let _ = writeln!(
        out,
        "- **Version:** `{}`\n- **Profile:** `{}`\n- **Root:** `{}`\n",
        report.tool_version, report.profile, report.root
    );

    let s = &report.summary;
    out.push_str("## Summary\n\n");
    out.push_str("| Total | PASS | FAIL | WARN | SKIP | MANUAL | ERROR |\n");
    out.push_str("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {} | {} | {} |\n",
        s.total, s.pass, s.fail, s.warn, s.skip, s.manual, s.error
    );

    out.push_str("## Results\n\n");
    out.push_str("| ID | Status | Severity | Refs | Title |\n");
    out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
    for r in &report.results {
        let _ = writeln!(
            out,
            "| `{}` | **{}** | `{}` | {} | {} |",
            r.id,
            r.status.as_str(),
            r.severity.as_str(),
            escape_md(&r.references.compact_label()),
            escape_md(&r.title)
        );
    }

    let findings: Vec<_> = report
        .results
        .iter()
        .filter(|r| matches!(r.status, Status::Fail | Status::Warn | Status::Error))
        .collect();

    if !findings.is_empty() {
        out.push_str("\n## Findings\n\n");
        for item in findings {
            let _ = writeln!(
                out,
                "<details>\n<summary><strong>[{}] {}</strong> ({}) — {}</summary>\n",
                item.status.as_str(),
                item.id,
                item.severity.as_str(),
                escape_md(&item.title)
            );
            if let Some(ref exp) = item.expected {
                let _ = writeln!(out, "- **Expected:** `{}`", exp.replace('`', "'"));
            }
            if let Some(ref act) = item.actual {
                let _ = writeln!(out, "- **Actual:** `{}`", act.replace('`', "'"));
            }
            if !item.details.is_empty() {
                out.push_str("- **Details:**\n");
                for detail in &item.details {
                    let _ = writeln!(out, "  - {}", escape_md(detail));
                }
            }
            if item.status == Status::Fail && !item.remediation.is_empty() {
                out.push_str("\n**Remediation:**\n\n```text\n");
                out.push_str(&item.remediation);
                out.push_str("\n```\n");
            }
            out.push_str("\n</details>\n\n");
        }
    }

    out
}

fn escape_md(raw: &str) -> String {
    raw.replace('|', "\\|")
}
