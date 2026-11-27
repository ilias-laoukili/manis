//! Human-readable aligned terminal table reporter.

use crate::model::{AuditReport, Status};
use crate::rules::schema::{ProfileSpec, RuleSpec};
use std::fmt::Write as _;

/// Renders an [`AuditReport`] as a deterministic, aligned plain-text table with failure details.
pub fn render(report: &AuditReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "manis {} | profile: {} | root: {}",
        report.tool_version, report.profile, report.root
    );
    out.push('\n');

    let rows: Vec<[String; 5]> = report
        .results
        .iter()
        .map(|r| {
            [
                r.id.clone(),
                r.status.as_str().to_string(),
                r.severity.as_str().to_string(),
                r.references.compact_label(),
                r.title.clone(),
            ]
        })
        .collect();

    render_grid(
        &mut out,
        &["ID", "STATUS", "SEVERITY", "REFS", "TITLE"],
        &rows,
    );

    let s = &report.summary;
    let _ = writeln!(
        out,
        "\nSummary: total={} pass={} fail={} warn={} skip={} manual={} error={}",
        s.total, s.pass, s.fail, s.warn, s.skip, s.manual, s.error
    );

    let findings: Vec<_> = report
        .results
        .iter()
        .filter(|r| matches!(r.status, Status::Fail | Status::Warn | Status::Error))
        .collect();

    if !findings.is_empty() {
        out.push_str("\nFindings:\n");
        for item in findings {
            let _ = writeln!(
                out,
                "\n[{}] {} ({}) - {}",
                item.status.as_str(),
                item.id,
                item.severity.as_str(),
                item.title
            );
            if let Some(ref exp) = item.expected {
                let _ = writeln!(out, "  Expected:    {exp}");
            }
            if let Some(ref act) = item.actual {
                let _ = writeln!(out, "  Actual:      {act}");
            }
            if !item.details.is_empty() {
                out.push_str("  Details:\n");
                for detail in &item.details {
                    let _ = writeln!(out, "    - {detail}");
                }
            }
            if item.status == Status::Fail && !item.remediation.is_empty() {
                out.push_str("  Remediation:\n");
                for line in item.remediation.lines() {
                    let _ = writeln!(out, "    {line}");
                }
            }
        }
    }

    out
}

/// Renders the `manis list` output for profiles and rules.
pub fn render_rule_list(
    profiles: Option<&[ProfileSpec]>,
    rules: &[&RuleSpec],
    selected_profile: Option<&str>,
) -> String {
    let mut out = String::new();

    if let Some(profs) = profiles {
        out.push_str("Profiles:\n");
        let name_width = profs.iter().map(|p| p.name.len()).max().unwrap_or(0);
        for prof in profs {
            let _ = writeln!(
                out,
                "  {:<width$}  {}",
                prof.name,
                prof.description,
                width = name_width
            );
        }
        out.push('\n');
    }

    if let Some(name) = selected_profile {
        let _ = writeln!(out, "Rules in profile '{name}' ({}):", rules.len());
    } else {
        let _ = writeln!(out, "Rules ({}):", rules.len());
    }
    out.push('\n');

    let rows: Vec<[String; 5]> = rules
        .iter()
        .map(|r| {
            [
                r.id.clone(),
                r.severity.as_str().to_string(),
                r.references.compact_label(),
                r.profiles.join(","),
                r.title.clone(),
            ]
        })
        .collect();

    render_grid(
        &mut out,
        &["ID", "SEVERITY", "REFS", "PROFILES", "TITLE"],
        &rows,
    );

    out
}

/// Renders the `manis explain <RULE_ID>` output for one or more matched rules.
pub fn render_explain(rules: &[&RuleSpec]) -> String {
    let mut out = String::new();
    for (idx, rule) in rules.iter().enumerate() {
        if idx > 0 {
            out.push_str("\n------------------------------------------------------------\n\n");
        }
        let _ = writeln!(out, "{} - {}", rule.id, rule.title);
        let _ = writeln!(out, "Severity:    {}", rule.severity.as_str());
        let _ = writeln!(out, "Profiles:    {}", rule.profiles.join(", "));

        let cis = if rule.references.cis.is_empty() {
            "none".to_string()
        } else {
            rule.references.cis.join(", ")
        };
        let anssi = if rule.references.anssi.is_empty() {
            "none".to_string()
        } else {
            rule.references.anssi.join(", ")
        };
        let nist = if rule.references.nist.is_empty() {
            "none".to_string()
        } else {
            rule.references.nist.join(", ")
        };

        let _ = writeln!(out, "References:");
        let _ = writeln!(out, "  CIS (Ubuntu 24.04 v1.0.0): {cis}");
        let _ = writeln!(out, "  ANSSI-BP-028 v2.0:         {anssi}");
        let _ = writeln!(out, "  NIST SP 800-53 Rev. 5:     {nist}");
        let _ = writeln!(out, "\nDescription:\n  {}", rule.description.trim());
        let _ = writeln!(out, "\nRemediation:");
        for line in rule.remediation.trim().lines() {
            let _ = writeln!(out, "  {line}");
        }
    }
    out
}

fn render_grid<const N: usize>(out: &mut String, headers: &[&str; N], rows: &[[String; N]]) {
    let mut widths = [0usize; N];
    for i in 0..N {
        widths[i] = headers[i].len();
    }
    for row in rows {
        for i in 0..N {
            widths[i] = widths[i].max(row[i].len());
        }
    }

    // Header
    for (i, header) in headers.iter().enumerate() {
        if i + 1 == N {
            let _ = writeln!(out, "{header}");
        } else {
            let _ = write!(out, "{:<width$}  ", header, width = widths[i]);
        }
    }

    // Separator
    for (i, width) in widths.iter().enumerate() {
        let sep = "-".repeat(*width);
        if i + 1 == N {
            let _ = writeln!(out, "{sep}");
        } else {
            let _ = write!(out, "{sep}  ");
        }
    }

    // Rows
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i + 1 == N {
                let _ = writeln!(out, "{cell}");
            } else {
                let _ = write!(out, "{:<width$}  ", cell, width = widths[i]);
            }
        }
    }
}
