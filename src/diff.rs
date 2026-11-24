//! Baseline hardening drift detection (`manis diff <baseline.json> <current.json>`).

use crate::error::ManisError;
use crate::model::{AuditReport, Severity, Status};
use crate::report::DiffFormat;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// A single rule whose status changed between baseline and current reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffEntry {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub baseline_status: Option<Status>,
    pub current_status: Option<Status>,
}

/// Aggregate summary of drift between two reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffSummary {
    pub regressions: usize,
    pub fixed: usize,
    pub changed: usize,
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
}

/// Complete deterministic drift report between a baseline and current audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffReport {
    pub baseline_profile: String,
    pub current_profile: String,
    pub summary: DiffSummary,
    pub regressions: Vec<DiffEntry>,
    pub fixed: Vec<DiffEntry>,
    pub changed: Vec<DiffEntry>,
    pub added: Vec<DiffEntry>,
    pub removed: Vec<DiffEntry>,
}

impl DiffReport {
    /// Returns `true` when at least one regression (`PASS/WARN/SKIP -> FAIL`) occurred.
    pub fn has_regressions(&self) -> bool {
        !self.regressions.is_empty()
    }
}

/// Loads a JSON [`AuditReport`] from disk.
pub fn load_report(path: &Path) -> Result<AuditReport, ManisError> {
    let raw = fs::read_to_string(path)
        .map_err(|e| ManisError::Io(format!("failed to read report '{}': {e}", path.display())))?;
    serde_json::from_str(&raw).map_err(|e| {
        ManisError::Config(format!(
            "invalid audit report JSON '{}': {e}",
            path.display()
        ))
    })
}

/// Computes deterministic hardening drift between `baseline` and `current`.
pub fn compute_diff(baseline: &AuditReport, current: &AuditReport) -> DiffReport {
    let base_map: BTreeMap<&str, _> = baseline
        .results
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();
    let curr_map: BTreeMap<&str, _> = current.results.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut regressions = Vec::new();
    let mut fixed = Vec::new();
    let mut changed = Vec::new();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = 0usize;

    for (id, curr) in &curr_map {
        match base_map.get(id) {
            Some(base) => {
                if base.status == curr.status {
                    unchanged += 1;
                    continue;
                }
                let entry = DiffEntry {
                    id: curr.id.clone(),
                    title: curr.title.clone(),
                    severity: curr.severity,
                    baseline_status: Some(base.status),
                    current_status: Some(curr.status),
                };
                if curr.status == Status::Fail
                    && matches!(base.status, Status::Pass | Status::Warn | Status::Skip)
                {
                    regressions.push(entry);
                } else if base.status == Status::Fail && curr.status == Status::Pass {
                    fixed.push(entry);
                } else {
                    changed.push(entry);
                }
            }
            None => {
                added.push(DiffEntry {
                    id: curr.id.clone(),
                    title: curr.title.clone(),
                    severity: curr.severity,
                    baseline_status: None,
                    current_status: Some(curr.status),
                });
            }
        }
    }

    for (id, base) in &base_map {
        if !curr_map.contains_key(id) {
            removed.push(DiffEntry {
                id: base.id.clone(),
                title: base.title.clone(),
                severity: base.severity,
                baseline_status: Some(base.status),
                current_status: None,
            });
        }
    }

    let summary = DiffSummary {
        regressions: regressions.len(),
        fixed: fixed.len(),
        changed: changed.len(),
        added: added.len(),
        removed: removed.len(),
        unchanged,
    };

    DiffReport {
        baseline_profile: baseline.profile.clone(),
        current_profile: current.profile.clone(),
        summary,
        regressions,
        fixed,
        changed,
        added,
        removed,
    }
}

/// Renders a [`DiffReport`] into `table`, `json`, or `markdown`.
pub fn render_diff(diff: &DiffReport, format: DiffFormat) -> Result<String, ManisError> {
    match format {
        DiffFormat::Json => {
            let mut json = serde_json::to_string_pretty(diff)
                .map_err(|e| ManisError::Io(format!("failed to serialize diff JSON: {e}")))?;
            json.push('\n');
            Ok(json)
        }
        DiffFormat::Table => Ok(render_diff_table(diff)),
        DiffFormat::Markdown => Ok(render_diff_markdown(diff)),
    }
}

fn render_diff_table(diff: &DiffReport) -> String {
    let mut out = String::new();
    let s = &diff.summary;
    let _ = writeln!(
        out,
        "manis diff | baseline: {} -> current: {}",
        diff.baseline_profile, diff.current_profile
    );
    let _ = writeln!(
        out,
        "Summary: regressions={} fixed={} changed={} added={} removed={} unchanged={}\n",
        s.regressions, s.fixed, s.changed, s.added, s.removed, s.unchanged
    );

    append_table_section(&mut out, "Regressions", &diff.regressions);
    append_table_section(&mut out, "Fixed", &diff.fixed);
    append_table_section(&mut out, "Other Changes", &diff.changed);
    append_table_section(&mut out, "Added Rules", &diff.added);
    append_table_section(&mut out, "Removed Rules", &diff.removed);

    if s.regressions == 0 && s.fixed == 0 && s.changed == 0 && s.added == 0 && s.removed == 0 {
        out.push_str("No hardening drift detected.\n");
    }

    out
}

fn append_table_section(out: &mut String, title: &str, entries: &[DiffEntry]) {
    if entries.is_empty() {
        return;
    }
    let _ = writeln!(out, "{title} ({}):", entries.len());
    for e in entries {
        let from = e.baseline_status.map_or("-", Status::as_str);
        let to = e.current_status.map_or("-", Status::as_str);
        let _ = writeln!(
            out,
            "  {:<10} {:<8} {:<6} -> {:<6}  {}",
            e.id,
            e.severity.as_str(),
            from,
            to,
            e.title
        );
    }
    out.push('\n');
}

fn render_diff_markdown(diff: &DiffReport) -> String {
    let mut out = String::new();
    let s = &diff.summary;
    out.push_str("# manis Hardening Drift Report\n\n");
    out.push_str("| Regressions | Fixed | Changed | Added | Removed | Unchanged |\n");
    out.push_str("| ---: | ---: | ---: | ---: | ---: | ---: |\n");
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {} | {} |\n",
        s.regressions, s.fixed, s.changed, s.added, s.removed, s.unchanged
    );

    append_md_section(&mut out, "Regressions", &diff.regressions);
    append_md_section(&mut out, "Fixed", &diff.fixed);
    append_md_section(&mut out, "Other Changes", &diff.changed);
    append_md_section(&mut out, "Added Rules", &diff.added);
    append_md_section(&mut out, "Removed Rules", &diff.removed);

    out
}

fn append_md_section(out: &mut String, title: &str, entries: &[DiffEntry]) {
    if entries.is_empty() {
        return;
    }
    let _ = writeln!(out, "## {title}\n");
    out.push_str("| ID | Severity | Baseline | Current | Title |\n");
    out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
    for e in entries {
        let from = e.baseline_status.map_or("-", Status::as_str);
        let to = e.current_status.map_or("-", Status::as_str);
        let _ = writeln!(
            out,
            "| `{}` | `{}` | {} | {} | {} |",
            e.id,
            e.severity.as_str(),
            from,
            to,
            e.title.replace('|', "\\|")
        );
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuditSummary, BenchmarkRefs, RuleResult};

    fn make_report(items: &[(&str, Status, Severity)]) -> AuditReport {
        let results: Vec<RuleResult> = items
            .iter()
            .map(|(id, status, severity)| RuleResult {
                id: (*id).to_string(),
                title: format!("Rule {id}"),
                status: *status,
                severity: *severity,
                references: BenchmarkRefs::default(),
                artifact_uri: None,
                expected: None,
                actual: None,
                details: Vec::new(),
                remediation: "fix".to_string(),
            })
            .collect();
        let summary = AuditSummary::from_results(&results);
        AuditReport {
            schema_version: "0.2".to_string(),
            tool_version: "0.2.0".to_string(),
            profile: "cis-l1-server".to_string(),
            root: "/".to_string(),
            summary,
            results,
        }
    }

    #[test]
    fn classifies_regressions_fixed_changed_added_removed() {
        let base = make_report(&[
            ("R1", Status::Pass, Severity::High),
            ("R2", Status::Fail, Severity::Medium),
            ("R3", Status::Warn, Severity::Low),
            ("R4", Status::Pass, Severity::Low),
            ("R5", Status::Pass, Severity::Low),
        ]);
        let curr = make_report(&[
            ("R1", Status::Fail, Severity::High),   // regression
            ("R2", Status::Pass, Severity::Medium), // fixed
            ("R3", Status::Pass, Severity::Low),    // changed
            ("R4", Status::Pass, Severity::Low),    // unchanged
            ("R6", Status::Fail, Severity::High),   // added
        ]);

        let diff = compute_diff(&base, &curr);
        assert!(diff.has_regressions());
        assert_eq!(diff.summary.regressions, 1);
        assert_eq!(diff.summary.fixed, 1);
        assert_eq!(diff.summary.changed, 1);
        assert_eq!(diff.summary.added, 1);
        assert_eq!(diff.summary.removed, 1);
        assert_eq!(diff.summary.unchanged, 1);
    }
}
