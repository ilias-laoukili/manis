use manis::config::{SimpleDate, UserConfig};
use manis::engine::{run_audit, run_audit_with_config};
use manis::model::{AuditReport, Severity, Status};
use manis::report::{render_report, OutputFormat};
use manis::rules::RuleRegistry;
use manis::sys::RootFsSystemView;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn manis_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_manis"))
}

#[test]
fn ubuntu_hardened_fixture_passes_cis_l1_server_and_all_profiles_with_exit_0() {
    let fixture = fixture_path("ubuntu-hardened");

    // Default profile is `cis-l1-server`.
    let cis_out = manis_bin()
        .args([
            "audit",
            "--format",
            "json",
            "--root",
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("run manis audit (default cis-l1-server)");
    assert_eq!(
        cis_out.status.code(),
        Some(0),
        "expected exit 0 on ubuntu-hardened cis-l1-server, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&cis_out.stdout),
        String::from_utf8_lossy(&cis_out.stderr)
    );
    let cis_report: AuditReport =
        serde_json::from_slice(&cis_out.stdout).expect("valid CIS JSON report");
    assert_eq!(cis_report.profile, "cis-l1-server");
    assert!(cis_report.summary.total >= 90);
    assert_eq!(cis_report.summary.fail, 0);
    assert_eq!(cis_report.summary.warn, 0);
    assert_eq!(cis_report.summary.pass, cis_report.summary.total);

    // Full `all` profile: 100 automated PASS + 3 explicit MANUAL controls, 0 FAIL, exit 0.
    let all_out = manis_bin()
        .args([
            "audit",
            "--profile",
            "all",
            "--format",
            "json",
            "--root",
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("run manis audit --profile all");
    assert_eq!(all_out.status.code(), Some(0));
    let all_report: AuditReport =
        serde_json::from_slice(&all_out.stdout).expect("valid all JSON report");
    assert_eq!(all_report.summary.total, 103);
    assert_eq!(all_report.summary.pass, 100);
    assert_eq!(all_report.summary.manual, 3);
    assert_eq!(all_report.summary.fail, 0);
    assert_eq!(all_report.summary.warn, 0);
}

#[test]
fn ubuntu_default_fixture_fails_unhardened_rules_and_reports_expected_actual_remediation() {
    let fixture = fixture_path("ubuntu-default");
    let output = manis_bin()
        .args([
            "audit",
            "--profile",
            "all",
            "--format",
            "json",
            "--root",
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("run manis audit");

    assert_eq!(output.status.code(), Some(1));

    let report: AuditReport =
        serde_json::from_slice(&output.stdout).expect("valid JSON AuditReport");
    assert_eq!(report.summary.total, 103);
    assert!(report.summary.fail >= 75);
    assert_eq!(report.summary.manual, 3);

    for res in report.results.iter().filter(|r| r.status == Status::Fail) {
        assert!(
            res.expected.as_deref().is_some_and(|s| !s.is_empty()),
            "FAIL rule {} must include expected value",
            res.id
        );
        assert!(
            res.actual.as_deref().is_some_and(|s| !s.is_empty()),
            "FAIL rule {} must include actual value",
            res.id
        );
        assert_ne!(
            res.remediation.trim(),
            "",
            "FAIL rule {} must include remediation",
            res.id
        );
        assert!(
            res.artifact_uri.as_deref().is_some_and(|u| !u.is_empty()),
            "FAIL rule {} must include artifact_uri for SARIF",
            res.id
        );
    }

    // Verify FS-002 (R56) enforces BOTH whitelist and world-writable checks.
    let fs002 = report
        .results
        .iter()
        .find(|r| r.id == "FS-002")
        .expect("FS-002 present");
    assert_eq!(fs002.status, Status::Fail);
    assert_eq!(fs002.severity, Severity::Critical);
    let joined_details = fs002.details.join("\n");
    assert!(joined_details.contains("/usr/local/bin/custom-suid"));
    assert!(joined_details.contains("/usr/local/bin/debug-helper"));
    assert!(joined_details.contains("world-writable"));

    // Verify new v0.3.0 blocks fail on unhardened ubuntu-default.
    for id in [
        "BOOT-001", "BOOT-002", "MAC-001", "MAC-002", "MAC-003", "SVC-001", "SVC-003", "SVC-004",
        "SVC-011", "FW-002", "AUTH-010", "AUTH-014", "AUTH-017", "AUTH-018", "FS-009", "LOG-001",
        "LOG-003", "LOG-013", "LOG-014",
    ] {
        let status = report
            .results
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("rule {id} missing"))
            .status;
        assert_eq!(
            status,
            Status::Fail,
            "expected {id} to FAIL on ubuntu-default"
        );
    }
}

#[test]
fn json_sarif_and_markdown_outputs_are_deterministic_and_sarif_includes_locations() {
    let registry = RuleRegistry::load_embedded().expect("registry");
    let view = RootFsSystemView::from_root(fixture_path("ubuntu-default")).expect("view");

    let r1 = run_audit(&registry, "cis-l1-server", &view).expect("run 1");
    let r2 = run_audit(&registry, "cis-l1-server", &view).expect("run 2");

    for format in [
        OutputFormat::Json,
        OutputFormat::Sarif,
        OutputFormat::Markdown,
    ] {
        let out1 = render_report(&r1, format).expect("render 1");
        let out2 = render_report(&r2, format).expect("render 2");
        assert_eq!(out1, out2, "format {format:?} must be deterministic");
    }

    let sarif_str = render_report(&r1, OutputFormat::Sarif).expect("sarif");
    let sarif: serde_json::Value = serde_json::from_str(&sarif_str).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("sarif results array");
    assert!(
        results.len() >= 60,
        "expected broad SARIF findings on ubuntu-default"
    );
    for item in results {
        let uri = item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .expect("every SARIF result must carry a physicalLocation.artifactLocation.uri");
        assert!(!uri.is_empty() && !uri.starts_with('/'));
    }

    let md = render_report(&r1, OutputFormat::Markdown).expect("markdown");
    assert!(md.contains("# manis Hardening Audit Report"));
    assert!(md.contains("| ID | Status | Severity | Refs | Title |"));
    assert!(md.contains("<details>"));
}

#[test]
fn manis_toml_waivers_expiration_and_overrides_work_deterministically() {
    let registry = RuleRegistry::load_embedded().expect("registry");
    let view = RootFsSystemView::from_root(fixture_path("ubuntu-default")).expect("view");

    let cfg = UserConfig::parse(
        r#"
[waivers.SSH-002]
reason = "Temporary migration exemption"
expires = "2026-06-01"

[overrides.suid_sgid]
extra_whitelist = ["/usr/local/bin/custom-suid"]

[overrides.package_repos]
extra_trusted_domains = ["untrusted.example.com"]
"#,
    )
    .expect("parse config");

    let before = SimpleDate::parse("2026-05-01").unwrap();
    let rep_before =
        run_audit_with_config(&registry, "all", &view, &cfg, Some(before)).expect("audit before");
    let ssh002_before = rep_before
        .results
        .iter()
        .find(|r| r.id == "SSH-002")
        .unwrap();
    assert_eq!(ssh002_before.status, Status::Skip);
    assert!(ssh002_before.details[0].contains("Temporary migration exemption"));

    let fs002 = rep_before
        .results
        .iter()
        .find(|r| r.id == "FS-002")
        .unwrap();
    assert!(!fs002.details.iter().any(|d| d.contains("custom-suid")));
    assert!(fs002.details.iter().any(|d| d.contains("debug-helper")));

    let after = SimpleDate::parse("2026-06-02").unwrap();
    let rep_after =
        run_audit_with_config(&registry, "all", &view, &cfg, Some(after)).expect("audit after");
    let ssh002_after = rep_after
        .results
        .iter()
        .find(|r| r.id == "SSH-002")
        .unwrap();
    assert_eq!(ssh002_after.status, Status::Fail);
    assert!(ssh002_after
        .details
        .iter()
        .any(|d| d.contains("waiver expired on 2026-06-01")));
}

#[test]
fn diff_subcommand_detects_fixes_regressions_and_honors_no_fail() {
    let tmp = tempdir().expect("tempdir");
    let base_json = tmp.path().join("default.json");
    let hard_json = tmp.path().join("hardened.json");

    let out_def = manis_bin()
        .args([
            "audit",
            "--format",
            "json",
            "--root",
            fixture_path("ubuntu-default").to_str().unwrap(),
            "--output",
            base_json.to_str().unwrap(),
        ])
        .output()
        .expect("audit default");
    assert_eq!(out_def.status.code(), Some(1));

    let out_hard = manis_bin()
        .args([
            "audit",
            "--format",
            "json",
            "--root",
            fixture_path("ubuntu-hardened").to_str().unwrap(),
            "--output",
            hard_json.to_str().unwrap(),
        ])
        .output()
        .expect("audit hardened");
    assert_eq!(out_hard.status.code(), Some(0));

    let diff_fixed = manis_bin()
        .args([
            "diff",
            base_json.to_str().unwrap(),
            hard_json.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("diff default -> hardened");
    assert_eq!(diff_fixed.status.code(), Some(0));
    let val: serde_json::Value =
        serde_json::from_slice(&diff_fixed.stdout).expect("valid diff json");
    assert_eq!(val["summary"]["regressions"], 0);
    assert!(val["summary"]["fixed"].as_u64().unwrap() >= 60);

    let diff_reg = manis_bin()
        .args([
            "diff",
            hard_json.to_str().unwrap(),
            base_json.to_str().unwrap(),
        ])
        .output()
        .expect("diff hardened -> default");
    assert_eq!(diff_reg.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&diff_reg.stdout).contains("Regressions"));

    let diff_no_fail = manis_bin()
        .args([
            "diff",
            hard_json.to_str().unwrap(),
            base_json.to_str().unwrap(),
            "--no-fail",
            "--format",
            "markdown",
        ])
        .output()
        .expect("diff --no-fail");
    assert_eq!(diff_no_fail.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&diff_no_fail.stdout).contains("## Regressions"));
}

#[test]
fn empty_root_never_produces_false_pass_on_missing_configs() {
    let dir = tempdir().expect("tempdir");
    let registry = RuleRegistry::load_embedded().expect("registry");
    let view = RootFsSystemView::from_root(dir.path()).expect("view");
    let report = run_audit(&registry, "all", &view).expect("audit");

    assert_eq!(report.summary.total, 103);
    for res in &report.results {
        if res.id == "FS-002" {
            assert_eq!(res.status, Status::Pass);
        } else {
            assert_ne!(
                res.status,
                Status::Pass,
                "rule {} must not silently PASS on an empty root",
                res.id
            );
        }
    }
}

#[test]
fn cli_list_explain_config_and_error_exit_codes() {
    let list_out = manis_bin().arg("list").output().expect("manis list");
    assert_eq!(list_out.status.code(), Some(0));
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_stdout.contains("BOOT-001"));
    assert!(list_stdout.contains("MAC-003"));
    assert!(list_stdout.contains("FW-002"));
    assert!(list_stdout.contains("LOG-013"));
    assert!(list_stdout.contains("REFS"));

    let explain_cis = manis_bin()
        .args(["explain", "5.3.3.1.2"])
        .output()
        .expect("explain 5.3.3.1.2");
    assert_eq!(explain_cis.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&explain_cis.stdout).contains("AUTH-014"));

    let unknown_rule = manis_bin()
        .args(["explain", "DOES-NOT-EXIST"])
        .output()
        .expect("explain unknown");
    assert_eq!(unknown_rule.status.code(), Some(2));

    let tmp = tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("manis.toml");
    std::fs::write(
        &cfg_path,
        "[waivers.SSH-002]\nreason = \"CLI waiver test\"\n",
    )
    .expect("write config");
    let out = manis_bin()
        .args([
            "audit",
            "--format",
            "json",
            "--root",
            fixture_path("ubuntu-default").to_str().unwrap(),
            "--config",
            cfg_path.to_str().unwrap(),
        ])
        .output()
        .expect("audit with --config");
    let rep: AuditReport = serde_json::from_slice(&out.stdout).expect("json");
    let ssh002 = rep.results.iter().find(|r| r.id == "SSH-002").unwrap();
    assert_eq!(ssh002.status, Status::Skip);
}
