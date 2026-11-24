use manis::engine::run_audit;
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
fn ubuntu_hardened_fixture_passes_all_13_rules_with_exit_0() {
    let fixture = fixture_path("ubuntu-hardened");
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

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit code 0 on ubuntu-hardened, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: AuditReport =
        serde_json::from_slice(&output.stdout).expect("valid JSON AuditReport");
    assert_eq!(report.summary.total, 13);
    assert_eq!(report.summary.pass, 13);
    assert_eq!(report.summary.fail, 0);
    assert_eq!(report.summary.warn, 0);
    assert_eq!(report.summary.error, 0);
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
    assert_eq!(report.summary.total, 13);
    // Stock Ubuntu has SECCOMP & Yama enabled (KERN-004 passes); the other 12 fail.
    assert_eq!(report.summary.pass, 1);
    assert_eq!(report.summary.fail, 12);
    assert_eq!(report.summary.warn, 0);

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
        assert!(
            !res.remediation.trim().is_empty(),
            "FAIL rule {} must include remediation",
            res.id
        );
    }

    // Verify R56 (FS-002) enforces BOTH whitelist and world-writable checks.
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
}

#[test]
fn json_output_is_byte_for_byte_deterministic_without_timestamps() {
    let registry = RuleRegistry::load_embedded().expect("registry");
    let view = RootFsSystemView::from_root(fixture_path("ubuntu-default")).expect("view");

    let r1 = run_audit(&registry, "all", &view).expect("run 1");
    let r2 = run_audit(&registry, "all", &view).expect("run 2");

    let j1 = render_report(&r1, OutputFormat::Json).expect("json 1");
    let j2 = render_report(&r2, OutputFormat::Json).expect("json 2");

    assert_eq!(j1, j2, "JSON output must be byte-for-byte deterministic");
    assert!(
        !j1.contains("timestamp"),
        "JSON output must not contain variable timestamps by default"
    );
}

#[test]
fn table_output_uses_refs_column_and_shows_findings() {
    let fixture = fixture_path("ubuntu-default");
    let output = manis_bin()
        .args([
            "audit",
            "--profile",
            "cis-l1-server",
            "--format",
            "table",
            "--root",
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("run manis table");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("REFS"));
    assert!(!stdout.contains("ID        STATUS  SEVERITY  ANSSI"));
    assert!(stdout.contains("Expected:"));
    assert!(stdout.contains("Actual:"));
    assert!(stdout.contains("Remediation:"));
}

#[test]
fn fail_on_threshold_controls_exit_code() {
    // In ubuntu-default, KERN-002 (R10) has severity medium.
    // Profile anssi-reinforced with --fail-on critical fails because FS-002 is critical.
    let fixture = fixture_path("ubuntu-default");
    let out_crit = manis_bin()
        .args([
            "audit",
            "--profile",
            "all",
            "--fail-on",
            "critical",
            "--root",
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("run --fail-on critical");
    assert_eq!(out_crit.status.code(), Some(1));

    // Create a minimal tree where only medium-severity AUTH-001 (TMOUT) fails;
    // --fail-on high should exit 0 while --fail-on medium exits 1.
    let dir = tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
    std::fs::write(dir.path().join("etc/profile"), "umask 077\n").expect("write");
    std::fs::write(dir.path().join("etc/login.defs"), "UMASK 077\n").expect("write");
    std::fs::write(dir.path().join("etc/sudoers"), "root ALL=(ALL:ALL) ALL\n").expect("write");
    std::fs::create_dir_all(dir.path().join("etc/apt/sources.list.d")).expect("mkdir");
    std::fs::write(
        dir.path().join("etc/apt/sources.list.d/ubuntu.sources"),
        "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/\nSuites: noble\nComponents: main\n",
    )
    .expect("write");

    let out_high = manis_bin()
        .args([
            "audit",
            "--profile",
            "anssi-minimal",
            "--fail-on",
            "high",
            "--root",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("run --fail-on high");
    assert_eq!(out_high.status.code(), Some(0));

    let out_med = manis_bin()
        .args([
            "audit",
            "--profile",
            "anssi-minimal",
            "--fail-on",
            "medium",
            "--root",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("run --fail-on medium");
    assert_eq!(out_med.status.code(), Some(1));
}

#[test]
fn empty_root_never_produces_false_pass_on_missing_sysctls_or_configs() {
    let dir = tempdir().expect("tempdir");
    let registry = RuleRegistry::load_embedded().expect("registry");
    let view = RootFsSystemView::from_root(dir.path()).expect("view");
    let report = run_audit(&registry, "all", &view).expect("audit");

    // FS-002 (suid_sgid) scans the empty dir and legitimately sees 0 SUID/SGID binaries (PASS).
    // Every other rule depends on missing system files/sysctls and must NEVER silently PASS.
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
fn cli_list_explain_output_and_error_exit_codes() {
    let list_out = manis_bin().arg("list").output().expect("manis list");
    assert_eq!(list_out.status.code(), Some(0));
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_stdout.contains("KERN-001"));
    assert!(list_stdout.contains("cis-l1-server"));
    assert!(list_stdout.contains("REFS"));

    // Explain by ANSSI alias and by CIS ID
    let explain_anssi = manis_bin()
        .args(["explain", "R9"])
        .output()
        .expect("explain R9");
    assert_eq!(explain_anssi.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&explain_anssi.stdout).contains("KERN-001"));

    let explain_cis = manis_bin()
        .args(["explain", "5.4.3.2"])
        .output()
        .expect("explain 5.4.3.2");
    assert_eq!(explain_cis.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&explain_cis.stdout).contains("AUTH-001"));

    // Unknown rule -> exit code 2
    let unknown_rule = manis_bin()
        .args(["explain", "DOES-NOT-EXIST"])
        .output()
        .expect("explain unknown");
    assert_eq!(unknown_rule.status.code(), Some(2));

    // Unknown profile -> exit code 2
    let unknown_profile = manis_bin()
        .args([
            "audit",
            "--profile",
            "does-not-exist",
            "--root",
            fixture_path("ubuntu-hardened").to_str().unwrap(),
        ])
        .output()
        .expect("unknown profile");
    assert_eq!(unknown_profile.status.code(), Some(2));

    // --output writes report to file
    let tmp = tempdir().expect("tempdir");
    let out_file = tmp.path().join("report.json");
    let write_out = manis_bin()
        .args([
            "audit",
            "--format",
            "json",
            "--root",
            fixture_path("ubuntu-hardened").to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("audit --output");
    assert_eq!(write_out.status.code(), Some(0));
    assert!(write_out.stdout.is_empty());
    let written: AuditReport =
        serde_json::from_str(&std::fs::read_to_string(&out_file).expect("read report"))
            .expect("valid JSON");
    assert_eq!(written.summary.pass, 13);
}
