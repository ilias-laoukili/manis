# manis — Technical Specification

## 1. Purpose & Open-Source Positioning

`manis` is a read-only Linux hardening compliance CLI written in safe, synchronous Rust.

Existing Linux auditing tools leave a practical gap for modern DevSecOps, golden VM image pipelines (Packer), containers, and lightweight servers:

- **OpenSCAP (`oscap`):** authoritative for formal SCAP/OVAL certification, but heavy to install and cumbersome on minimal Linux systems.
- **Lynis:** comprehensive, but a large legacy shell codebase without native SARIF output or clean declarative multi-framework rules.
- **InSpec / Ansible:** require Ruby or Python/Ansible runtimes.
- **Trivy / Prowler:** focused on containers, Kubernetes, and cloud APIs rather than deep OS/kernel hardening.

`manis` targets that gap with:

1. A single static Linux `musl` binary (< 5 MB, zero dependencies, < 200 ms runtime).
2. Human-readable declarative TOML rules with cross-framework mappings (`CIS`, `ANSSI-BP-028 v2.0`, `NIST SP 800-53`).
3. CI-native outputs (`table`, `json`, `sarif`, `markdown`) and baseline drift detection (`diff`).
4. Full offline testability via `--root <path>` against fixture filesystems or mounted rootfs images.

### Non-Goals

- No destructive automatic remediation (prints actionable remediation commands instead).
- No SCAP/OVAL XML runtime (use OpenSCAP when formal OVAL certification is required).
- No application CVE vulnerability scanning (use Trivy/Grype).

## 2. Architecture

```text
TOML Rules & Profiles + User Config (manis.toml)
                     |
                     v
            Evaluation Engine  <---  SystemView (Live Linux OR --root fixture)
                     |
                     v
      Reporters: Table | JSON | SARIF 2.1.0 | Markdown | Diff
```

### Status Semantics (No False Positives)

- `PASS`: value read and compliant.
- `FAIL`: value read and non-compliant (includes `expected`, `actual`, and `remediation`).
- `WARN`: parameter absent, unreadable due to permissions, or partial check.
- `SKIP`: waived in `manis.toml` (with documented reason) or not applicable to OS.
- `MANUAL`: benchmark control that cannot be automated reliably (e.g. BIOS/UEFI password, physical access).
- `ERROR`: unexpected collector/parse error.

## 3. Declarative Rule Primitives

Core reusable primitives cover 45–60+ CIS Linux Level 1 Server and ANSSI-BP-028 controls without duplicating logic:

1. `sysctl` — `/proc/sys/...` comparison (`eq`, `ge`, `le`, `in`)
2. `kernel_config` — `/proc/config.gz` or `/boot/config-*`
3. `mount_options` — `/proc/mounts` and `/etc/fstab` (`nodev`, `nosuid`, `noexec`)
4. `sshd_config` — `/etc/ssh/sshd_config` + `sshd_config.d/*.conf`
5. `file_meta` — mode and `uid`/`gid` checks on critical files (`/etc/shadow`, `/etc/passwd`, cron)
6. `file_content` — regex/directive assertions (`TMOUT`, `umask`, banners, PAM)
7. `sudoers` — `/etc/sudoers` + `/etc/sudoers.d/*` (target users, negations `!`, `use_pty`, `logfile`)
8. `suid_sgid` — SUID/SGID inventory compared against an explicit whitelist + world-writable check
9. `package_repos` — APT/RPM repository trust and GPG verification
10. `manual` — transparent tracking of non-automatable controls

## 4. CLI Contract

```bash
manis audit [--profile cis-l1-server|anssi-minimal|anssi-intermediary|anssi-reinforced] \
            [--format table|json|sarif|markdown] \
            [--fail-on critical|high|medium|low] \
            [--root <path>] [--config manis.toml] [--output <file>]

manis list [--profile <name>]
manis explain <RULE_ID>
manis diff <baseline.json> <current.json>
```

### Exit Codes

- `0`: no `FAIL` at or above `--fail-on`.
- `1`: at least one `FAIL` meets or exceeds `--fail-on`.
- `2`: invalid arguments, configuration error, or execution error.

## 5. Milestones

- **v0.1.0 (MVP):** `SystemView` (`--root`), 6 core primitives, 12 corrected ANSSI-BP-028 rules cross-mapped to CIS/NIST, `table` + `json` reporters, fixture test suite, CI.
- **v0.2.0 (International CIS + DevSecOps):** `sshd_config`, `file_meta`, `package_repos`, `manual` primitives; 45–60 rules covering `cis-l1-server` + ANSSI profiles; `sarif` + `markdown` + `diff` + `manis.toml` waivers; Docker integration tests in CI; static `musl` release binaries.
