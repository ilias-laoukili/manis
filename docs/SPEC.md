# manis — Technical Specification

## 1. Purpose & Open-Source Positioning

`manis` is a read-only Linux hardening compliance CLI written in safe, synchronous Rust (`#![forbid(unsafe_code)]`).

Existing Linux auditing tools leave a practical gap for modern DevSecOps, golden VM image pipelines (Packer), containers, and lightweight servers:

- **OpenSCAP (`oscap`):** authoritative for formal SCAP/OVAL certification, but heavy to install and cumbersome on minimal Linux systems.
- **Lynis:** comprehensive, but a large legacy shell codebase without native SARIF output or clean declarative multi-framework rules.
- **InSpec / Ansible:** require Ruby or Python/Ansible runtimes.
- **Trivy / Prowler:** focused on containers, Kubernetes, and cloud APIs rather than deep OS/kernel hardening.

`manis` targets that gap with:

1. A single static Linux `musl` binary (< 5 MB, zero runtime dependencies, zero external subprocesses).
2. Human-readable declarative TOML rules with verified cross-framework mappings (`CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0`, `ANSSI-BP-028 v2.0`, `NIST SP 800-53 Rev. 5`).
3. CI-native deterministic outputs (`table`, `json`, `sarif` 2.1.0, `markdown`), baseline drift detection (`diff`), and auditable waivers/overrides (`manis.toml`).
4. Full offline testability via `--root <path>` against fixture filesystems or mounted rootfs images on Linux and macOS without root privileges.

### Non-Goals

- No destructive automatic remediation (prints actionable remediation commands instead).
- No SCAP/OVAL XML runtime (use OpenSCAP when formal OVAL certification is required).
- No application CVE vulnerability scanning (use Trivy/Grype).

---

## 2. Architecture

```text
Embedded TOML Rules & Profiles (103 rules) + Optional User Config (manis.toml)
                           |
                           v
                  Evaluation Engine  <---  SystemView (Live Linux `/` OR `--root` fixture)
                           |
                           v
        Reporters: Table | JSON | SARIF 2.1.0 | Markdown | Diff
```

### `SystemView` Invariants

- Every check primitive inspects the target system strictly through `SystemView` (`read_to_string`, `read_bytes`, `metadata`, `read_link`, `read_dir`, `walk_files`, `kernel_release`).
- Virtual paths are confined inside the configured root directory (`..` traversal is rejected).
- In `--root <path>` mode, symlinks are resolved component by component inside the root, like a `chroot`: absolute targets are re-rooted, `..` in a target stops at the root, and more than 40 links is an error. No read can reach a host file. Live mode (`/`) keeps kernel path resolution.
- In `--root <path>` fixture mode only, an optional `.manis-meta.toml` overlay may specify simulated Unix permission modes, `uid`/`gid`, `unreadable = true`, or `symlink_target` (since Git does not store SUID/SGID bits or ownership). Live mode (`/`) **never** reads `.manis-meta.toml`.

### Status Semantics (No False Positives)

- `PASS`: value read and compliant.
- `FAIL`: value read and non-compliant (always includes `expected`, `actual`, `remediation`, and `artifact_uri`).
- `WARN`: parameter absent, file/directory unreadable due to permissions, or partial scan.
- `SKIP`: explicitly waived in `manis.toml` (with documented `reason`) or optional missing backup file.
- `MANUAL`: benchmark control that cannot be automated reliably (e.g. BIOS/UEFI password, full-disk encryption policy, physical console security).
- `ERROR`: unexpected collector or rule configuration error.

---

## 3. Declarative Rule Primitives (14)

All 103 embedded rules are implemented via 14 reusable, zero-subprocess primitives:

1. `sysctl` — `/proc/sys/...` comparison (`eq`, `ge`, `le`, `in`) with optional `/proc/cmdline` or alternative sysctl short-circuits (e.g. IPv6 disabled-or-hardened).
2. `kernel_config` — `/boot/config-*`, in-memory gzip `/proc/config.gz` (`flate2` pure Rust), or `/lib/modules/*/build/.config`.
3. `mount_options` — `/proc/mounts` dedicated partition checks (`required_separate`, `required_options`, `any_of_options` for `hidepid`).
4. `sshd_config` — `/etc/ssh/sshd_config` + `Include` drop-ins with OpenSSH first-match-wins semantics and `Match` block handling.
5. `file_meta` — `max_mode` bitmask compliance and `uid`/`gid` ownership on critical system files (`/etc/shadow`, `/etc/passwd`, `/boot/grub/grub.cfg`, cron, SSH).
6. `file_content` — shell inactivity timeout (`TMOUT`), `umask` (strict + standard + PAM), `key_value_bound` (whitespace and `=`, optional `allow_zero`), `/etc/passwd` UID 0 uniqueness & system account `nologin`/`false` shells, `/etc/shadow` empty password check, login banners, AppArmor loaded profiles, and regex assertions.
7. `sudoers` — `/etc/sudoers` + `/etc/sudoers.d/*` (broad root targets, `!` command negations, required `Defaults` `use_pty`/`logfile`/`timestamp_timeout`, `NOPASSWD`, `!authenticate`).
8. `suid_sgid` — filesystem walk enforcing explicit SUID/SGID whitelist and forbidding world-writable SUID/SGID binaries.
9. `world_writable` — filesystem walk detecting world-writable regular files (`o+w`) and world-writable directories missing the sticky bit (`+t`).
10. `package_repos` — APT `.list`, DEB822 `.sources`, YUM/DNF `.repo` exact/subdomain host trust and GPG verification checks.
11. `package_state` — RFC-822 `/var/lib/dpkg/status` parser (`all_installed`, `any_installed`, `all_absent`).
12. `service_state` — systemd symlink and `*.wants/` inspector (`any_enabled`, `exactly_one_enabled`, `all_disabled_or_masked`) without calling `systemctl`.
13. `firewall_config` — UFW (`/etc/ufw/*`, `/etc/default/ufw`) and nftables (`/etc/nftables.conf`) single-active-firewall, default-deny input, and loopback checks.
14. `manual` — transparent tracking of non-automatable controls with explicit verification steps.

---

## 4. CLI Contract

```bash
manis audit [--profile cis-l1-server|all|anssi-minimal|anssi-intermediary|anssi-reinforced] \
            [--format table|json|sarif|markdown] \
            [--fail-on critical|high|medium|low] \
            [--root <path>] [--config manis.toml] [--output <file>]

manis list [--profile <name>]
manis explain <RULE_ID>
manis diff <baseline.json> <current.json> [--format table|json|markdown] [--no-fail] [--output <file>]
```

- Default `--profile`: `cis-l1-server`.
- Default `--format`: `table` (uses international `REFS` column).
- Default `--fail-on`: `low`.
- Deterministic JSON, SARIF 2.1.0 (with `physicalLocation.artifactLocation.uri` on every finding), and Markdown outputs omit variable wall-clock timestamps by default.
- Stdout handles `BrokenPipe` cleanly (exit `0` without panicking in shell pipelines).

### Exit Codes

- `0`: compliant (no `FAIL` at or above `--fail-on`, or no regressions in `diff`, or `--no-fail`).
- `1`: at least one `FAIL` meets or exceeds `--fail-on`, or at least one regression (`PASS/WARN/SKIP -> FAIL`) detected in `diff`.
- `2`: invalid arguments, configuration error, unknown profile/rule, or internal error.

---

## 5. Delivered Milestones

- **v0.1.0 (MVP):** `SystemView` (`--root`), 7 core primitives, 13 migrated & fixed ANSSI-BP-028 rules cross-mapped to CIS/NIST, `table` + `json` reporters, Ubuntu fixtures, CI.
- **v0.2.0 (International CIS + DevSecOps):** `sshd_config`, `file_meta`, `manual` primitives; 55 verified rules across 8 domains; `sarif` 2.1.0 + `markdown` + `diff` + `manis.toml` waivers & overrides; live Docker integration tests in CI; static `musl` x86_64 & ARM64 release workflow.
- **v0.3.0 (Full CIS L1 Server Coverage):** `SystemView::read_link`, 4 pure file-based primitives (`package_state`, `service_state`, `firewall_config`, `world_writable`), AppArmor & advanced PAM (`pwquality`, `faillock`, `pwhistory`, `pam_unix`), GRUB, unused services & NTP, host firewall, `journald`/`auditd`/AIDE, world-writable files/dirs, system account non-interactive shells → **103 verified rules (`100` automated + `3 MANUAL`)** across all 7 CIS Ubuntu 24.04 LTS Benchmark sections.
