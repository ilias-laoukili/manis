# manis

[![CI](https://github.com/ilias-laoukili/manis/actions/workflows/ci.yml/badge.svg)](https://github.com/ilias-laoukili/manis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/ilias-laoukili/manis)](https://github.com/ilias-laoukili/manis/releases)

**Declarative, zero-dependency Linux hardening audit CLI** mapped to **CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 (Level 1 Server)**, **ANSSI-BP-028 v2.0**, and **NIST SP 800-53 Rev. 5**.

Named after *Manis* — the pangolin, the only mammal fully armored in protective scales.

---

## Why `manis`?

- **Single static binary (< 5 MB, ~1.9 MB stripped):** Written in safe, synchronous Rust (`#![forbid(unsafe_code)]`) with zero runtime dependencies and zero external subprocesses (`systemctl`, `dpkg`, `ufw`, `findmnt` are never shelled out).
- **103 embedded declarative rules (`100` automated + `3 MANUAL`) across 14 primitives:** Human-readable TOML rules with verified cross-framework references (`CIS`, `ANSSI-BP-028 v2.0`, `NIST SP 800-53`).
- **No silent false positives:** Missing files, absent sysctls, or `PermissionDenied` errors emit explicit `WARN` or `FAIL` — never a silent `PASS`. Non-automatable controls are tracked explicitly as `MANUAL`.
- **CI/DevSecOps native:** Deterministic `table`, `json`, `sarif` (2.1.0 for GitHub Code Scanning), and `markdown` reports, baseline drift detection (`manis diff`), and auditable waivers/overrides (`manis.toml`).
- **Offline fixture testing:** `--root <path>` runs 100% of rules deterministically against mounted rootfs images or fixture trees on Linux and macOS without root privileges.

### Sample Output

```text
$ manis audit --root tests/fixtures/ubuntu-default
manis 0.3.0 | profile: cis-l1-server | root: tests/fixtures/ubuntu-default

ID        STATUS  SEVERITY  REFS               TITLE
--------  ------  --------  -----------------  -------------------------------------------------------------------
AUTH-001  FAIL    medium    CIS 5.4.3.2, R32   Interactive shell inactivity timeout (TMOUT)
AUTH-005  PASS    critical  CIS 5.4.2.1        Ensure root is the only UID 0 account
AUTH-006  FAIL    critical  CIS 7.2.2          Ensure no /etc/shadow accounts have empty password fields
AUTH-018  FAIL    medium    CIS 5.4.2.7        Ensure system accounts do not have a valid login shell
FS-002    FAIL    critical  CIS 7.1.13, R56    Audit SUID/SGID binaries against whitelist and forbid world-writable
FS-009    FAIL    high      CIS 7.1.11         Ensure world-writable files and directories are secured
SSH-002   FAIL    critical  CIS 5.1.20         Disable direct root login over SSH
...
Summary: total=93 pass=5 fail=84 warn=0 skip=4 manual=0 error=0
```

```text
$ manis diff baseline.json hardened.json
manis diff | baseline: cis-l1-server -> current: cis-l1-server
Summary: regressions=0 fixed=84 changed=4 added=0 removed=0 unchanged=5

Fixed (84):
  AUTH-001   medium   FAIL   -> PASS    Interactive shell inactivity timeout (TMOUT)
  AUTH-006   critical FAIL   -> PASS    Ensure no /etc/shadow accounts have empty password fields
  FS-009     high     FAIL   -> PASS    Ensure world-writable files and directories are secured
  SSH-002    critical FAIL   -> PASS    Disable direct root login over SSH
  ...
```

---

## Benchmark Coverage (CIS Ubuntu 24.04 LTS v1.0.0 — Sections 1 to 7)

| CIS Section | Domain | Rules (`manis list --profile all`) | Scope & Notes |
| :--- | :--- | :---: | :--- |
| **1. Initial Setup** | Filesystems (`1.1`), APT repos/GPG (`1.2`), AppArmor (`1.3`), GRUB (`1.4`), Kernel/ASLR/ptrace/coredumps (`1.5`), Banners (`1.6`) | **23** | Unused FS modules (`cramfs`–`udf`), `/tmp` & `/dev/shm` mounts, APT `.list`/DEB822 `.sources` + GPG, AppArmor packages/boot/profiles (`1.3.1.3` L1 & `1.3.1.4` L2), GRUB perms & PBKDF2 password, kernel sysctl/compile hardening, `/etc/issue` & `/etc/issue.net`. |
| **2. Services** | Special-purpose daemons (`2.1`), Legacy clients (`2.2`), Time sync (`2.3`), Cron perms (`2.4`) | **14** | `nis`, `rsh`, `telnet` package absence; `avahi-daemon`, `cups`, `rpcbind`, `rsync`, `snmpd`, `vsftpd` disabled/masked via systemd links; single NTP daemon (`chrony` XOR `systemd-timesyncd`) + authorized time servers; `/etc/crontab` & `/etc/cron.d` perms. |
| **3. Network Configuration** | IPv4 & IPv6 kernel sysctl hardening (`3.3`) | **2** *(24 sysctls)* | Full IPv4 stack hardening (`R12` / `3.3.1`–`3.3.10`) and IPv6 disabled-or-hardened (`R13` / `3.3.1`, `3.3.5`, `3.3.11`). |
| **4. Host-Based Firewall** | UFW & nftables (`4.2` / `4.3`) | **4** | Firewall package presence, single active firewall (no UFW+nftables conflict), default `DROP`/`REJECT` input policy, loopback (`lo` / `127.0.0.0/8`) rules. |
| **5. Access Control** | OpenSSH (`5.1`), `sudo` (`5.2`), PAM (`5.3`), User accounts & shell env (`5.4`) | **31** | OpenSSH first-match-wins + `Include` drop-ins (`5.1.1`–`5.1.22`); `sudoers` (`use_pty`, `logfile`, `timestamp_timeout`, no `NOPASSWD`, no `!authenticate`, `R40`/`R42`); `pwquality`, `faillock` (`deny`, `unlock_time = 0` or `>= 900`), `pwhistory`, `pam_unix` (`yescrypt`/`sha512`, no `nullok`); `TMOUT`, `umask`, password aging, unique UID 0, system accounts non-interactive shell (`5.4.2.7`). |
| **6. Logging & Auditing** | `systemd-journald` (`6.1`), `auditd` (`6.2`), AIDE (`6.3`) | **15** | `journald` persistent + compressed storage; `auditd` installed/enabled, boot `audit=1` & `audit_backlog_limit`, `keep_logs` & `disk_full_action`, critical audit rules (`sudoers`, time, identity, kernel modules, `-e 2` immutable); AIDE installed & timer scheduled. |
| **7. System Maintenance** | Critical file permissions (`7.1`), World-writable & SUID/SGID (`7.1.11`, `7.1.13`), Account integrity (`7.2`) | **11** | `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` (+ `-` backups); world-writable files & non-sticky directories (`7.1.11`); SUID/SGID whitelist + world-writable SUID/SGID scan (`7.1.13` / `R56`); empty `/etc/shadow` password check (`7.2.2`). |
| **Manual Controls** | Firmware, encryption, physical security | **3 (`MANUAL`)** | Explicitly tracked as `Status::Manual`: BIOS/UEFI password & boot order (`MAN-001`), full-disk encryption (`MAN-002`), physical console/rack access (`MAN-003`). |
| **Total** | **All embedded rules** | **103 (`100` automated + `3 MANUAL`)** | Matches `manis list --profile all` (`93` rules in default `cis-l1-server` profile). |

> **Honest boundary:** `manis` inspects system state strictly through files (`/proc`, `/sys`, `/etc`, `/boot`, `/var/lib/dpkg/status`). Runtime-only checks requiring live kernel netlink queries or formal OVAL/SCAP certification belong to dedicated tools like OpenSCAP.

---

## Comparison with Existing Tools

| Capability | `manis` | OpenSCAP (`oscap`) | Lynis |
| :--- | :--- | :--- | :--- |
| **Deployment footprint** | Single static `< 5 MB` Rust binary | Heavy XML/XCCDF/OVAL stack | Shell script suite + system utils |
| **Subprocess / runtime deps** | Zero | `libopenscap` + SCAP content | Bash + coreutils / `awk` / `grep` |
| **Offline `--root` / macOS testing** | Native, deterministic | Requires chroot / container | Host-focused |
| **SARIF 2.1.0 & baseline `diff`** | Built-in | Requires converters | Enterprise / external |
| **Formal SCAP/OVAL certification** | Non-goal | Authoritative | Non-goal |
| **Declarative rules & waivers** | Embedded TOML + `manis.toml` | XML tailoring | Profile `.prf` overrides |

---

## Quick Start

### Build from source

```bash
cargo build --release
```

### Run an audit

```bash
# Default profile: CIS Ubuntu 24.04 LTS Level 1 Server (live host)
sudo manis audit

# Audit an offline rootfs or fixture directory (no root required)
manis audit --root tests/fixtures/ubuntu-default

# Run all 103 rules (including ANSSI-BP-028 reinforced & explicit MANUAL controls)
manis audit --profile all --root tests/fixtures/ubuntu-hardened

# Emit deterministic JSON, SARIF 2.1.0, or Markdown
manis audit --format json --output report.json
manis audit --format sarif --output manis.sarif
manis audit --format markdown --output report.md

# Fail CI only on high or critical findings
manis audit --fail-on high
```

### Explore rules and explain references

```bash
# List profiles and rules
manis list
manis list --profile anssi-minimal

# Look up a rule by canonical ID, ANSSI alias, or CIS control ID
manis explain SSH-002
manis explain R9
manis explain 5.3.3.1.2
```

### Detect hardening drift (`manis diff`)

```bash
# Exits 1 if any regression (PASS/WARN/SKIP -> FAIL) is detected; use --no-fail for exit 0
manis diff baseline.json current.json
manis diff baseline.json current.json --format markdown --no-fail
```

### Waivers & overrides (`manis.toml`)

```toml
[waivers.KERN-002]
reason = "Runtime module loading required for eBPF observability agent"
expires = "2027-06-01" # Optional: once expired, rule reverts to normal evaluation

[overrides.suid_sgid]
extra_whitelist = ["/opt/corp/bin/helper"]

[overrides.package_repos]
extra_trusted_domains = ["packages.internal.example"]
```

```bash
manis audit --config manis.toml
```

### GitHub Code Scanning (SARIF 2.1.0)

```yaml
- name: Run manis hardening audit
  run: manis audit --format sarif --output manis.sarif || true

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: manis.sarif
```

---

## Exit Codes

| Code | Meaning |
| :---: | :--- |
| `0` | Compliant (no `FAIL` at or above `--fail-on`, or no regressions in `diff`) |
| `1` | Non-compliant (at least one `FAIL` >= `--fail-on`, or regression detected in `diff`) |
| `2` | Invalid arguments, configuration error, or internal execution error |

---

## Development Setup

```bash
# Activate repository pre-commit checks
git config core.hooksPath .githooks

# Verify formatting, strict Clippy lints (pedantic + forbid(unsafe_code)), and tests
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

See [`docs/SPEC.md`](docs/SPEC.md) for the technical architecture and specification.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
