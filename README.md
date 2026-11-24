# manis

**Declarative, zero-dependency Linux hardening audit CLI** mapped to **CIS Benchmarks**, **ANSSI-BP-028 v2.0**, and **NIST SP 800-53**.

Named after *Manis* — the pangolin, the only mammal fully armored in protective scales.

> **Status:** Early scaffold (`v0.1.0-dev`). See [`docs/SPEC.md`](docs/SPEC.md) for the full specification and roadmap.

## Design Goals

- **Single static binary:** Written in safe, synchronous Rust (`#![forbid(unsafe_code)]`) with static `musl` Linux builds and zero runtime dependencies.
- **Declarative multi-framework rules:** Reusable TOML rule primitives tagged with cross-references to CIS Linux Level 1 Server, ANSSI-BP-028, and NIST SP 800-53.
- **Strict, non-destructive auditing:** Read-only by default, with explicit `PASS`, `FAIL`, `WARN`, `SKIP`, `MANUAL`, and `ERROR` statuses (no silent false passes on missing parameters).
- **CI/DevSecOps native:** Human-readable terminal tables, deterministic `JSON`, `SARIF 2.1.0` for GitHub Code Scanning, `Markdown` reports, and baseline `diff`.
- **Offline fixture testing:** `--root <path>` allows testing rules against simulated Linux trees or mounted root filesystems without root privileges.

## Development Setup

```bash
# Activate repository pre-commit checks
git config core.hooksPath .githooks

# Verify formatting, lints, and tests
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
