# Instructions for agents

How an agent working in this repository must behave, and what it must check before starting.

## Before starting

- Read `docs/SPEC.md` before changing the CLI interface, rule schema, status semantics, or architecture.
- Find what the author changed by hand and never overwrite it.
- Check that the pre-commit checks are active: `git config core.hooksPath` returns `.githooks`.
- Check that the starting point is sound:
  - `cargo fmt --check` passes;
  - `cargo clippy --all-targets -- -D warnings` passes;
  - `cargo test --quiet` passes.

## How to behave

### With the author

- Answer in French: the verdict first, in simple words, with simple questions.
- Unsolicited advice is allowed; the author keeps the right to set it aside.
- Before changing the CLI contract, exit codes, rule schema, or benchmark mappings, present the exact proposed change and wait for approval.

### Security & audit correctness (non-negotiable)

- **Read-only by default:** `manis` must never modify system files, kernel parameters, or host state.
- **No false positives (`PASS`):** when a file, sysctl key, mount point, or kernel config cannot be read or is absent, never silently return `PASS`. Return `WARN`, `FAIL`, or `ERROR` according to the rule specification.
- **No `unsafe` code:** `unsafe_code = "forbid"` is enforced in `Cargo.toml`.
- **Testable via `--root`:** every collector must read through the `SystemView` abstraction so all rules run deterministically against fixture directories on macOS and Linux without root privileges.
- **Accurate benchmark citations:** never invent CIS, ANSSI-BP-028, or NIST SP 800-53 rule IDs; verify every cited identifier against the official benchmark document before adding it to `rules/`.
- **Explicit `MANUAL` coverage:** rules that cannot be automated reliably (e.g., BIOS/UEFI password, physical security) are declared explicitly with status `MANUAL` rather than silently omitted or faked.

### Repository & git discipline

- Create no file, in particular no `.md` file, without being asked.
- Never delete with `rm`: move what is replaced to the macOS Trash (`/usr/bin/trash`), never to an archive folder in `~/Documents`.
- Do not commit without being asked.
- The agent is at no point a contributor and never presents itself as one: no author, co-author, or contributor mention of the agent in a commit message (no `Co-Authored-By` line), a pull request, a document, the code, or anywhere else.
- Never rewrite a commit: no `amend`, no `rebase`, no `force push`.
- Never bypass the pre-commit checks (no `--no-verify`).
- Keep build artifacts and local reports out of git (`target/`, `*.sarif`).

### Code style & dependencies

- All code, comments, rule definitions, CLI messages, docs, and `AGENTS.md` are in English.
- Keep dependencies minimal, well-audited, and synchronous (no `async` runtime unless justified by a real bottleneck).
- Every rule primitive must have unit tests covering pass, fail, missing/unreadable input, comments/whitespace edge cases, and waiver/whitelist behavior.
- Output formats (`json`, `sarif`, `markdown`) must be deterministic when run against the same fixture (sorted rule order, no unseeded randomness).

## Before handing back

- Run `cargo fmt --check`.
- Run `cargo clippy --all-targets -- -D warnings`.
- Run `cargo test --quiet`.
- State clearly what was checked and what was not.
