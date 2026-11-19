# Feature Specification: Advanced Toolkit Options (v2.1)

**Spec ID:** 001-advanced-toolkit

**Status:** Complete — implemented and verified

**Created:** 2026-11-19

**Owner:** maintainer

**Input:** roadmap phases M0–M7, `.speckit/constitution.md`

## Overview

Turn the v2.0 toolkit into a fully option-driven, pipeline-capable, CI-friendly network inventory tool while
preserving its safety guarantees. The work fixes two confirmed defects, removes documentation/option drift,
adds a declarative option registry, exposes advanced (but non-offensive) Nmap options, adds profile/pipelines v2,
expands reporting and compliance, and improves packaging and UX.

## Goals

1. Every Nmap option the toolkit supports is declared once and validated centrally.
2. Power users can express any safe advanced scan (timing, discovery probes, scan techniques, NSE expression)
   without bypassing the toolkit's guard rails.
3. Workflows are data-driven, resumable and condition-aware.
4. Reports are machine-consumable in CI (SARIF, baselines, severity gates) and auditable.
5. Scope, authorization and dry-run plans are reviewable and hashable.
6. All existing CLI usage keeps working unchanged.

## Non-goals

- Brute-force, DoS, exploit, fuzzer or intrusive NSE categories.
- Evasion/spoofing: decoys, source spoofing, spoofed MAC, proxies, bad checksums, randomisation meant to evade.
- Authenticated scanning via SSH, web UI, daemon/server mode, or a database backend.
- New runtime dependencies (Python stays stdlib-only; no yaml/toml/requests at runtime).

## User stories

### US1 — Correctness (P0)
As an operator, I can pass several targets separated by spaces to `-t`, exactly as documented, and compare two
runs even when findings include both host-level (port `null`) and port-level entries.

**Acceptance criteria**
- Given `-t "10.0.0.1 10.0.0.2"`, the plan shows two targets and Nmap receives two address arguments.
- Given a report with mixed `port: null` / `port: 80` findings on the same host, `report.py diff A B` exits 0
  and prints `resolved` lines; no `TypeError`.
- `make test && make lint` pass locally.

### US2 — One source of truth (P0)
As a maintainer, I add a flag in one place and help, parsing, completion, config validation and docs update.

**Acceptance criteria**
- `lib/options.sh` registry lists every flag with value type, validator, Nmap mapping, risk, root need and category.
- `nmap-toolkit.sh --dump-options --json` emits the registry as JSON.
- `help`, `completions/`, `CONFIG_KEYS` and generated docs are produced from the registry; a test asserts no drift.

### US3 — Advanced safe options (P0/P1)
As a power user, I can tune discovery probes, timing, parallelism, port selection, version/OS detection, NSE
expressions and debug output using explicit flags with validation.

**Acceptance criteria**
- Each option in `data-model.md` §2 is accepted, validated and appears in the dry-run command.
- Invalid values are rejected with exit code 2 and a message naming the option.
- Blocked offensive/evasion flags are rejected with exit code 4 even in `custom`/`advanced` mode.
- `--explain` prints why each argument was added (profile / override / privilege adaptation / skipped NSE).

### US4 — Data-driven profiles and pipelines (P1)
As an operator, I can define profiles with `extends`, variables and ordered stages, run one stage, and resume a
failed workflow from its last completed stage.

**Acceptance criteria**
- Built-in profiles load from data files; `--list-profiles` output is unchanged for existing names.
- A user profile in `~/.config/xamltech-nmap-toolkit/profiles/` can extend `standard` and override ports.
- A pipeline stage can be gated by `when: port in 22,80,443`; `--stage 2` runs only that stage.
- `--resume RUN_DIR` reuses `hosts-up.txt` / `ports-open.txt` and skips completed stages.

### US5 — CI-friendly reporting (P1)
As a CI user, I can consume SARIF, suppress known false positives via a baseline, and fail a job on severity.

**Acceptance criteria**
- `report.py sarif RUN_DIR -o out.sarif` produces valid SARIF 2.1.0 with `result.ruleId` per finding.
- `report.py baseline create RUN_DIR -b baseline.json` and `report --baseline baseline.json` filter suppressed
  findings while preserving raw ones in `report.json`.
- `diff --fail-on HIGH` exits 10 only when a new finding is HIGH or CRITICAL.
- Report JSON includes `schema_version` and a SHA-256 manifest of native inputs.

### US6 — Compliance and approval (P1)
As a security lead, I can require an approved, hashed scan plan and restrict runs to a scope with time windows.

**Acceptance criteria**
- `--dry-run --json` emits a deterministic plan with a SHA-256 hash.
- `--plan-file plan.json --plan-hash HASH` refuses to run on mismatch (exit 4).
- Scope v2 supports allow/deny CIDRs, wildcard names, `valid_from`/`valid_until` and `max_hosts`; violations exit 4.
- Audit log records operator, sudo user, toolkit commit, command and input hashes; logs are `0600`.

### US7 — Packaging and ergonomics (P2)
As a user, I get zsh/fish completions, a generated man page, a single version constant, presets and an
interactive advanced mode.

**Acceptance criteria**
- `make completions` regenerates bash/zsh/fish files from the registry; no manual edits needed.
- Version is defined once and consumed by the CLI, report engine, man page and release workflow.
- `--save-preset NAME` / `--preset NAME` round-trip; interactive menu exposes an "Advanced options" screen.

## Functional requirements

| ID | Priority | Requirement |
|---|---|---|
| FR-001 | P0 | Fix `-t` space-separated target parsing via `set_targets` |
| FR-002 | P0 | Fix `diff` sort of finding keys with mixed `None`/int ports |
| FR-003 | P0 | Remove duplicate `ui_init` call in `main()` |
| FR-004 | P0 | Consolidate duplicated profile docs into one canonical file |
| FR-010 | P0 | Option registry in `lib/options.sh` with declared schema |
| FR-011 | P0 | Help and usage generated from registry |
| FR-012 | P0 | `parse_args` driven by registry + action table |
| FR-013 | P0 | Completion files generated from registry |
| FR-014 | P0 | `CONFIG_KEYS` generated from registry |
| FR-015 | P0 | `--dump-options --json` and `--explain` |
| FR-016 | P0 | Consistency test across registry/help/completion/config/docs |
| FR-020 | P0 | Discovery probes: `-PS/-PA/-PU/-PY`, `-PE/-PP/-PM/-PO`, `-PR`, `--disable-arp-ping`, `--send-ip`, `--send-eth` |
| FR-021 | P0 | Techniques: `-sT/-sS/-sA/-sW/-sM/-sF/-sN/-sX/-sU/-sO/-sY/-sZ`, guarded `--scanflags` |
| FR-022 | P0 | Timing: all `--min-*`, `--max-*`, `--initial-rtt-timeout`, `--scan-delay`, `--max-scan-delay`, `--max-attempts`, `--script-timeout` |
| FR-023 | P0 | Ports: `-p`, `--top-ports`, `--exclude-ports`, `-F`, `-r`, `-p-` |
| FR-024 | P1 | Detection: `--version-intensity`, `--version-light`, `--version-all`, `--version-trace`, `-O`, `--osscan-limit`, `--osscan-guess`, `--fuzzy` |
| FR-025 | P1 | NSE: `--script-args-file`, `--script-trace`, expression builder, maintenance `--script-updatedb` |
| FR-026 | P1 | Debug: `-vv`, `-ddd`, `--packet-trace` only with `--verbose` |
| FR-027 | P1 | Network: `-6`, `-e`, `--source-port`, `--data-length`, `--ttl`, `--mtu` |
| FR-028 | P0 | Extend guard denylist; `--policy advanced` + `--ack-risk` opt-in |
| FR-030 | P1 | Profile data files with `extends` and variables |
| FR-031 | P1 | User profiles under XDG config path |
| FR-032 | P1 | Pipeline DSL with ordered stages and `when` conditions |
| FR-033 | P1 | `--stage NAME` and `--resume RUN_DIR` |
| FR-034 | P2 | Incremental scan against a baseline |
| FR-040 | P1 | SARIF 2.1.0 export |
| FR-041 | P1 | Baseline create/apply with suppression tracking |
| FR-042 | P1 | `diff --fail-on SEVERITY` |
| FR-043 | P1 | Report `schema_version` + SHA-256 input manifest + audit log |
| FR-044 | P2 | Webhook and email notifications |
| FR-045 | P2 | HTML side-by-side diff and sortable findings table |
| FR-046 | P2 | Additional `--export` kinds (CSV coordinates, JSON for tool import) |
| FR-050 | P1 | Scope v2: allow/deny, time windows, max hosts, expiry |
| FR-051 | P1 | Deterministic `--dry-run --json` plan hash and `--plan-file`/`--plan-hash` enforcement |
| FR-052 | P1 | `umask 077`, symlink checks, atomic writes, `0600` logs |
| FR-060 | P2 | Cache `nmap --version`; stage checkpoints; atomic `latest` symlink |
| FR-061 | P2 | Single version constant; man page; zsh/fish completions |
| FR-062 | P2 | Release workflow with checksums; CI adds ruff/mypy/bandit + doc link check |
| FR-070 | P2 | Interactive advanced mode, presets, command replay, target groups, `--estimate` |

## Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-001 | `make test` and `make lint` pass on every commit; full suite < 180s |
| NFR-002 | No new runtime dependency; Python stdlib only |
| NFR-003 | Existing CLI flags, profiles, run layout and exit codes remain valid |
| NFR-004 | Every new flag has positive and negative tests before merge |
| NFR-005 | Dry-run never creates files or contacts the network |
| NFR-006 | No host-derived data reaches HTML/CSV/Markdown unescaped |
| NFR-007 | Help text fits 80 columns in plain mode |
| NFR-008 | Registry generation is deterministic (sorted output, no timestamps) |

## Edge cases

- Targets with IPv6 brackets, CIDR, octet ranges, wildcards and multiple `-t` occurrences.
- Findings with `port: null`, duplicate findings on one host, unresolvable hostnames in scope.
- Interrupted workflow with partial XML: resume must reuse only complete stage outputs.
- Non-TTY execution: no spinner, no prompts, no typed consent without `--authorized`.
- Running under sudo: result ownership returned to `SUDO_USER`; audit log records both identities.
- Read-only output directory: fail with exit 1 and actionable message, no partial reports.

## Dependencies / assumptions

- Bash 4.4+, GNU coreutils (`find -printf`, `xargs -d`), Nmap 7.x, optional Python 3.10+.
- `shellcheck` available in CI (locally optional); `python3` required for reports/CI gates.
- Current baseline: `a40394c`, `tests/run.sh` reports 116 passed / 1 skipped.

## Out of scope

See Non-goals. Roadmap ideas explicitly deferred: SARIF ticket export to Jira, webhook secret storage,
authenticated `odoo.conf` hardening checks over SSH, runtime Odoo support-matrix fetch.

## References

- `.speckit/constitution.md` — principles and quality gates
- `specs/001-advanced-toolkit/plan.md` — technical approach
- `specs/001-advanced-toolkit/data-model.md` — schemas for registry, profiles, pipelines, reports, scope
- `specs/001-advanced-toolkit/tasks.md` — implementation tasks
- `specs/001-advanced-toolkit/checklists/requirements.md` — review checklist
