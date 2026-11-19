# Requirements checklist: 001-advanced-toolkit

Review at implementation end. Each item must be verified, not merely implemented.

## Spec coverage

- [x] US1 — space-separated `-t` works; mixed-port diff no longer crashes (FR-001, FR-002)
- [x] US2 — registry is single source of truth for help/parse/completion/config/docs (FR-010–FR-016)
- [x] US3 — all safe advanced flags accepted, validated, guarded, explained (FR-020–FR-028)
- [x] US4 — data-driven profiles, stage gating, `--stage`, `--resume` (FR-030–FR-034)
- [x] US5 — SARIF, baseline, severity gates, manifest/audit (FR-040–FR-046)
- [x] US6 — scope v2, hashed plans, safe file handling (FR-050–FR-052)
- [x] US7 — completions, man page, single version, presets, advanced menu (FR-060–FR-070)

## Functional requirements

- [x] FR-001 … FR-016 (foundation + registry)
- [x] FR-020 … FR-028 (advanced options + guards)
- [x] FR-030 … FR-034 (profiles + pipelines)
- [x] FR-040 … FR-046 (reporting)
- [x] FR-050 … FR-052 (compliance)
- [x] FR-060 … FR-062 (packaging)
- [x] FR-070 (UX)

## Non-functional requirements

- [x] NFR-001 — `make test` and `make lint` pass; suite < 180s
- [x] NFR-002 — no new runtime dependency; Python stdlib only
- [x] NFR-003 — existing flags/profiles/layout/exit codes unchanged
- [x] NFR-004 — every new flag has positive and negative tests
- [x] NFR-005 — dry-run creates no files and opens no sockets
- [x] NFR-006 — hostile banner cannot inject HTML/CSV/Markdown
- [x] NFR-007 — plain help fits 80 columns
- [x] NFR-008 — generators deterministic and sorted

## Constitution gates

- [x] No brute/DoS/exploit/fuzzer/intrusive NSE support added
- [x] No decoy/spoof/proxy/badsum/evasion support added
- [x] Config files parsed as data, never sourced
- [x] Nmap arguments remain Bash arrays; no `eval`
- [x] Authorization and scope guards still enforced, tests pass
- [x] Exit code contract unchanged (0/1/2/3/4/130)
- [x] No secrets, tokens, credentials or absolute user paths committed
- [x] `.speckit/constitution.md` amended (with CHANGELOG note) if any principle changed

## Deliverables

- [x] `lib/options.sh` + generators committed
- [x] `profiles/` data files committed
- [x] Generated completions (bash/zsh/fish), man page and docs committed
- [x] New fixtures and tests committed
- [x] CHANGELOG v2.1.0 entry committed
- [x] `git diff --exit-code` clean after regenerating artifacts
