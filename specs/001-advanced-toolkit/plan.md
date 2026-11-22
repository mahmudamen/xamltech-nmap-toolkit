# Implementation Plan: 001-advanced-toolkit

## Technical approach

Keep the current architecture (Bash entry point + sourced `lib/*.sh` + stdlib Python engine). Add one new
dependency-free component — the option registry — and make every existing option surface a projection of it.
Move profile/pipeline definitions from Bash arrays to plain-text data files parsed by the existing whitelist
pattern (no YAML/TOML dependency). Extend the Python report engine with SARIF, baselines and schema versioning.

### Architecture after change

```text
nmap-toolkit.sh          thin CLI: ui_init, config load, parse_args from registry, dispatch
lib/options.sh           NEW: registry + validators + generators (help/completion/config/docs)
lib/core.sh              config, validation, scope, authorisation, privilege adaptation, guard rails
lib/profiles.sh          profile loader (reads profiles/*.txt), profile_field, overrides
lib/scan.sh              run dirs, stages, resume, post-process, reports
lib/ui.sh                terminal primitives (unchanged API)
lib/interactive.sh       menus + advanced screen
lib/report.py            parsing, findings, report json/csv/md/html/sarif, diff, history, scope, export
lib/render.awk           live stdout renderer
profiles/*.txt           NEW: built-in profile/pipeline definitions (pipe-delimited, comments with #)
config/scope.example.txt scope v2 example
completions/             generated bash + zsh + fish
docs/                    generated PROFILES.md, hand-written USAGE/EXAMPLES/REPORTS/INTEGRATIONS
.speckit/                constitution
specs/001-advanced-toolkit/
```

### Data flow for a scan

```text
CLI args -> registry validation -> config defaults -> profile data -> pipeline stages
         -> apply_overrides -> privilege adaptation -> guard rails -> Nmap argv (array)
         -> native output -> report.py -> report.json + formats -> dashboard + diff
         -> audit log + manifest (0600)
```

## Decisions

1. **Registry format:** pipe-delimited records in `lib/options.sh`, mirroring `PROFILE_TABLE`. Fields:
   `flag|value|validator|nmap_template|risk|root|category|default|description`. Parsed with `IFS='|' read`.
   No associative arrays for ordering-critical data; Bash 4.4+ is already required.
2. **Generators over templates:** `lib/options.sh` exposes `options_emit_help`, `options_emit_completion`,
   `options_emit_config_keys`. `make completions` and `make docs` write generated files; CI re-runs generators
   and fails if output differs (via `git diff --exit-code`).
3. **Actions stay explicit:** non-scan actions (`--diff`, `--export`, `--doctor`, …) live in a separate
   `ACTION_TABLE`; the generic parse loop consumes registry flags and delegates actions.
4. **Profile data format:** same pipe-delimited style as today, plus optional `stage` records:
   `stage|name|profile|targets|when|ports|scripts|timeout|on_fail`. A parser validates all fields.
5. **Resume:** each stage writes `stage-N-<name>.done` containing input hashes and exit code after success.
   `--resume` reads these and skips completed stages; partial XML is never treated as complete.
6. **Baselines:** separate JSON file listing suppressed `(severity, host, port, title, source)` tuples with a
   reason and expiry. Filtering happens at presentation time; `report.json` keeps raw + suppressed counts.
7. **SARIF:** implement in `report.py` using `json.dump`; rule metadata derived from `SEVERITIES` and finding
   titles. No external SARIF library.
8. **Version:** single `VERSION` in `lib/report.py`, read by the CLI via
   `python3 -I lib/report.py version`; `nmap-toolkit.sh` no longer hardcodes `SCRIPT_VERSION`.
9. **Safety:** new flags are added to the registry with `risk` metadata; `guard_custom_args` gains a denylist
   for evasion/spoof tokens; `--policy advanced` requires `--ack-risk` and is recorded in the audit log.

## Phase mapping

| Phase | Spec tasks | Outcome |
|---|---|---|
| M0 Foundation | T001–T005 | Known defects fixed, docs consolidated, suite green |
| M1 Registry | T006–T016 | One source of truth, generators + drift test |
| M2 Advanced options | T017–T030 | Full safe Nmap option coverage with guards |
| M3 Pipelines | T031–T040 | Data-driven profiles, stages, resume, incremental |
| M4 Reporting | T041–T051 | SARIF, baseline, severity gates, manifest, audit |
| M5 Compliance | T052–T058 | Scope v2, hashed plans, safe file handling |
| M6 Packaging | T059–T070 | Cache, checkpoints, multi-shell completions, man, CI |
| M7 UX | T071–T078 | Advanced menu, presets, replay, groups, estimate |

## Test strategy

- **Unit:** `tests/run.sh` helpers (`check`, `check_not`, `contains`, `absent`) with `--dry-run` only — no network.
- **Registry drift:** generate to a temp dir, diff against committed artifacts.
- **Fixtures:** `tests/fixtures/sample-vuln.xml` extended with host-script finding + hostile banner;
  new `tests/fixtures/sample-mixed-findings.json`.
- **Live:** localhost HTTP service scan plus one guarded advanced-options scan.
- **Security:** hostile banner injection into HTML/CSV/Markdown; XML entity rejection; blocked flags;
  out-of-scope targets; plan-hash mismatch; file permissions after sudo run.
- **Performance:** time `make test` and a 1-host dry-run; version lookup cache asserted by call count.

## Migration / compatibility

- Existing `PROFILE_TABLE` names remain; new files are additive. Keep `lib/profiles.sh` function signatures.
- `report.json` gains `schema_version`; readers ignore unknown keys. `diff`/`history` accept both.
- Completion files are overwritten by generators; users' manual edits are intentionally not preserved (documented).
- Config keys remain whitelisted; new keys are generated from registry, never sourced.

## Risks

| Risk | Mitigation |
|---|---|
| Registry refactor breaks CLI parsing | Keep `parse_args` case arms during transition; compare dry-run output before/after via snapshot test |
| Generated docs differ in CI | Commit generated files; generator is deterministic and sorted |
| Advanced flags accidentally enable offensive NSE | Dual guard: registry `risk` + `guard_script_spec` + test matrix |
| Profile data files become another drift source | `--list-profiles` and docs generated from the same loader |
| Report schema change breaks consumers | Bump `schema_version`, keep old keys, test `diff` against v1 fixture |
| Sudo + preserved env | Explicit env allowlist for re-exec; audit operator and sudo user |

## Definition of done

- All tasks in `tasks.md` checked, with verification command recorded per task.
- `make test && make lint` green; `specs/001-advanced-toolkit/checklists/requirements.md` fully checked.
- README, USAGE, SECURITY and CHANGELOG updated; generators produce no diff.
- No secrets, no new runtime dependencies, no behaviour outside the constitution.
