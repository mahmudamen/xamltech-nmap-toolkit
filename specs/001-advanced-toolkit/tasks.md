# Tasks: 001-advanced-toolkit

**Execution rule:** work top-to-bottom; do not start a task whose dependencies are unchecked. Each task must end
with its verification command passing. Mark `[x]` only after verification. Use `.speckit/constitution.md` as the
authority when a task conflicts with convenience.

## M0 — Foundation fixes (P0)

- [x] **T001** (FR-001) Fix documented space-separated `-t` targets — `nmap-toolkit.sh:137`: replace `for t in $2` with `set_targets "$2"` (it sets `IFS=$' \t\n'`); add `tests/run.sh` case asserting two targets from one `-t`. Verify: `bash tests/run.sh`.
- [x] **T002** (FR-002) Fix `diff` crash — `lib/report.py:774`: sort finding keys with `(k[0], k[1] or 0, k[2])`; add `tests/fixtures/sample-mixed-findings.json` with host-level + port-level findings on the same host and a `diff` test. Verify: `bash tests/run.sh`.
- [x] **T003** (FR-003) Remove duplicate `ui_init` in `main()` (`nmap-toolkit.sh:241`); keep the post-config call; verify `--version`, `--help`, `--doctor`, `--list-profiles` still render. Verify: `bash tests/run.sh`.
- [x] **T004** (FR-004) Wire `tests/test_shellcheck.sh` into `Makefile lint` or delete it; ensure shellcheck coverage is unambiguous. Verify: `make lint`.
- [x] **T005** (FR-004) Make `docs/PROFILES.md` canonical; convert `docs/SCAN_PROFILES.md` to a pointer or remove it and fix all links (grep the repo). Verify: link check + `bash tests/run.sh`.

## M1 — Option registry (P0)

Depends: M0.

- [x] **T006** (FR-010) Create `lib/options.sh` with the 9-field registry format from `data-model.md` §1; seed it with all current flags from `nmap-toolkit.sh:58–192`. Verify: `bash -n lib/options.sh`.
- [x] **T007** (FR-010) Implement `option_list`, `option_get`, `option_validate`, `option_aliases` helpers; aliases resolved to canonical flag. Verify: unit calls in `tests/run.sh`.
- [x] **T008** (FR-011) Generate `usage()` help sections from the registry by `CATEGORY`; preserve current section order and 80-column plain output. Verify: `--help` snapshot diff.
- [x] **T009** (FR-012) Add `ACTION_TABLE` for `--diff`, `--export`, `--open-report`, `--list-scripts`, `--script-help`, `--doctor`, `--check-updates`, `--version`, `--help`; refactor `parse_args` to consume registry flags generically. Verify: `bash tests/run.sh`.
- [x] **T010** (FR-015) Add `--dump-options --json` emitting the registry as JSON (sorted, deterministic). Verify: JSON parse + stable hash across runs.
- [x] **T011** (FR-015) Add `--explain` printing profile origin, each override, privilege adaptation and skipped NSE scripts. Verify: dry-run test with `-sS` as non-root.
- [x] **T012** (FR-013) Implement `options_emit_completion` for bash; regenerate `completions/xamltech-nmap.bash`. Verify: generated file matches regeneration.
- [x] **T013** (FR-014) Replace hand-written `CONFIG_KEYS` in `lib/core.sh:48` with `options_emit_config_keys`; keep `COLOR_MODE`/`ONLINE_CHECK` semantics. Verify: config test in `tests/run.sh`.
- [x] **T014** (FR-016) Generate the "Overrides that work with every profile" table in `docs/PROFILES.md` from the registry. Verify: generator diff is empty.
- [x] **T015** (FR-013, FR-016) Add `make completions` and `make docs` targets; both deterministic and sorted. Verify: run twice, `git diff --exit-code`.
- [x] **T016** (FR-016) Add drift test: compare registry-derived help, completion, config keys and docs against committed files. Verify: `bash tests/run.sh`.

## M2 — Advanced safe Nmap options (P0/P1)

Depends: M1. All flags must be registry entries with validator, Nmap template, positive/negative tests.

- [x] **T017** (FR-020) Add discovery probes: `-PS/-PA/-PU/-PY` port lists, `-PE/-PP/-PM/-PO`, `-PR`, `--disable-arp-ping`, `--send-ip`, `--send-eth`. Verify: dry-run assertions.
- [x] **T018** (FR-021) Add techniques `-sT/-sS/-sA/-sW/-sM/-sF/-sN/-sX/-sU/-sO/-sY/-sZ` and guarded `--scanflags` (reject raw `0x` values outside `^[0-9A-Fa-f()|]+$`). Verify: dry-run + negative tests.
- [x] **T019** (FR-022) Add timing/parallelism flags: `--min-rate`, `--min-parallelism`, `--max-parallelism`, `--min-hostgroup`, `--max-hostgroup`, `--initial-rtt-timeout`, `--min-rtt-timeout`, `--max-rtt-timeout`, `--scan-delay`, `--max-scan-delay`, `--max-attempts`, `--script-timeout`, `--host-timeout`. Verify: validation matrix.
- [x] **T020** (FR-023) Add port flags `--exclude-ports`, `-F`, `-r`, `-p-` and ensure `_strip_args` in `lib/profiles.sh:229` keeps them consistent with `--ports`/`--top-ports`. Verify: override tests.
- [x] **T021** (FR-024) Add detection flags `--version-intensity`, `--version-light`, `--version-all`, `--version-trace`, `-O`, `--osscan-limit`, `--osscan-guess`, `--fuzzy`. Verify: dry-run + privilege adaptation test.
- [x] **T022** (FR-025) Add NSE flags `--script-args-file`, `--script-trace`, `--script-timeout`, expression builder, and maintenance action `--script-updatedb` (outside scan flow). Verify: guard tests.
- [x] **T023** (FR-026) Add `-vv`, `-ddd`, `--packet-trace`; require `--verbose` for `--packet-trace` (exit 2 otherwise). Verify: positive/negative tests.
- [x] **T024** (FR-027) Add `-6`, `-e`, `--source-port`, `--data-length`, `--ttl`, `--mtu` with numeric/range validators. Verify: dry-run assertions.
- [x] **T025** (FR-028) Extend `guard_custom_args` (`lib/core.sh:342`) denylist with decoy/spoof/proxy/badsum/evasion tokens; add `--policy strict|advanced` and `--ack-risk` requirement. Verify: exit 4 for every blocked token.
- [x] **T026** (FR-010, NFR-004) Add unit tests for every validator in `data-model.md` §1 (valid + invalid cases). Verify: `bash tests/run.sh`.
- [x] **T027** (FR-024) Extend `adapt_args_for_privileges` (`lib/core.sh:370`) to handle new technique/debug flags when unprivileged; add notes to `--explain`. Verify: simulated unprivileged dry-run.
- [x] **T028** (FR-015) Snapshot-test `--explain` output for one profile with overrides and skipped scripts. Verify: `bash tests/run.sh`.
- [x] **T029** (FR-010) Add a dry-run snapshot test asserting the exact Nmap argv for `standard`, `mynetwork`, `recon`, `custom`. Verify: `bash tests/run.sh`.
- [x] **T030** (FR-016) Regenerate completions/docs/version help after M2; confirm no drift. Verify: `make docs completions && git diff --exit-code`.

## M3 — Profiles and pipelines v2 (P1)

Depends: M1, M2.

- [x] **T031** (FR-030) Add `profiles/*.txt` and a loader in `lib/profiles.sh`; keep `profile_field`, `profile_exists`, `profile_risk`, `profile_desc` signatures. Verify: `--list-profiles` output identical to baseline.
- [x] **T032** (FR-030) Implement `extends` and `${TARGETS}/${PORTS_OPEN}` variable substitution with no shell expansion. Verify: user profile dry-run.
- [x] **T033** (FR-031) Load user profiles from `${XDG_CONFIG_HOME:-$HOME/.config}/xamltech-nmap-toolkit/profiles/`; user names override built-ins with a warning. Verify: test with temp XDG dir.
- [x] **T034** (FR-032) Parse `stage` records per `data-model.md` §2 with strict field validation. Verify: malformed stage rejected with exit 2.
- [x] **T035** (FR-032) Refactor `run_workflow` (`lib/scan.sh:192`) to execute declared stages; preserve stage banners and report merge. Verify: recon + inventory dry-run and live localhost test.
- [x] **T036** (FR-033) Add `--stage NAME` to run one stage using prior-stage artifacts. Verify: stage 2 only test.
- [x] **T037** (FR-033) Write `stage-N-<name>.done` markers per `data-model.md` §10 and implement `--resume RUN_DIR` with hash verification. Verify: simulated interrupted run.
- [x] **T038** (FR-032) Evaluate `when: port in …` and `host_count > N` conditions; skipped stages recorded in metadata. Verify: condition tests.
- [x] **T039** (FR-034) Add incremental scan mode against a baseline report: only hosts/ports not already seen. Verify: two-run fixture test.
- [x] **T040** (FR-030–034) Add tests for profile inheritance, user profiles, stage gating, resume and incremental. Verify: `bash tests/run.sh`.

## M4 — Reporting and CI integration (P1/P2)

Depends: M1, M2.

- [x] **T041** (FR-043) Add `schema_version: 2` to `report.json`; keep v1 readers working (`diff`, `history`, `export`). Verify: v1 fixture still parses.
- [x] **T042** (FR-043) Add stable `rule_id` to each finding (e.g. `XT-TELNET-001`) and expose via CSV/Markdown/HTML. Verify: fixture assertions.
- [x] **T043** (FR-043) Compute SHA-256 manifest of native Nmap outputs and write `integrity.native_sha256`. Verify: tamper test.
- [x] **T044** (FR-043) Append JSON audit records to `audit.log` with operator, sudo user, command, plan hash, toolkit commit and rc. Verify: live localhost run produces a valid line.
- [x] **T045** (FR-041) Implement `report.py baseline create|check` per `data-model.md` §7; filter suppressed findings at presentation time with counts. Verify: fixture test.
- [x] **T046** (FR-042) Add `diff --fail-on SEVERITY|CRITICAL|HIGH|MEDIUM|LOW` with exit 10 semantics; keep current `--fail-on-change`. Verify: matrix test.
- [x] **T047** (FR-040) Implement SARIF 2.1.0 writer and `report.py sarif RUN_DIR -o FILE`; validate with a JSON schema check in tests. Verify: fixture test.
- [x] **T048** (FR-044) Add generic webhook notification (POST JSON, `--webhook URL`, timeout 5s, no secrets logged). Verify: local HTTP mock test.
- [x] **T049** (FR-044) Add email notification via `sendmail` if present, opt-in with `--email ADDR`. Verify: mocked sendmail test.
- [x] **T050** (FR-045) Add sortable findings columns and side-by-side diff view to HTML report (with print CSS). Verify: hostile-banner injection test still passes.
- [x] **T051** (FR-046) Extend `--export` with `csv-coords` and `json-arm` kinds; test all kinds. Verify: `bash tests/run.sh`.

## M5 — Safety and compliance (P1)

Depends: M1, M3, M4.

- [x] **T052** (FR-050) Implement scope v2 parser (allow/deny/window/max_hosts/expires) with legacy line compatibility. Verify: fixture matrix.
- [x] **T053** (FR-050) Enforce deny/window/expiry/max_hosts in `report.py scope`; violations print target and exit 4. Verify: `tests/run.sh` scope cases.
- [x] **T054** (FR-051) Emit deterministic `--dry-run --json` plan per `data-model.md` §5 (exclude `created` from hash). Verify: two runs produce identical hash.
- [x] **T055** (FR-051) Add `--plan-file`/`--plan-hash` enforcement before any scan; mismatch exits 4. Verify: positive + tampered-plan test.
- [x] **T056** (FR-052) Set `umask 077` for run dirs; write `audit.log`/`toolkit.log`/`metadata.json` as `0600`. Verify: permission assertions in live test.
- [x] **T057** (FR-052) Reject symlinked `OUTPUT_DIR`/`latest`, write reports via temp file + `mv` (atomic). Verify: symlink attack test.
- [x] **T058** (FR-028, FR-050) Add policy tests: strict default, advanced requires `--ack-risk`, out-of-scope + plan mismatch + blocked flags all exit 4. Verify: `bash tests/run.sh`.

## M6 — Performance and packaging (P2)

Depends: M1–M5.

- [x] **T059** (FR-060) Cache `nmap --version` once per process (used by `env_line`, `write_metadata`, `write_summary`, `doctor`). Verify: call-count test with fake nmap.
- [x] **T060** (FR-060) Checkpoint each pipeline stage with hashed outputs; resume verifies hashes before skipping. Verify: resume test.
- [x] **T061** (FR-060) Update `OUTPUT_DIR/latest` atomically via temp symlink + `mv -T`. Verify: concurrent-run test.
- [x] **T062** (FR-061) Single version constant in `lib/report.py`; CLI reads it via `report.py version`; remove hardcoded `2.0.0` from `nmap-toolkit.sh:17`. Verify: version consistency test.
- [x] **T063** (FR-061) Generate a man page from the registry (`docs/xamltech-nmap.1`). Verify: `man --no-hyphenation` parse test or equivalence check.
- [x] **T064** (FR-061) Generate zsh completion from registry. Verify: `zsh -n` syntax check if available.
- [x] **T065** (FR-061) Generate fish completion from registry. Verify: file presence + content assertions.
- [x] **T066** (FR-062) Add release workflow: tag-triggered, builds checksums for source archive, uploads artifacts. Verify: workflow lint (`actionlint` if available).
- [x] **T067** (FR-062) CI: add `ruff check`, `mypy`, `bandit` for `lib/report.py`; keep shellcheck at warning level. Verify: CI-equivalent local run where tools exist.
- [x] **T068** (FR-062) CI: add markdown link check and generated-artifact diff check. Verify: local script run.
- [x] **T069** (NFR-001) Benchmark `make test` and a 1-host dry-run; document timings and keep suite under 180s. Verify: timed run recorded in `docs/REPORTS.md`.
- [x] **T070** (FR-061) Commit all generated artifacts; `make docs completions && git diff --exit-code` clean. Verify: CI gate simulation.

## M7 — UX and rollout (P2)

Depends: M6.

- [x] **T071** (FR-070) Add "Advanced options" screen to `interactive_mode` (`lib/interactive.sh:213`) exposing registry categories. Verify: non-TTY fallback still works.
- [x] **T072** (FR-070) Add `--save-preset NAME` / `--preset NAME` with JSON array storage. Verify: round-trip test.
- [x] **T073** (FR-070) Add command replay from history (`--replay N`) reusing stored argv. Verify: dry-run replay test.
- [x] **T074** (FR-070) Add target groups/tags (`--target-group NAME`) loaded from config dir. Verify: group expansion test.
- [x] **T075** (FR-070) Add `--estimate` printing expected hosts, stage count and rough duration from prior runs. Verify: fixture-based estimate test.
- [x] **T076** Update `README.md`, `docs/USAGE.md`, `docs/REPORTS.md`, `docs/INTEGRATIONS.md` and `SECURITY.md` for all new flags, policies and schemas. Verify: link check + review.
- [x] **T077** Add `CHANGELOG.md` entry for v2.1.0 listing added/changed/fixed items. Verify: review.
- [x] **T078** Final verification: `make test`, `make lint`, generated-artifact diff, full requirements checklist, no secrets scan. Verify: all green, then mark spec Complete.

## Definition of done

- [x] Every task above is `[x]` with its verification command passing.
- [x] `specs/001-advanced-toolkit/checklists/requirements.md` fully checked.
- [x] No ungenerated copies of help/completion/config/docs exist.
- [x] No new runtime dependencies and no constitution violations.
