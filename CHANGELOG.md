# Changelog

## [2.1.1] - 2026-11-22

### Added
- ShellCheck configuration (`.shellcheckrc`) for cross-file globals and comma-separated Nmap port arguments.
- Characterization tests for workflow stage failure handling (`abort` vs `continue`, successful stages never abort).

### Changed
- Shell hygiene: replaced unsafe word-splitting with `mapfile`, removed unused locals/globals, and extracted
  `stage_should_abort()` so stage failure policy is testable in isolation.
- No CLI flags, exit codes, output layout or report formats changed; `--version` now reports `2.1.1`.

## [2.1.0] - 2026-11-19

### Added
- Registry-driven option system (`lib/options.sh`): one source for help, validation, completion, config keys,
  generated `docs/OPTIONS.md`, man page, and `--dump-options`; bash/zsh/fish completions are generated artifacts.
- Advanced Nmap options with typed validation, privilege adaptation and an explainable plan (`--explain`);
  `--policy advanced --ack-risk` gates moderate-risk overrides.
- User profiles (`extends`, `ports`, `args`) and declarative, staged/resumable workflows (`profiles/stages.txt`,
  `--stage`, `--resume`), with hashed stage markers, `when` conditions and `--incremental` baseline filtering.
- Report schema v2 with stable `rule_id`, native-XML SHA-256 manifest, `baseline create|check`, SARIF 2.1.0 output,
  `diff --fail-on SEVERITY` (exit `10`), webhook/email hooks, and `csv-coords` / `json-arm` exports.
- Compliance: deterministic `--dry-run --json` plans, `--plan-file` + `--plan-hash` verification, JSON scope v2
  (`deny`, `valid_from`, `valid_until`/`expires`, `max_hosts`), and a `0600` audit log.
- UX/rollout: registry category screen in interactive mode, `--save-preset` / `--preset`, `--replay`,
  `--target-group`, `--estimate`, and `make option-drift`.

### Changed
- `results/latest` is updated atomically; run directories are created under `umask 077`.
- `--version` now reads the single version constant in `lib/report.py`; hard-coded version removed from the CLI.
- Help/completions/docs are generated and drift-checked instead of maintained by hand.

### Fixed
- Mixed `None`/int finding sorting, duplicate `ui_init`, repeatable/space-separated `--target`, and plan-hash
  verification of wrapped JSON plans.

## [2.0.0] - 2026-11-17

### Added
- Modular layout (`lib/ui|core|nse|profiles|scan|interactive.sh`, `lib/report.py`, `lib/render.awk`)
- Gradient headline banner, 6 themes, truecolor/256/ASCII rendering, `NO_COLOR` support
- Arrow-key interactive menus with automatic local-subnet detection
- Live colorized Nmap output with inline progress bar, spinner, severity dashboard
- 33 profiles (was 7): ARP/multi-probe sweeps, UDP, firewall mapping, polite, NSE packs, service families,
  Odoo / POS / IoT, audit; `recon` and `inventory` multi-stage workflows
- NSE script validation against local `script.db`; honest User-Agent; `--list-scripts`, `--script-help`
- Custom `scripts/odoo-info.nse` (version, public DB list, DB manager exposure) - read-only
- Reports: JSON, CSV, Markdown, self-contained HTML; heuristic findings with severity and advice
- Change detection (`--diff`, `--history`, automatic diff vs previous run, `--fail-on-change`)
- `--export` handoff lists for ZAP/Burp, Masscan, OpenVAS/Nessus
- Scope file enforcement, typed consent for non-private targets, `--authorized`, `--dry-run`
- Tuning flags: timing, ports, scripts, script args, rate, retries, host timeout, DNS, interface, exclude, IPv6
- Config files (whitelisted keys, never sourced); `--doctor`; `--online` version check
- Installer, bash completion, Makefile, example config/scope, 117-check test suite, CI

### Changed
- Target validation is now an allowlist (was a metacharacter blocklist)
- Result directories are named `<time>_<profile>_<target>` and `results/latest` is maintained
- Latency probes run in parallel; hosts-up extraction handles IPv6 and MAC lines correctly
- Unprivileged runs adapt automatically instead of failing

### Fixed
- `--args "-sV --top-ports 100"` was passed to Nmap as a single argument (strict `IFS`); now quote-aware splitting
- SYN-scan profiles failed outright for non-root users

### Removed / not included by design
- No brute-force, DoS, exploit or fuzzer NSE support; no output-flag passthrough in custom args

## [1.0.0] - 2026-10-03
Initial release.
