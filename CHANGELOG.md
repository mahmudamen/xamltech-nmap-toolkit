# Changelog

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
