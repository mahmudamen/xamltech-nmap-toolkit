<div align="center">

# XamlTech Nmap Toolkit  `v2.1`

**A colorful, scriptable command-line cockpit for Nmap - discovery, 30+ scan profiles, NSE intelligence,
change detection and shareable HTML reports.**

`Bash` · `Nmap` · `NSE` · `Python (stdlib)` · `Linux` · `MIT`

![terminal](docs/assets/terminal-recon.png)

</div>

> **Authorization required.** Use this project only against systems and networks you own or are explicitly
> authorized to test.

---

## Why v2

| | v1 | **v2** |
|---|---|---|
| Interface | prompts | gradient headline, 6 themes, arrow-key menus, live progress bar, colorized Nmap output |
| Profiles | 7 | **33** + multi-stage `recon` / `inventory` workflows |
| NSE | none | validated script packs (web, TLS, SSH, SMB, DB, mail, RDP, FTP, **Odoo**, **POS**, IoT, audit) + custom `odoo-info.nse` |
| Output | `.txt` + `.xml` | + `.gnmap`, **JSON, CSV, Markdown, self-contained HTML**, findings with severity |
| Change detection | - | automatic diff against the previous run, `--diff`, `--history` |
| Safety | metachar blocklist | allowlist validation, scope file, typed consent for non-private targets, blocked brute/DoS/exploit NSE, dry-run |
| Unprivileged use | SYN scans fail | automatic, reported fallback to TCP-connect |
| Tests | ShellCheck only | 117 automated checks, incl. live scans of localhost and hostile-banner injection tests |

![report](docs/assets/html-report.png)

## Install

```bash
sudo apt install nmap python3          # Debian/Ubuntu (python3 is optional but enables reports)
git clone https://github.com/mahmudamen/xamltech-nmap-toolkit.git
cd xamltech-nmap-toolkit
./nmap-toolkit.sh --doctor             # run in place, or:
./install.sh --user                    # installs `xamltech-nmap` + bash completion under ~/.local
```

Requirements: Linux, Bash 4.4+, Nmap, standard coreutils. Optional: `python3` (reports), `ping`, `ip`.

## Quick start

```bash
./nmap-toolkit.sh                                        # guided, arrow-key menu (auto-detects your subnets)
./nmap-toolkit.sh -t 192.168.1.0/24 -p recon --open      # discover → ports → versions/scripts, then open the report
./nmap-toolkit.sh -t erp.example.com -p odoo             # Odoo exposure review
./nmap-toolkit.sh -t 10.0.0.0/24 -p audit --scope scope.txt --sudo
./nmap-toolkit.sh -t 10.0.0.5 -p tls --dry-run           # show the exact Nmap command, run nothing
```

## Highlights

**Smart workflows.** `recon` finds live hosts, port-scans only those, then runs version detection and scripts
*only on ports that actually exist* - minutes instead of hours versus a blanket `-p-` scan.

**Odoo & POS aware** (built for ERP estates): the bundled `scripts/odoo-info.nse` (read-only) reports the Odoo
version, whether the **database list** is public, whether the **database manager** page is reachable and whether
the version is out of support. The `pos` profile covers ESC/POS printers (9100), CUPS/IPP and Odoo POS ports.

**Findings engine.** Exposed Telnet/FTP/RDP/databases, SMBv1 & signing, anonymous FTP, unauthenticated
Redis/Memcached, expired/self-signed/SHA-1 certificates, TLS 1.0/1.1, weak ciphers/SSH algorithms, risky HTTP
methods… graded `CRITICAL → INFO` with a recommendation. They are *hints* - verify before acting.

**Change detection.** Every run is compared with the previous run of the same profile + target:
new hosts, opened/closed ports, service changes, new/resolved findings (`rule_id` on every finding).
`--diff A B`, `--history`, `baseline create|check`, SARIF export, and
`python3 lib/report.py diff … --fail-on HIGH` (exit `10`) for CI.

**Graceful privileges.** Not root? SYN→connect, UDP/OS detection dropped - and the plan tells you exactly what
changed. `--sudo` re-runs through sudo (explicit opt-in, never automatic). cap_net_raw is detected too.

**Handoffs.** `--export urls|hostports|hosts|ports|openvas` feeds ZAP/Burp, Masscan, OpenVAS/Nessus. See
[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## Profiles (33)

`discovery arp sweep diagnostic list broadcast` · `quick standard deep full os udp firewall polite` ·
`default safe-nse discovery-nse vuln-safe vuln vulners` · `web tls ssh smb dns db mail rdp ftp` ·
`odoo pos iot` · `audit` · workflows `recon inventory` · `custom`

Full table with risk, privilege need and speed: **[docs/PROFILES.md](docs/PROFILES.md)** or `--list-profiles`.

## Options at a glance

```
Targets   -t/--target  -L/--target-file  --exclude  --scope FILE
Profiles  -p/--profile  -a/--args (custom)
Tuning    -T 0-5  --ports  --top-ports  --max-rate  --max-retries  --host-timeout
          --min-rate  --min-parallelism  --scanflags  --version-intensity  --mtu  --ttl
NSE       --scripts  --script-args  --list-scripts [F]  --script-help NAME
Output    -o DIR  --formats json,csv,md,html  --open  --notify  --no-latency  --theme  --no-color
Safety    --authorized  --dry-run  --sudo  -y  --scope FILE  --policy advanced --ack-risk
          --json  --plan-file PLAN.json --plan-hash HASH  --explain
Automation --save-preset NAME  --preset NAME  --replay N  --target-group NAME
          --stage discovery|ports|services  --resume RUN_DIR  --estimate
          --incremental baseline/report.json
Tools     --list-profiles  --history  --diff A B  --open-report  --export KIND
          --doctor  --check-updates [--online]  --config FILE  --dump-options
```

Config files (`/etc/xamltech-nmap-toolkit.conf`, `~/.config/xamltech-nmap-toolkit/config`, `./.xamltech-nmap.conf`)
are parsed as **data** with a key whitelist - never sourced. Example: [config/xamltech-nmap.conf.example](config/xamltech-nmap.conf.example).
The option registry in `lib/options.sh` is the single source of truth for help, completions (bash/zsh/fish),
the generated man page and [docs/OPTIONS.md](docs/OPTIONS.md); regenerate with `make completions options-docs`.

## Security model

* Allowlist target validation; no shell string is ever built from input (Nmap args are arrays).
* Non-private/unresolvable targets need a typed `I AM AUTHORIZED` (interactive) or `--authorized` (automation).
* `--scope FILE` refuses anything outside your authorized CIDRs/hosts, with CIDR-containment checks. JSON scope v2
  adds `deny`, `valid_from`, `valid_until`/`expires` and `max_hosts` (violations exit `4`).
* Approved automation can bind a dry-run to a hash: `--plan-file PLAN.json --plan-hash HASH`. Run metadata is
  appended to a `0600` audit log with operator, commit, plan hash and exit code.
* **Not included, by design:** brute-force, DoS, exploit and fuzzer NSE categories, decoys, source spoofing,
  proxies, `--badsum`, fragmentation/evasion, output-flag passthrough, silent privilege escalation. HTTP scripts identify themselves honestly in the User-Agent.
* Scan results are untrusted input: HTML/CSV/Markdown output is escaped or neutralised; XML entities are rejected.

## Results layout

```text
results/2026-11-17_102138_recon_192.168.1.0_24/
├── nmap.txt  nmap.xml  nmap.gnmap          native Nmap output (+ stage1-/stage2- for workflows)
├── report.html  report.md  report.json     reports
├── hosts.csv  services.csv  findings.csv   spreadsheets
├── hosts-up.txt  host-latency.txt          inventory + parallel latency
├── diff-vs-previous.txt                    what changed since last time
└── command.txt  metadata.json  toolkit.log  summary.txt   audit trail
```

## Development

```bash
make test      # static, validation, guard rails, report engine, diff, compliance, UX, live localhost scans
make lint      # ShellCheck + py_compile
make option-drift   # regenerate and verify help/completions/docs are in sync
```
CI runs both on every push. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Docs

[USAGE](docs/USAGE.md) · [PROFILES](docs/PROFILES.md) · [EXAMPLES](docs/EXAMPLES.md) · [REPORTS](docs/REPORTS.md) ·
[INTEGRATIONS](docs/INTEGRATIONS.md) · [SECURITY](SECURITY.md) · [CHANGELOG](CHANGELOG.md)

## Author

**Mahmoud Mohamed Amin** - Senior Odoo Developer, co-founder of XamlTech · GitHub
[@mahmudamen](https://github.com/mahmudamen) · https://xamltech.com

MIT License - see [LICENSE](LICENSE).

## Disclaimer

For legitimate network administration, diagnostics, inventory and authorized security testing. You are
responsible for complying with applicable laws, policies, contracts and authorization requirements.
