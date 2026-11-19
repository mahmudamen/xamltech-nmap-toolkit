# Reports, findings, diff

Every run creates `results/<timestamp>_<profile>_<target>/` (and a `results/latest` symlink):

| File | Purpose |
|---|---|
| `nmap.txt / nmap.xml / nmap.gnmap` | Native Nmap outputs (final stage for workflows) |
| `stage1-discovery.* / stage2-ports.*` | Earlier workflow stages |
| `report.json` | Merged, normalised data (`schema_version: 2`) - input for `--diff`, `--history`, `--export` |
| `report.sarif` | Optional SARIF 2.1.0 for code-scanning dashboards (`report.py sarif RUN_DIR -o FILE`) |
| `report.html` | Self-contained report: severity bar, filterable findings (sortable columns), host accordion, dark/light/print |
| `report.md` | Markdown summary for tickets and wikis |
| `hosts.csv / services.csv / findings.csv` | Spreadsheet-friendly (formula-injection safe) |
| `hosts-up.txt / host-latency.txt` | Live hosts and parallel ping latency |
| `diff-vs-previous.txt` | Changes since the last run of the same profile + target |
| `command.txt, metadata.json, toolkit.log, summary.txt, audit.log` | Reproducibility and audit trail (`audit.log` is `0600`) |
| `manifest.json` | SHA-256 of native Nmap XML inputs; stage markers carry output hashes |

## Findings are hints, not verdicts
Severity (`CRITICAL`…`INFO`) comes from simple, readable rules in `lib/report.py`: risky exposed services
(Telnet, FTP, RDP, databases…), NSE results (`VULNERABLE`, SMBv1, SMB signing, anonymous FTP, unauthenticated
Redis/Memcached), TLS problems (expired/self-signed/SHA-1 certificates, SSLv3/TLS1.0/1.1, weak ciphers), weak SSH
algorithms, risky HTTP methods, and Odoo exposure (public DB list / DB manager, unsupported versions).
Verify before acting; for authenticated CVE coverage use a real vulnerability scanner (see INTEGRATIONS.md).
Edit `ODOO_MIN_SUPPORTED` in `lib/report.py` to match the Odoo versions you support.

## Safety of report content
Banners and script output come from scanned hosts and are untrusted: HTML is escaped, CSV cells that start with
`= + - @` are prefixed, Markdown is escaped, and XML with entity declarations is rejected.

## Baselines and diff / CI usage
```bash
python3 lib/report.py baseline create results/<accepted-run> -b baseline.json
python3 lib/report.py baseline check results/<new-run> -b baseline.json      # known findings become suppressed
./nmap-toolkit.sh --diff results/<old-run> latest
python3 lib/report.py diff old/report.json new/report.json --fail-on HIGH    # exit 10 at/above HIGH
```
Findings carry a stable `rule_id` in JSON/CSV/Markdown/HTML. `--formats` may include `csv-coords` and `json-arm`
for handoff. `report.py report --xml RUN_DIR/nmap.xml --outdir RUN_DIR --webhook URL --email addr`
posts/sends a compact summary after the report is written; secrets stay in environment variables/CLI arguments,
never in report files.

## Performance baseline
Recorded on the development host (2026-11-19):

| Command | Time |
|---|---|
| `bash tests/run.sh` (full suite, one skipped ShellCheck when absent) | ~104s |
| `./nmap-toolkit.sh -t 127.0.0.1 -p discovery --dry-run --no-color --no-banner` | ~1.1s |

The suite is kept well under the 180s ceiling. `nmap --version` is cached per process and `results/latest` is
updated atomically.
