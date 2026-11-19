# Reports, findings, diff

Every run creates `results/<timestamp>_<profile>_<target>/` (and a `results/latest` symlink):

| File | Purpose |
|---|---|
| `nmap.txt / nmap.xml / nmap.gnmap` | Native Nmap outputs (final stage for workflows) |
| `stage1-discovery.* / stage2-ports.*` | Earlier workflow stages |
| `report.json` | Merged, normalised data - input for `--diff`, `--history`, `--export` |
| `report.html` | Self-contained report: severity bar, filterable findings, host accordion, dark/light/print |
| `report.md` | Markdown summary for tickets and wikis |
| `hosts.csv / services.csv / findings.csv` | Spreadsheet-friendly (formula-injection safe) |
| `hosts-up.txt / host-latency.txt` | Live hosts and parallel ping latency |
| `diff-vs-previous.txt` | Changes since the last run of the same profile + target |
| `command.txt, metadata.json, toolkit.log, summary.txt` | Reproducibility and audit trail |

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

## Diff / CI usage
```bash
./nmap-toolkit.sh --diff results/<old-run> latest
python3 lib/report.py diff old/report.json new/report.json --fail-on-change   # exit 10 if anything changed
```
