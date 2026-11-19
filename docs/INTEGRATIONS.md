# Working with other tools

Nmap is the right tool for **discovery, inventory and safe service checks**. Other stages of an authorized
assessment call for specialised tools. This toolkit deliberately does **not** reimplement them (and does not
include exploitation or firewall-evasion features); it hands clean, scoped data to them instead.

| Stage | Tool | Gap it fills |
|---|---|---|
| Very fast, wide port discovery | **Masscan** | Internet-scale / huge ranges at line rate |
| Deep vulnerability assessment | **OpenVAS / Greenbone, Nessus** | Authenticated checks, large CVE feeds, compliance |
| Packet-level analysis | **Wireshark / tshark** | Protocol dissection, troubleshooting captures |
| Web application testing | **OWASP ZAP, Burp Suite** | Crawling, injection/auth/session testing |
| Exploitation & validation | **Metasploit** | Only inside a signed, scoped engagement |

## Handoff exports

```bash
./nmap-toolkit.sh -t 10.0.0.0/24 -p recon          # scan first
./nmap-toolkit.sh --export urls latest      > urls.txt        # http(s)://ip[:port] for ZAP / Burp scope
./nmap-toolkit.sh --export hostports latest > hostports.txt   # ip:port
./nmap-toolkit.sh --export hosts latest     > hosts.txt       # live hosts, one per line
./nmap-toolkit.sh --export ports latest                       # 22,80,443,... (for -p lists)
./nmap-toolkit.sh --export openvas latest                     # comma-separated target string for OpenVAS/Nessus
```

Exports contain only addresses and port numbers taken from the scan - never banner text.

## Typical workflows

* **Big network:** Masscan finds candidates quickly → `--export`-style host list → `nmap-toolkit.sh -L hosts.txt -p standard`
  for accurate service/version detection (Masscan banners are not a substitute).
* **Vulnerability management:** `-p audit` or `-p recon` weekly; `--diff` shows drift; feed `--export openvas` into a
  scheduled Greenbone/Nessus scan for authenticated CVE coverage.
* **Web apps:** `-p web` or `-p odoo` → `--export urls` → import as ZAP/Burp targets.
* **Troubleshooting:** when a scan result looks wrong (filtered vs closed, odd resets), capture with
  `tshark -i eth0 host <target>` while re-running the scan and inspect the handshake.

Always keep the same **scope file** (`--scope`) for every tool in the engagement.
