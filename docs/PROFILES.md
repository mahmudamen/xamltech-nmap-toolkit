# Scan profiles

_Generated from `lib/profiles.sh` - run `./nmap-toolkit.sh --list-profiles` for the live view._

**Risk**: `safe` = read-only probing · `moderate` = broader or sends data off-network · `intrusive` = asks for explicit confirmation.  
**Root**: `yes` = best with raw sockets. Unprivileged runs adapt automatically (SYN→connect, UDP/OS detection dropped) and tell you what changed.


## Discovery

| Profile | Risk | Root | Speed | What it does |
|---|---|---|---|---|
| `discovery` | safe | no | fast | Host discovery only (ping scan) - build an inventory |
| `arp` | safe | yes | fast | ARP sweep of the local subnet - most reliable on a LAN |
| `sweep` | safe | no | fast | Multi-probe sweep: ICMP echo/timestamp + TCP SYN/ACK probes |
| `diagnostic` | safe | yes | fast | Discovery + traceroute + latency diagnostics |
| `list` | safe | no | fast | DNS list scan - resolve targets without touching them |
| `broadcast` | safe | no | medium | Target-less LAN broadcast discovery (DHCP, UPnP, mDNS, NetBIOS) |

## Ports

| Profile | Risk | Root | Speed | What it does |
|---|---|---|---|---|
| `quick` | safe | no | fast | Fast scan of the 100 most common TCP ports |
| `standard` | safe | yes | medium | Top-1000 TCP ports + service/version detection |
| `deep` | safe | yes | slow | All 65535 TCP ports + service/version detection |
| `full` | moderate | yes | slow | Everything: all ports, OS, versions, default scripts, traceroute |
| `os` | safe | yes | slow | All TCP ports + service versions + OS fingerprinting |
| `udp` | safe | yes | slow | Top-100 UDP ports + light version probing |
| `firewall` | safe | yes | medium | ACK scan to map firewall rules (filtered vs unfiltered) |
| `polite` | safe | no | slow | Rate-limited scan, gentle on fragile devices and production |

## Scripts

| Profile | Risk | Root | Speed | What it does |
|---|---|---|---|---|
| `default` | safe | no | medium | Service detection + the default NSE script set |
| `safe-nse` | safe | no | medium | All NSE scripts categorised as safe |
| `discovery-nse` | safe | no | medium | NSE discovery scripts (restricted to safe ones) |
| `vuln-safe` | safe | no | slow | Vulnerability checks that are flagged safe (low impact) |
| `vuln` | intrusive | no | slow | Broad vulnerability checks (no brute/DoS/exploit) - may disturb fragile services |
| `vulners` | moderate | no | medium | CVE lookup via vulners.com (sends service versions off-network) |

## Services

| Profile | Risk | Root | Speed | What it does |
|---|---|---|---|---|
| `web` | safe | no | medium | HTTP(S): titles, headers, methods, robots, directory hints |
| `tls` | safe | no | medium | TLS/SSL: certificates, protocols, ciphers, Heartbleed/POODLE |
| `ssh` | safe | no | fast | SSH: algorithms, host keys, auth methods, protocol v1 |
| `smb` | safe | no | medium | SMB/NetBIOS: dialects, signing, OS discovery, MS17-010 |
| `dns` | safe | no | fast | DNS: recursion, NSID, service discovery |
| `db` | safe | no | medium | Databases/caches exposure: MySQL, PostgreSQL, MSSQL, Redis, MongoDB... |
| `mail` | safe | no | medium | SMTP/IMAP/POP3 capabilities and TLS |
| `rdp` | safe | no | fast | RDP: encryption level and NTLM info |
| `ftp` | safe | no | fast | FTP: banner, anonymous access, system type |

## XamlTech

| Profile | Risk | Root | Speed | What it does |
|---|---|---|---|---|
| `mynetwork` | safe | no | medium | Local network review: common web/admin ports, service versions and safe NSE checks |
| `iot` | safe | no | medium | Cameras/IoT/embedded: RTSP, UPnP, web UIs, MQTT ports |

## Audit

| Profile | Risk | Root | Speed | What it does |
|---|---|---|---|---|
| `audit` | safe | yes | slow | Exposure review: top-1000 + versions + TLS/SSH/SMB/DB/HTTP checks |

## Workflows (multi-stage)

| Workflow | What it does |
|---|---|
| `recon` | Smart pipeline: discovery -> fast ports on live hosts -> versions/scripts on open ports only |
| `inventory` | Recon pipeline + OS detection and traceroute for a full asset inventory |

`recon` and `inventory` run discovery first, then a fast port scan **only on live hosts**, then versions and
scripts **only on the ports that were actually found** - far faster than a blanket deep scan.

## Custom
`-p custom -a "<nmap args>"` runs your own arguments (quote-aware). The toolkit refuses output flags it manages
(`-oN/-oX/-oG/-oA`, `--resume`, `--datadir`, `--script-updatedb`) and NSE selections containing
`brute`, `dos`, `exploit`, `fuzzer` or `intrusive`.

## Overrides that work with every profile
`-T`, `--ports`, `--top-ports`, `--scripts`, `--script-args`, `--max-rate`, `--max-retries`, `--host-timeout`,
`--dns-servers`, `-e`, `--exclude`, `--no-ping`, `--no-dns`, `--ipv6`.
