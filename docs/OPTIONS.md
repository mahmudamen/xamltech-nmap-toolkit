# Generated option reference

Generated from `lib/options.sh` by `make docs`. Do not edit by hand.

| Flag | Value | Risk | Root | Description |
|---|---|---|---|---|
| \`--target\`, \`-t\` | csv | safe | no | Host, hostname, CIDR or range; repeatable |
| \`--target-file\`, \`-L\` | str | safe | no | Read targets from file (one per line) |
| \`--exclude\` | csv | safe | no | Exclude hosts or networks |
| \`--scope\` | str | safe | no | Authorized scope file; refuse targets outside it |
| \`--stage\` | str | safe | no | Run one workflow stage (discovery|ports|services) |
| \`--resume\` | str | safe | no | Resume a workflow from an existing run directory |
| \`--incremental\` | str | safe | no | Scan only hosts/ports absent from a baseline report |
| \`--target-group\` | str | safe | no | Expand a named target group |
| \`--save-preset\` | str | safe | no | Save current options as a named JSON preset |
| \`--preset\` | str | safe | no | Load options from a named JSON preset |
| \`--replay\` | str | safe | no | Replay a numbered command from history |
| \`--project\` | str | safe | no | Associate this scan with a project |
| \`--project-create\` | str | safe | no | Create a named project |
| \`--project-info\` | str | safe | no | Description for a new project |
| \`--project-goals\` | str | safe | no | Comma separated goals for a new project |
| \`--project-list\` | none | safe | no | List projects with their status |
| \`--project-show\` | str | safe | no | Show project plan, timeline and next action |
| \`--project-step-add\` | str | safe | no | Add an ordered step to a project |
| \`--project-step\` | str | safe | no | Step id for --project-step-add |
| \`--goal\` | str | safe | no | Goal text for --project-step-add |
| \`--project-args\` | str | safe | no | Saved toolkit arguments for the step |
| \`--project-step-status\` | str | safe | no | Set step status: NAME STEP=STATUS |
| \`--note\` | str | safe | no | Note for --project-step-status |
| \`--project-resume\` | str | safe | no | Resume the next project step and its saved arguments |
| \`--estimate\` | none | safe | no | Estimate hosts, stages and duration |
| \`--profile\`, \`-p\` | str | safe | no | Scan profile name |
| \`--args\`, \`-a\` | str | moderate | no | Quote-aware arguments for the custom profile |
| \`--timing\`, \`-T\` | str | safe | no | Nmap timing template 0-5 |
| \`--ports\` | str | safe | no | Port specification, e.g. 22,80,443 or T:22,U:53 |
| \`--top-ports\` | int | safe | no | Scan the N most common ports |
| \`--max-rate\` | int | safe | no | Maximum packets per second |
| \`--max-retries\` | int | safe | no | Probe retransmissions |
| \`--host-timeout\` | str | safe | no | Give up on slow hosts |
| \`--dns-servers\` | csv | safe | no | Custom resolvers |
| \`--interface\`, \`-e\` | str | safe | no | Network interface |
| \`--scripts\` | csv | safe | no | Extra NSE scripts (validated) |
| \`--script-args\` | str | moderate | no | NSE script arguments |
| \`--output\`, \`-o\` | str | safe | no | Result directory |
| \`--formats\` | csv | safe | no | Report formats |
| \`--theme\` | str | safe | no | Color theme |
| \`--no-latency\` | none | safe | no | Skip the parallel ping latency table |
| \`--open\` | none | safe | no | Open the service page when done (default) |
| \`--no-open\` | none | safe | no | Do not open a browser when reports finish |
| \`--notify\` | none | safe | no | Bell or desktop notification when done |
| \`--no-color\` | none | safe | no | Force colors off |
| \`--color\` | none | safe | no | Force colors on |
| \`--no-banner\` | none | safe | no | Hide the headline |
| \`--authorized\` | none | safe | no | Confirm authorization for non-private targets |
| \`--json\` | none | safe | no | Emit the dry-run plan as deterministic JSON |
| \`--plan-file\` | str | safe | no | Require an approved JSON scan plan |
| \`--plan-hash\` | str | safe | no | SHA-256 hash of the approved plan |
| \`--dry-run\` | none | safe | no | Show the plan and exact command, run nothing |
| \`--sudo\` | none | safe | no | Re-run the toolkit through sudo |
| \`--yes\`, \`-y\` | none | safe | no | Skip confirmation prompts |
| \`--no-ping\`, \`-Pn\` | none | safe | no | Treat hosts as up |
| \`--no-dns\`, \`-n\` | none | safe | no | Skip DNS resolution |
| \`--ipv6\`, \`-6\` | none | safe | no | IPv6 scanning |
| \`--policy\` | str | safe | no | strict or advanced (requires --ack-risk) |
| \`--ack-risk\` | none | moderate | no | Acknowledge advanced policy risks |
| \`--tcp-syn-probe\`, \`-PS\` | csv | safe | no | TCP SYN discovery probe ports |
| \`--tcp-ack-probe\`, \`-PA\` | csv | safe | no | TCP ACK discovery probe ports |
| \`--udp-probe\`, \`-PU\` | csv | safe | no | UDP discovery probe ports |
| \`--sctp-probe\`, \`-PY\` | csv | safe | no | SCTP discovery probe ports |
| \`--icmp-echo\`, \`-PE\` | none | safe | no | ICMP echo discovery |
| \`--icmp-timestamp\`, \`-PP\` | none | safe | no | ICMP timestamp discovery |
| \`--icmp-netmask\`, \`-PM\` | none | safe | no | ICMP netmask discovery |
| \`--ip-proto-ping\`, \`-PO\` | csv | safe | no | IP protocol ping |
| \`--arp-ping\`, \`-PR\` | none | safe | no | ARP discovery (local network) |
| \`--disable-arp-ping\` | none | safe | no | Skip ARP discovery |
| \`--send-ip\` | none | safe | no | Send raw IP packets |
| \`--send-eth\` | none | safe | no | Send raw Ethernet frames |
| \`--connect-scan\`, \`-sT\` | none | safe | no | TCP connect scan |
| \`--syn-scan\`, \`-sS\` | none | moderate | yes | TCP SYN scan |
| \`--ack-scan\`, \`-sA\` | none | moderate | yes | TCP ACK scan |
| \`--window-scan\`, \`-sW\` | none | moderate | yes | TCP window scan |
| \`--maimon-scan\`, \`-sM\` | none | moderate | yes | TCP Maimon scan |
| \`--fin-scan\`, \`-sF\` | none | moderate | yes | TCP FIN scan |
| \`--null-scan\`, \`-sN\` | none | moderate | yes | TCP NULL scan |
| \`--xmas-scan\`, \`-sX\` | none | moderate | yes | TCP XMAS scan |
| \`--udp-scan\`, \`-sU\` | none | moderate | yes | UDP scan |
| \`--ip-proto-scan\`, \`-sO\` | none | moderate | yes | IP protocol scan |
| \`--sctp-init-scan\`, \`-sY\` | none | moderate | yes | SCTP INIT scan |
| \`--sctp-cookie-scan\`, \`-sZ\` | none | moderate | yes | SCTP COOKIE-ECHO scan |
| \`--scanflags\` | str | moderate | yes | Custom TCP flag set (no raw hex) |
| \`--min-rate\` | int | safe | no | Minimum packets per second |
| \`--min-parallelism\` | int | safe | no | Minimum parallel probes |
| \`--max-parallelism\` | int | safe | no | Maximum parallel probes |
| \`--min-hostgroup\` | int | safe | no | Minimum hosts per group |
| \`--max-hostgroup\` | int | safe | no | Maximum hosts per group |
| \`--initial-rtt-timeout\` | str | safe | no | Initial RTT timeout |
| \`--min-rtt-timeout\` | str | safe | no | Minimum RTT timeout |
| \`--max-rtt-timeout\` | str | safe | no | Maximum RTT timeout |
| \`--scan-delay\` | str | safe | no | Delay between probes |
| \`--max-scan-delay\` | str | safe | no | Maximum probe delay |
| \`--max-attempts\` | int | safe | no | Maximum probe attempts |
| \`--script-timeout\` | str | safe | no | Timeout per NSE script |
| \`--exclude-ports\` | str | safe | no | Ports to exclude |
| \`--fast-scan\`, \`-F\` | none | safe | no | Fast (100 most common ports) |
| \`--randomize-ports\`, \`-r\` | none | safe | no | Scan ports in random order |
| \`--all-ports\`, \`-p-\` | none | safe | no | Scan all 65535 ports |
| \`--version-intensity\` | int | safe | no | Version detection intensity 0-9 |
| \`--version-light\` | none | safe | no | Light version detection |
| \`--version-all\` | none | safe | no | Aggressive version detection |
| \`--version-trace\` | none | safe | no | Trace version detection |
| \`--os-detection\`, \`-O\` | none | moderate | yes | OS detection |
| \`--fuzzy\` | none | moderate | yes | Fuzzy OS match |
| \`--script-args-file\` | str | safe | no | Read NSE arguments from a file |
| \`--script-trace\` | none | safe | no | Trace NSE traffic |
| \`--script-updatedb\` | none | safe | no | Update the local NSE script database |
| \`--packet-trace\` | none | safe | no | Trace sent/received packets (needs --verbose) |
| \`--extra-verbose\`, \`-vv\` | none | safe | no | Extra verbose output |
| \`--debug\`, \`-ddd\` | none | safe | no | Debug output |
| \`--source-port\` | int | safe | no | Fixed source port |
| \`--data-length\` | int | safe | no | Append random data to probes |
| \`--ttl\` | int | safe | no | Set IPv4 TTL |
| \`--mtu\` | int | safe | no | Set IP MTU |
| \`--config\` | str | safe | no | Load an extra config file |
| \`--list-profiles\` | none | safe | no | Show every profile |
| \`--list-scripts\` | str | safe | no | Browse local NSE scripts |
| \`--script-help\` | str | safe | no | Show NSE script documentation |
| \`--history\` | none | safe | no | List previous runs |
| \`--diff\` | str | safe | no | Compare two runs |
| \`--open-report\` | str | safe | no | Open the service page or HTML report |
| \`--export\` | str | safe | no | Handoff list (urls, hosts, ports, openvas) |
| \`--doctor\` | none | safe | no | Check the environment |
| \`--check-updates\` | none | safe | no | Nmap version information |
| \`--online\` | none | safe | no | Query nmap.org for the latest version |
| \`--dump-options\` | none | safe | no | Print the option registry as JSON |
| \`--explain\` | none | safe | no | Explain why each Nmap argument was added |
| \`--verbose\`, \`-v\` | none | safe | no | Debug output |
| \`--version\` | none | safe | no | Print version |
| \`--help\`, \`-h\` | none | safe | no | Show help |
