# XamlTech Nmap Toolkit

**Interactive network discovery and diagnostics toolkit built with Bash + Nmap.**

The XamlTech Nmap Toolkit provides a clean interactive and CLI interface around Nmap for **authorized network inventory, host discovery, latency diagnostics, port discovery, service/version detection, OS identification, and reproducible result collection**.

> **Authorization required:** Use this project only against systems and networks you own or are explicitly authorized to test.

---

## Features

- Interactive terminal UI
- CLI automation mode
- Host, hostname, IP range, and CIDR targets
- Scan profiles:
  - Discovery
  - Quick
  - Standard
  - Deep
  - OS detection
  - Diagnostic
  - Custom
- Host up/down discovery
- Latency measurement for discovered hosts
- TCP port discovery
- Service/version detection
- OS detection
- Optional traceroute diagnostics
- Nmap dependency detection
- Local Nmap update/candidate check on Debian/Ubuntu systems
- Human-readable logs
- Nmap XML output for automation
- Per-scan result directories
- ShellCheck CI
- No silent package installation
- Explicit authorization confirmation in interactive mode

---

## Requirements

Linux with:

- Bash 4+
- Nmap
- `awk`
- `sed`
- `grep`
- `date`
- `mkdir`
- `tee`
- `timeout`
- `sort`
- `ping` is recommended for latency reporting

### Install Nmap

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install nmap
```

Fedora:

```bash
sudo dnf install nmap
```

Arch Linux:

```bash
sudo pacman -S nmap
```

Check:

```bash
nmap --version
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/mahmudamen/xamltech-nmap-toolkit.git
cd xamltech-nmap-toolkit
```

Make the script executable:

```bash
chmod +x nmap-toolkit.sh
```

Run:

```bash
./nmap-toolkit.sh
```

---

## Quick Start

### Interactive

```bash
./nmap-toolkit.sh
```

The program asks for:

1. Target
2. Scan profile
3. Custom arguments if required
4. Authorization confirmation

Example target:

```text
192.168.1.0/24
```

---

## CLI Mode

### Discover hosts

```bash
./nmap-toolkit.sh \
  --target 192.168.1.0/24 \
  --profile discovery
```

### Standard scan

```bash
./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile standard
```

### Deep scan

```bash
./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile deep
```

### OS detection

```bash
sudo ./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile os
```

### Diagnostics

```bash
./nmap-toolkit.sh \
  --target 192.168.1.0/24 \
  --profile diagnostic
```

### Custom Nmap arguments

```bash
./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile custom \
  --args "-sV --top-ports 100"
```

---

## Scan Profiles

| Profile | Purpose | Typical Nmap behavior |
|---|---|---|
| `discovery` | Inventory reachable hosts | Host discovery |
| `quick` | Fast port overview | Top 100 TCP ports |
| `standard` | General inventory | Top 1000 TCP ports + service detection |
| `deep` | Broad TCP inventory | All TCP ports + service detection |
| `os` | Host identification | Broad TCP + service + OS detection |
| `diagnostic` | Network diagnostics | Host discovery + traceroute |
| `custom` | Advanced users | User-supplied Nmap arguments |

The profiles intentionally favor **visibility and diagnostics** rather than exploitation.

---

## Results

Each run creates a timestamped directory:

```text
results/
└── 2026-10-03_162241/
    ├── metadata.txt
    ├── nmap.txt
    ├── nmap.xml
    ├── hosts-up.txt
    ├── host-latency.txt
    └── summary.txt
```

### `nmap.txt`

Human-readable Nmap output.

### `nmap.xml`

Machine-readable Nmap output suitable for:

- reporting tools
- inventory systems
- Python scripts
- CI pipelines
- future XamlTech integrations

### `hosts-up.txt`

Reachable IPv4 hosts discovered during the run.

### `host-latency.txt`

Basic ICMP latency measurements where `ping` is available.

---

## Nmap Update Check

Run:

```bash
./nmap-toolkit.sh --check-updates
```

On Debian/Ubuntu, the script can compare the installed version with the local APT candidate.

The script **does not automatically install or upgrade Nmap**.

Example:

```text
Installed : 7.x
APT       : 7.x

[WARN] An APT candidate newer than the installed version is available.

Ubuntu/Debian:
  sudo apt update
  sudo apt install nmap
```

For authoritative release information, see the official Nmap project:

https://nmap.org/

---

## Root Privileges

Some Nmap capabilities work better with elevated privileges.

For example:

```bash
sudo ./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile os
```

The toolkit does not automatically invoke `sudo`.

This is deliberate: privilege escalation should remain an explicit administrator decision.

---

## Security Model

The script:

- does not silently install software
- does not create persistence
- does not modify firewall rules
- does not exploit discovered services
- does not attempt credential attacks
- does not hide scan activity
- rejects several shell metacharacters in target input
- uses Nmap arguments as an array rather than constructing an executable shell command
- stores results locally
- asks for authorization confirmation in interactive mode

Custom Nmap arguments are intentionally available for authorized administrators, but they should be used responsibly.

---

## Performance

For a small LAN such as:

```text
192.168.1.0/24
```

start with:

```bash
./nmap-toolkit.sh --target 192.168.1.0/24 --profile discovery
```

Then investigate specific reachable hosts:

```bash
./nmap-toolkit.sh --target 192.168.1.10 --profile standard
```

This two-stage workflow avoids unnecessarily performing expensive scans against every address.

---

## Troubleshooting

### `nmap: command not found`

Install Nmap using your distribution's package manager.

### OS detection says root privileges are required

Run:

```bash
sudo ./nmap-toolkit.sh --target TARGET --profile os
```

### No latency is shown

Install/use `ping`, and remember that ICMP can be filtered by the target or network.

### A host is shown as down

Host discovery can be affected by:

- firewalls
- ICMP filtering
- routing
- VLAN configuration
- host security software

A "down" result does not prove that a system is physically offline.

---

## Development

Run ShellCheck manually:

```bash
shellcheck nmap-toolkit.sh
```

Run the lightweight test:

```bash
bash tests/test_shellcheck.sh
```

The GitHub Actions workflow runs ShellCheck automatically.

---

## Project Principles

- Explicit over magical behavior
- Safe defaults
- Reproducible output
- Automation-friendly XML
- Linux-first implementation
- Small dependency footprint
- Clear operational feedback
- No unnecessary privilege escalation
- Defensive and authorized use

---

## Roadmap

Potential future releases:

- [ ] JSON summary output
- [ ] Better CIDR host inventory parsing
- [ ] Concurrent latency checks
- [ ] Config file support
- [ ] Interactive host selection after discovery
- [ ] Service inventory table
- [ ] Markdown/HTML report generation
- [ ] Network interface selection
- [ ] IPv6 improvements
- [ ] Optional DNS inventory
- [ ] Plugin/profile architecture
- [ ] Bash completion
- [ ] Packaging for Debian-based systems

---

## Author

### Mahmoud Mohamed Amin

Software Developer / Odoo Developer / Systems Builder

- GitHub: **@mahmudamen**
- Website: **https://xamltech.com**

XamlTech builds business software, ERP systems, automation tools, and developer utilities.

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Disclaimer

This project is provided for legitimate network administration, diagnostics, inventory, and authorized security testing.

You are responsible for ensuring that your use of Nmap and this toolkit complies with applicable laws, organizational policies, contracts, and authorization requirements.
