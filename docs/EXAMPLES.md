# Examples

```bash
# Guided, colorful menu
./nmap-toolkit.sh

# Inventory a LAN, then drill into what's there
./nmap-toolkit.sh -t 192.168.1.0/24 -p recon --open
./nmap-toolkit.sh -t 192.168.1.0/24 -p inventory --sudo        # + OS detection and traceroute

# Local network review (XamlTech default)
./nmap-toolkit.sh -t 192.168.1.0/24 -p mynetwork                # common web/admin ports + safe NSE
./nmap-toolkit.sh -t 10.20.0.5 -p mynetwork --ports 80,443,8080
./nmap-toolkit.sh -t 10.20.0.5 -p mynetwork --scripts http-security-headers

# Targeted service reviews
./nmap-toolkit.sh -t 10.0.0.5 -p tls --ports 443,8443
./nmap-toolkit.sh -t 10.0.0.0/24 -p smb
./nmap-toolkit.sh -t 10.0.0.0/24 -p db                         # exposed MySQL/PostgreSQL/Redis/MongoDB...

# Gentle on fragile devices
./nmap-toolkit.sh -t 10.0.0.50 -p polite --max-rate 20

# Safe vulnerability checks (low impact) vs broader (asks confirmation)
./nmap-toolkit.sh -t 10.0.0.5 -p vuln-safe
./nmap-toolkit.sh -t 10.0.0.5 -p vuln

# Strict scope, non-interactive (cron / CI)
./nmap-toolkit.sh -t 10.0.0.0/24 -p audit --scope scope.txt -y --no-color --formats json,html

# Preview without sending a packet
./nmap-toolkit.sh -t 10.0.0.0/24 -p audit --dry-run

# Weekly drift check
./nmap-toolkit.sh -t 10.0.0.0/24 -p recon -y
./nmap-toolkit.sh --diff results/<last-week> latest

# Browse NSE
./nmap-toolkit.sh --list-scripts ssl
./nmap-toolkit.sh --script-help ssl-enum-ciphers

# Target-less LAN broadcast discovery (rogue DHCP, UPnP, mDNS)
./nmap-toolkit.sh -p broadcast --sudo
```
