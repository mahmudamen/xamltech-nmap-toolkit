# Usage Guide

## 1. Start Interactive Mode

```bash
./nmap-toolkit.sh
```

The interactive workflow is:

```text
Dependency check
       ↓
Nmap update check
       ↓
Target selection
       ↓
Profile selection
       ↓
Authorization confirmation
       ↓
Nmap scan
       ↓
XML export
       ↓
Host inventory
       ↓
Latency report
       ↓
Summary
```

## 2. Choosing a Target

Supported examples:

```text
192.168.1.1
192.168.1.0/24
192.168.1.1-254
router.local
```

Only pass targets that you are authorized to scan.

## 3. Recommended Workflow

For a LAN:

```bash
./nmap-toolkit.sh --target 192.168.1.0/24 --profile discovery
```

Review:

```text
results/<timestamp>/hosts-up.txt
```

Then inspect individual systems:

```bash
./nmap-toolkit.sh --target 192.168.1.10 --profile standard
```

For a system you administer:

```bash
sudo ./nmap-toolkit.sh --target 192.168.1.10 --profile os
```

## 4. Saving Elsewhere

```bash
./nmap-toolkit.sh \
  --target 192.168.1.0/24 \
  --profile discovery \
  --output ./network-audit
```

## 5. Automation

The CLI interface is suitable for shell automation:

```bash
./nmap-toolkit.sh \
  --target 192.168.1.0/24 \
  --profile discovery \
  --yes
```

Use the generated `nmap.xml` for downstream processing.

## 6. Custom Profile

Example:

```bash
./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile custom \
  --args "-sV --top-ports 100"
```

The custom mode passes arguments directly to Nmap as individual arguments. Do not place shell commands in the argument string.
