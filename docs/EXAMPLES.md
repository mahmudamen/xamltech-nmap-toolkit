# Examples

## Example 1: Home/Lab Network Discovery

```bash
./nmap-toolkit.sh \
  --target 192.168.1.0/24 \
  --profile discovery
```

Inspect:

```bash
cat results/*/hosts-up.txt
```

## Example 2: Router Inventory

```bash
./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile standard
```

## Example 3: Administrator OS Inventory

```bash
sudo ./nmap-toolkit.sh \
  --target 192.168.1.10 \
  --profile os
```

## Example 4: Diagnostic Discovery

```bash
./nmap-toolkit.sh \
  --target 192.168.1.0/24 \
  --profile diagnostic
```

## Example 5: CI-Friendly Discovery

```bash
./nmap-toolkit.sh \
  --target 192.168.1.0/24 \
  --profile discovery \
  --yes \
  --output ./artifacts/network
```

## Example 6: Custom Authorized Scan

```bash
./nmap-toolkit.sh \
  --target 192.168.1.10 \
  --profile custom \
  --args "-sV --top-ports 100"
```

## Reading XML

The result file:

```text
results/<timestamp>/nmap.xml
```

can be processed by Python, Go, JavaScript, CI systems, or inventory/reporting tools.
