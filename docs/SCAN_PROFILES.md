# Scan Profiles

## Discovery

Underlying profile:

```text
-sn --reason
```

Use when the primary question is:

> Which hosts respond?

Example:

```bash
./nmap-toolkit.sh -t 192.168.1.0/24 -p discovery
```

---

## Quick

Underlying profile:

```text
-T4 --top-ports 100 --open --reason
```

Use for a fast first look at commonly used TCP ports.

---

## Standard

Underlying profile:

```text
-sS -T4 --top-ports 1000 -sV --open --reason
```

Provides a practical service inventory.

Some environments may require elevated privileges for SYN scanning.

---

## Deep

Underlying profile:

```text
-sS -T3 -p- -sV --open --reason
```

Scans all TCP ports and performs service/version detection.

This can take substantially longer than `standard`, particularly across larger networks.

---

## OS

Underlying profile:

```text
-sS -T3 -p- -sV -O --osscan-limit --open --reason
```

Attempts OS identification in addition to broad TCP/service enumeration.

OS identification is probabilistic and depends on the target's responses. It should not be treated as absolute truth.

---

## Diagnostic

Underlying profile:

```text
-sn -T4 --reason --traceroute
```

Useful for understanding reachability and routing.

Traceroute results depend on network topology and filtering.

---

## Custom

Custom mode allows authorized administrators to specify Nmap arguments.

Example:

```bash
./nmap-toolkit.sh \
  --target 192.168.1.1 \
  --profile custom \
  --args "-sV --top-ports 100"
```

Custom mode is intentionally not restricted to the built-in profiles. Administrators remain responsible for selecting appropriate Nmap options for their authorized environment.
