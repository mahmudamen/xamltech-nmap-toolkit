# Project Overview

## Goal

Provide a small, understandable Bash interface for Nmap that makes routine authorized network discovery easier without hiding what Nmap is doing.

## Non-Goals

This project is not intended to be:

- an exploitation framework
- a credential attack framework
- a persistence tool
- a stealth framework
- a vulnerability weaponization platform

## Architecture

```text
CLI / Interactive UI
        |
        v
Argument Validation
        |
        v
Profile Builder
        |
        v
Nmap
        |
        +------------------+
        |                  |
        v                  v
   nmap.txt            nmap.xml
        |                  |
        +--------+---------+
                 |
                 v
          Result Processor
                 |
        +--------+--------+
        |        |        |
        v        v        v
     Hosts    Latency   Summary
```

## Design Decisions

### Bash

Bash keeps the deployment footprint extremely small and works well for Linux administration environments.

### Nmap

Nmap remains the actual network scanning engine. This project intentionally does not attempt to reimplement network discovery.

### XML

Nmap XML output is retained because structured output is significantly more useful than parsing terminal formatting in downstream automation.

### Explicit Privileges

The toolkit does not automatically run itself through `sudo`. Users decide when elevated privileges are appropriate.
