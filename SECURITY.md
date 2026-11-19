# Security Policy

## Authorized use
Network administration, asset inventory, diagnostics, authorized security testing, labs. Do not use against
systems or networks without permission.

## What the toolkit refuses to do
Brute-force / DoS / exploit / fuzzer NSE scripts, decoys (`-D`), source spoofing (`-S`), proxies, `--badsum`,
fragmentation/evasion, user-supplied output flags, silent sudo, and scanning outside a supplied `--scope` file.
JSON scope v2 adds deny lists, validity windows and host limits. Non-private targets require explicit consent.
Approved automation can pin a scan to `--plan-file` + `--plan-hash` (mismatch exits `4`). These are intentional and
tested.

## Reporting a vulnerability
Please do not publish details in a public issue. Contact the maintainer via the author's profile / https://xamltech.com.

## In scope
Command/argument injection, unsafe argument or config handling, privilege escalation, unintended file writes,
unsafe temp files, credential exposure, **report injection (HTML/CSV/Markdown) from hostile banners**, XML parsing
issues, and bypasses of scope/authorization/NSE guards.
