# XamlTech Nmap Toolkit - project notes

Purpose: a safe, fast, pleasant CLI around Nmap for authorized discovery, inventory, diagnostics and exposure review,
with a generic local-network profile.

Layout: `nmap-toolkit.sh` (CLI) · `lib/` (ui, core, nse, profiles, scan, interactive, report.py, render.awk) ·
`tests/` · `docs/` · `config/` · `webapp/` · `completions/` · `install.sh`.

Principles: explicit over magical · safe defaults · data never becomes code · reproducible output ·
small dependency footprint (Bash, Nmap, optional stdlib-only Python) · no offensive features.

Roadmap ideas: SARIF/Markdown ticket export, webhook notifications, per-profile config overrides,
service version support matrix fetched at runtime, authenticated hardening checks via SSH (opt-in).
