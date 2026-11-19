# XamlTech Nmap Toolkit - project notes

Purpose: a safe, fast, pleasant CLI around Nmap for authorized discovery, inventory, diagnostics and exposure review,
with first-class Odoo/POS awareness.

Layout: `nmap-toolkit.sh` (CLI) · `lib/` (ui, core, nse, profiles, scan, interactive, report.py, render.awk) ·
`scripts/odoo-info.nse` · `tests/` · `docs/` · `config/` · `completions/` · `install.sh`.

Principles: explicit over magical · safe defaults · data never becomes code · reproducible output ·
small dependency footprint (Bash, Nmap, optional stdlib-only Python) · no offensive features.

Roadmap ideas: SARIF/Markdown ticket export, webhook notifications, per-profile config overrides,
Odoo version support matrix fetched at runtime, PostgreSQL/odoo.conf hardening checks via authenticated SSH (opt-in).
