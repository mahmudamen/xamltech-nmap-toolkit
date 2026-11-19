# XamlTech Nmap Toolkit — Constitution

Version: 1.0.0 (2026-11-19). Applies to every change in this repository.

## Purpose

A safe, fast, pleasant CLI around Nmap for authorized discovery, inventory, diagnostics and exposure review,
with first-class Odoo/POS awareness. Small dependency footprint: Bash 4.4+, Nmap, optional stdlib-only Python.

## Non-negotiable principles

1. **Explicit over magical.** No hidden privilege escalation, no silent rewrites the operator cannot see.
2. **Data is never code.** Config files and scan output are parsed, never sourced or `eval`-ed.
3. **Safe defaults.** Every risky action requires an explicit flag or typed confirmation.
4. **No offensive features.** Brute-force, DoS, exploit, fuzzer and intrusive NSE categories are blocked by design.
   Decoys (`-D`), source spoofing (`-S`), `--spoof-MAC`, `--proxies`, `--badsum` and evasion options stay blocked
   unless a site opt-in policy is explicitly acknowledged.
5. **Arrays, not strings.** Nmap arguments are Bash arrays; no command string is built from user input.
6. **Untrusted output stays untrusted.** HTML, CSV and Markdown escape or neutralise host-derived data;
   XML entities are rejected.
7. **Single source of truth.** CLI flags, help, completion, config whitelist, docs and tests are generated from
   one option registry. Hand-edited copies are not allowed.
8. **Reproducible output.** Every run writes `metadata.json`, `command.txt`, native Nmap files and a report.
   Report schemas are versioned; changes are backwards compatible or bump the schema.
9. **Linux-first, stdlib-only.** No new runtime dependencies. Python code uses the standard library only.
10. **Backwards compatibility.** Existing flags, profiles, run directory layout and exit codes keep working.
    New behaviour is additive or behind a flag.

## Exit codes (fixed contract)

`0` success · `1` error · `2` usage · `3` missing dependency · `4` blocked by policy · `130` interrupted.
Do not introduce new exit codes without updating this constitution and the docs.

## Quality gates (all must pass before merge)

```bash
make test     # bash tests/run.sh — full suite, including live localhost scans
make lint     # shellcheck -x -S warning + python3 -m py_compile
```

Additional gates for new work:

- Every new option has: registry entry, validator, help text, completion entry, config key (where relevant),
  at least one positive and one negative test, and a docs entry generated from the registry.
- Every new finding rule has a fixture in `tests/fixtures/` and a hostile-banner injection test.
- Every new profile/pipeline stage has a dry-run test asserting the exact Nmap argument list.
- No secrets, credentials, tokens or absolute user paths in committed files.
- `SECURITY.md` and `docs/USAGE.md` updated when behaviour or guarantees change.

## Decision precedence

When requirements conflict: **safety > explicitness > compatibility > convenience > performance**.

## Amendment process

Changes to this file require a dedicated commit, a note in `CHANGELOG.md`, and approval by the maintainer.
