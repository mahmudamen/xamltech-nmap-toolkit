# Contributing

Thank you for contributing to XamlTech Nmap Toolkit.

## Development Principles

- Keep Bash code ShellCheck-clean.
- Prefer arrays over string-built shell commands.
- Never silently escalate privileges.
- Never silently install packages.
- Keep default profiles focused on discovery and diagnostics.
- Preserve machine-readable output.
- Update documentation when behavior changes.

## Pull Requests

Please include:

1. Description of the change
2. Reason for the change
3. Test steps
4. Documentation updates when needed

## Testing

Run:

```bash
make lint
```

For functional tests, use an authorized local lab or test network.


## v2 notes
- Run `make lint test` before opening a PR; new behavior needs a test in `tests/run.sh`.
- New profiles go in `PROFILE_TABLE` + `build_nmap_args` (`lib/profiles.sh`); regenerate `docs/PROFILES.md`.
- Do not add brute-force, DoS, exploit or evasion features - they are out of scope for this project.
