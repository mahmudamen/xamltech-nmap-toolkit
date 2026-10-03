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
shellcheck nmap-toolkit.sh
bash tests/test_shellcheck.sh
```

For functional tests, use an authorized local lab or test network.
