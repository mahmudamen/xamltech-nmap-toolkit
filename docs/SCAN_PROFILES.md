# Scan profiles

The canonical, generated profile reference is **[docs/PROFILES.md](PROFILES.md)**. It lists all 33 profiles,
workflows and custom mode with risk, privilege and speed, and is generated from `lib/profiles.sh`.

For the live view, run:

```bash
./nmap-toolkit.sh --list-profiles
```

Per-option Nmap arguments and tuning flags are documented in [USAGE.md](USAGE.md) and in the option registry
(`lib/options.sh`).
