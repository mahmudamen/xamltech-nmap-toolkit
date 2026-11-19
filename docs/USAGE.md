# Usage guide

## 1. Interactive mode
```bash
./nmap-toolkit.sh
```
Arrow keys / `j` `k` move, Enter selects, digits jump, `q` cancels. Menus: Guided scan, Smart recon, NSE script
packs, Advanced options (registry categories: targets, tuning, NSE, Nmap, safety…), Browse profiles,
History & reports (open/compare), Tools (doctor, updates, NSE browser), Settings (theme, formats, output dir -
can be saved to `~/.config/xamltech-nmap-toolkit/config`). Your local subnets are detected automatically.
Non-TTY input falls back to numbered prompts.

## 2. Targets
`192.168.1.1` · `192.168.1.0/24` · `192.168.1.1-254` · `10.0.1-3.*` · `router.local` · `::1` ·
several separated by spaces · `-L targets.txt` (one per line, `#` comments) · `--exclude 192.168.1.1,192.168.1.254`.

Private/loopback/link-local targets proceed after the normal confirmation. Anything else (public IPs,
unresolvable names) needs a typed phrase interactively, or `--authorized` in scripts. With `--scope FILE`
(see `config/scope.example.txt`) anything outside the list is refused.

## 3. Privileges
Raw-socket features (SYN, UDP, OS detection, ARP, traceroute) need root or `cap_net_raw`. Without them the
toolkit rewrites the command (`-sS→-sT`, drops `-sU`/`-O`/…) and shows each change in the plan.
`--sudo` re-runs the toolkit via sudo; ownership of results is handed back to your user.

## 4. Recommended workflow
```bash
./nmap-toolkit.sh -t 192.168.1.0/24 -p recon       # everything alive + what runs on it
./nmap-toolkit.sh -t 192.168.1.20  -p tls          # drill into one service family
./nmap-toolkit.sh --diff results/<old> latest      # what changed?
```

## 5. Automation (cron/CI)
```bash
./nmap-toolkit.sh -t 10.0.0.0/24 -p recon -y --no-color --no-banner --scope scope.txt \
    --formats json,html -o /var/lib/xamltech-nmap
```
Exit codes: `0` ok · `1` error · `2` usage · `3` missing dependency · `4` blocked by policy (scope/authorization/NSE
guard/plan hash) · `10` diff gate (`--fail-on SEVERITY`) · `130` interrupted.

## 6. Reusable inputs
```bash
./nmap-toolkit.sh -t 10.0.0.0/24 -p discovery --save-preset weekly   # stores argv as JSON under the config dir
./nmap-toolkit.sh --preset weekly                                    # replay the saved options
./nmap-toolkit.sh --replay 1                                         # replay the newest command from history
./nmap-toolkit.sh --target-group branch-a -p standard                # expand ~/.config/xamltech-nmap-toolkit/groups/branch-a.txt
./nmap-toolkit.sh -t 10.0.0.0/24 -p recon --estimate                 # hosts, stages, duration from prior runs
./nmap-toolkit.sh -t 10.0.0.0/24 -p standard --incremental baseline/report.json
```

Workflows are declared in `profiles/stages.txt` (`stage|pipeline|index|name|profile|targets|when|ports|scripts|timeout|on_fail`).
`targets` is `original`, `hosts-up` or `hosts-open`; `when` accepts `host_count > N` or `port in 22,80,443`.
Skipped stages are recorded in `metadata.json`. `--incremental` removes hosts and ports already present in a
baseline report before scanning.

Presets, target groups and history live in `${XAMLTECH_NMAP_CONFIG_DIR:-$XDG_CONFIG_HOME/xamltech-nmap-toolkit}`
(`history.jsonl` is `0600`). Names are restricted to `[A-Za-z0-9_-]`; no config data is ever sourced or `eval`-ed.

## 7. Approved plans and compliance
```bash
./nmap-toolkit.sh -t 10.0.0.0/24 -p audit --dry-run --json > plan.json
python3 -c 'import json; print(json.load(open("plan.json"))["plan_hash"])'
./nmap-toolkit.sh --plan-file plan.json --plan-hash <hash>          # refuses if plan or hash changed
./nmap-toolkit.sh --explain -t 10.0.0.5 -p custom -a '-sS --top-ports 100' --ack-risk --policy advanced
```
`--json` output is deterministic (targets sorted, `created` excluded from the hash). Scope v2 JSON adds `deny`,
`valid_from`, `valid_until`/`expires` and `max_hosts`; violations exit `4`. Every scan writes an audit line with
operator, `sudo_user`, git commit, plan hash, command and return code to a `0600` audit log.

## 8. Colors & terminals
Truecolor when `COLORTERM=truecolor`, else 256-color; `NO_COLOR` and `--no-color` disable; non-UTF-8 locales get
an ASCII layout. Themes: cyber, ocean, sunset, matrix, aurora, mono.

## 9. Troubleshooting
* `--doctor` checks Nmap, NSE scripts, Python, privileges, terminal and output directory.
* Hosts shown "down": firewalls/ICMP filtering - retry with `--no-ping`.
* Missing HTML/JSON: install `python3`.
* A profile skips scripts: they are validated against the local `script.db`; skipped names are listed in the plan.
* Custom NSE `odoo-info.nse` needs service detection (`-sV`) to recognise the port as HTTP - built-in profiles do this.
