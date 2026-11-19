# Data Model: 001-advanced-toolkit

All new files are plain UTF-8 text with `#` comments. No YAML/TOML parser dependency.

## 1. Option registry (`lib/options.sh`)

Format: `FLAG|VALUE|VALIDATOR|NMAP_TEMPLATE|RISK|ROOT|CATEGORY|DEFAULT|DESCRIPTION`

| Field | Allowed values / syntax | Notes |
|---|---|---|
| `FLAG` | `--name` or `-x,--long` | First alias is canonical; comma-separated aliases |
| `VALUE` | `none`, `str`, `int`, `csv`, `portspec`, `hostspec`, `duration` | `none` = boolean flag |
| `VALIDATOR` | regex or helper name (`v_timing`, `v_ports`, `v_duration`, …) | Empty = accept non-empty string |
| `NMAP_TEMPLATE` | Nmap argv template, `%v` = value | Empty = toolkit-only option |
| `RISK` | `safe`, `moderate`, `intrusive`, `blocked` | `blocked` never reaches Nmap |
| `ROOT` | `yes`, `no` | Informs plan/privilege adaptation |
| `CATEGORY` | `target`, `profile`, `tuning`, `discovery`, `technique`, `ports`, `detection`, `nse`, `debug`, `network`, `output`, `safety`, `tool`, `policy` | Drives help sections |
| `DEFAULT` | literal or empty | Command-line values override config, config overrides default |
| `DESCRIPTION` | one line, <= 78 chars | Used by help and man page |

Rules:

- One record per canonical option; aliases share the record.
- `blocked` options remain in the registry so help can explain why they are refused.
- Generators emit records sorted by `CATEGORY`, then `FLAG`.
- `--dump-options --json` emits `[{flag, aliases, value, validator, nmap_template, risk, root, category, default, description}]`.

### Validator library

| Name | Accepts |
|---|---|
| `v_timing` | `0-5` or `paranoid|sneaky|polite|normal|aggressive|insane` |
| `v_ports` | `^[0-9TUSP:,-]+$` (existing) |
| `v_hostspec` | existing `validate_target_token` allowlist |
| `v_duration` | `^[0-9]+[smhd]?$` |
| `v_count` | `^[0-9]+$` |
| `v_rate` | `^[0-9]+$`, > 0 |
| `v_csv` | comma-separated safe tokens, no shell metacharacters |
| `v_script_expr` | NSE expression string passed through `guard_script_spec` |

## 2. Profiles (`profiles/*.txt`)

Existing six fields unchanged:

```text
name|category|risk|root|speed|description
```

New optional stage records (pipeline):

```text
stage|pipeline|index|name|profile|targets|when|ports|scripts|timeout|on_fail
```

| Field | Meaning |
|---|---|
| `pipeline` | Parent workflow name (`recon`, `inventory`, user-defined) |
| `index` | Positive integer, execution order |
| `name` | Stable stage id, used by `--stage` and `.done` files |
| `profile` | Existing profile name whose Nmap args seed the stage |
| `targets` | `original`, `hosts-up`, `hosts-open`, or a literal host list |
| `when` | Empty or `port in 22,80,443` / `host_count > N` |
| `ports` | Overrides profile ports for this stage |
| `scripts` | Extra script expression, validated by `guard_script_spec` |
| `timeout` | Duration (`v_duration`), `0` = no timeout |
| `on_fail` | `abort` (default) or `continue` |

Variables: `${TARGETS}`, `${HOSTS_UP}`, `${PORTS_OPEN}` substituted from prior stage outputs only; no shell expansion.

## 3. Presets (`~/.config/xamltech-nmap-toolkit/presets/*.json`)

```json
{"name": "lan-audit", "version": 1, "args": ["-t", "10.0.0.0/24", "-p", "audit", "--formats", "json,html"]}
```

Saved/loaded as arrays; never as a shell string.

## 4. Scope v2 (`config/scope.example.txt` syntax)

One directive per line, `#` comments:

```text
allow 10.0.0.0/8
deny  10.0.5.0/24
allow *.lab.example.com
window 2026-01-01T00:00:00Z 2026-01-31T23:59:59Z
max_hosts 512
expires 2027-01-01
```

Legacy lines (bare CIDR/IP/hostname/range/wildcard) are treated as `allow`. A target is in scope when it matches
an `allow`, matches no `deny`, and all active windows/expiry/max_hosts constraints hold. Violations print the
offending target and exit 4.

## 5. Plan (`--dry-run --json`)

```json
{
  "plan_version": 1,
  "toolkit_version": "2.1.0",
  "profile": "audit",
  "targets": ["10.0.0.0/24"],
  "stages": [{"name": "discovery", "argv": ["nmap", "-sn"]}],
  "adaptations": ["-sS -> -sT (raw sockets unavailable)"],
  "skipped_scripts": ["vulners"],
  "policy": "strict",
  "created": "ISO-8601"
}
```

`created` is excluded from the hash input. `plan_hash` = SHA-256 of canonical JSON (sorted keys, no whitespace).
`--plan-file` + `--plan-hash` re-parse the plan, recompute the hash and compare before any scan action.

## 6. Report JSON (`report.json`) additions

Existing v1 keys stay. Add:

```json
{
  "schema_version": 2,
  "meta": {"command": "...", "policy": "strict", "plan_hash": "...", "toolkit_commit": "..."},
  "stats": {"findings": {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}, "suppressed": 0},
  "integrity": {"native_sha256": {"nmap.xml": "...", "nmap.txt": "..."}},
  "findings": [{"severity":"HIGH","host":"...","port":443,"proto":"tcp","title":"...","detail":"...","advice":"...","source":"ssl-cert","rule_id":"XT-SSL-001","suppressed":false}]
}
```

`schema_version: 1` files remain readable by `diff`, `history` and `export` (missing keys default).

## 7. Baseline (`baseline.json`)

```json
{"baseline_version": 1, "entries": [{"severity":"LOW","host":"10.0.0.5","port":80,"proto":"tcp","title":"Cleartext HTTP without HTTPS on the same host","reason":"accepted risk","expires":"2027-01-01"}]}
```

Match key: `(severity, host, port, proto, title)`. Expired entries are ignored with a warning.

## 8. SARIF output

SARIF 2.1.0 minimal profile:

- `version: "2.1.0"`, `$schema` official URI (constant in code).
- One `run.tool.driver.rule` per unique `rule_id` with `shortDescription` and `defaultConfiguration.level`.
- One `result` per non-suppressed finding: `ruleId`, `level`, `message.text`,
  `locations[0].physicalLocation.artifactLocation.uri` = `nmap.xml`,
  `regions[0].startLine` = 1, `properties` = `{host, port, proto, advice}`.

## 9. Audit log (`audit.log`, mode 0600)

One JSON object per line:

```json
{"ts":"ISO-8601","operator":"alice","sudo_user":"root","action":"scan","profile":"audit","targets":["..."],"command":"...","plan_hash":"...","toolkit_commit":"...","rc":0}
```

## 10. Stage completion marker (`stage-N-<name>.done`)

```json
{"stage":"discovery","index":1,"rc":0,"finished":"ISO-8601","outputs":{"hosts-up.txt":"sha256:...","stage1-discovery.xml":"sha256:..."}}
```

Only written when the stage exits 0 and its primary XML parses. `--resume` verifies output hashes.
