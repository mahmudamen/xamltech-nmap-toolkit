# Role
You are a senior security-tooling engineer extending the **XamlTech Nmap Toolkit** (Bash 4.4+, Python 3 stdlib only, Nmap/NSE, Linux).
Goal: make it a complete network assessment tool: host discovery, OS and service fingerprinting, vulnerability detection, a managed NSE script library (custom, advanced and community), and a safe way to search and update community scripts from public GitHub.

Follow Clean Code, TDD, BDD, DDD and SOLID. Behavior of existing CLI flags, exit codes and output layout stays backward compatible.

# Authorization and safety (non-negotiable)
- Use only against systems the operator owns or is explicitly authorized to test. Keep the existing consent flow (`I AM AUTHORIZED` / `--authorized`) and `--scope` enforcement (exit `4`).
- NEVER enable or ship NSE categories `brute`, `dos`, `exploit`, `fuzzer`, or `intrusive` by default. `vuln` scripts that are intrusive stay behind `--policy advanced --ack-risk`.
- No decoys, spoofing, proxies, evasion, or silent privilege escalation.
- Scan results and downloaded scripts are **untrusted input**. Escape all output, reject XML entities, never `eval`/`source` fetched content.
- No shell strings built from input; Nmap args are arrays.

# Feature 1: Complete assessment coverage
Add or complete these profiles, each defined as data in a registry (Open/Closed):
- `fingerprint`: `-sV --version-intensity`, `-O --osscan-guess` (privilege fallback reported), `--script banner,http-title,ssl-cert,ssh-hostkey,smb-os-discovery,nbstat,rdp-ntlm-info,snmp-info,http-server-header`
- `vuln-safe`: only non-intrusive `vuln`/`safe` scripts plus `vulners` (CVE mapping from service CPEs), `http-vuln-*` and `ssl-*` checks that are read-only
- `vuln-deep`: advanced, opt-in, includes `vulscan` (local CVE databases) and intrusive `vuln` scripts, requires `--policy advanced --ack-risk`
- `full-assessment`: staged workflow discovery, then ports, then fingerprint, then vuln-safe, then report; each stage runs only on hosts and ports found by the previous stage
- Keep the existing `mynetwork`, `iot`, `audit` profiles and make them reuse the same stages

Parse OS, services, CPEs, CVE ids, CVSS and script output into domain objects (`Host`, `Service`, `OsGuess`, `Finding`, `Cve`) and feed the existing findings engine, reports, diff and SARIF export.

# Feature 2: Script library layout
```text
scripts/
├── custom/        first-party NSE scripts
├── advanced/      first-party scripts needing --policy advanced
├── community/     fetched from GitHub, pinned and verified (never hand-edited)
├── quarantine/    freshly downloaded, NOT usable until approved
├── manifest.json  name, source repo, pinned commit SHA, sha256 per file, license, categories, approved_by, approved_at
└── allowlist.json permitted repos and paths
```
Each script must have a valid NSE header (`description`, `categories`, `author`, `license`) and a `--script-help` entry. Provide `--list-scripts [FILTER]`, `--script-help NAME`, and `--scripts-verify` (recompute hashes against the manifest, exit non-zero on drift).

# Feature 3: Search and update from public GitHub
Commands:
- `--search-scripts QUERY`: search GitHub (repos tagged `nse`, `nmap-scripts`, `nmap-nse`, and code search for `.nse` files) via the public REST API. Show repo, stars, license, last push, matching files. Optional `GITHUB_TOKEN` env var only to raise rate limits (never stored or logged).
- `--update-scripts [--source NAME]`: for each allowlisted repo, resolve the latest **commit SHA**, download files by SHA (not by branch name) into `scripts/quarantine/`, and show a unified diff against the current approved version.
- `--approve-script NAME`: after the operator reviews the diff, move it from quarantine to `scripts/community/`, update `manifest.json`, then run `nmap --script-updatedb`.
- `--update-nmap-db`: refresh Nmap's `script.db` and report the Nmap version and its CVE-relevant data files.
- Seed allowlist (verify each is still maintained and its license permits redistribution): `vulnersCom/nmap-vulners`, `scipag/vulscan`, `nmap/nmap` (official scripts). Adding a repo needs an explicit `--allow-source OWNER/REPO` plus confirmation.

Download vetting (all mandatory, test each one):
1. HTTPS only, certificate verification on, size limit and timeout per file, rate-limit handling (honor `Retry-After`).
2. Only paths ending in `.nse`, `.lua`, `.csv`, `.json` or `.db` from allowlisted repos; reject path traversal and symlinks.
3. Static review of every script before approval, flagging and blocking: categories `brute|dos|exploit|fuzzer`, `os.execute`, `io.popen`, `os.remove`, `package.loadlib`, `loadstring`/`load` on network data, writes outside the nmap temp dir, and connections to hosts other than the scan target.
4. License detected and recorded; unknown license means blocked until the operator overrides explicitly.
5. Nothing downloaded is ever executed during update; execution only happens in a later, scope-checked scan after approval.
6. Append every search, download, approval and hash to the `0600` audit log. Support `--offline` so the toolkit works with no network, and `--dry-run` for the updater.

# Architecture (DDD and SOLID)
Bounded contexts: Scope and Authorization, Scan Planning, Execution, Findings, Change Detection, Reporting, **Script Library** (new: catalog, manifest, vetting, GitHub source).
- `ScriptSource` interface (`search`, `latest_ref`, `fetch`), so GitHub is one implementation and tests inject a fake (DIP).
- `ScriptVetter` as a chain of small rule objects, so adding a rule never edits the engine (OCP).
- Domain logic is I/O-free; HTTP, filesystem, clock and nmap executor are injected.
- Python stdlib only (`urllib`, `hashlib`, `json`, `difflib`, `unittest`).

# Tests (write first, Red → Green → Refactor)
BDD scenarios, for example:
- Given a downloaded script containing `os.execute`, When I run the vetter, Then it stays in quarantine and the reason is reported.
- Given a manifest hash that no longer matches the file, When I run `--scripts-verify`, Then it exits non-zero naming the file.
- Given `--offline`, When I run `--update-scripts`, Then nothing is fetched and the exit message says so.
- Given a non-root user, When I run `fingerprint`, Then OS detection is dropped and the plan reports it.
- Given a target outside the scope file, When I run any profile, Then it is refused with exit `4`.
- Given a GitHub API rate-limit response, When searching, Then the toolkit backs off and reports the reset time.
Include hostile-input tests (malicious script name, huge file, redirect to another host, banner injection into the HTML report). Use a local fake GitHub server in tests; no real network calls in `make test`.

# Quality gates
`make test`, `make lint` (ShellCheck clean, `py_compile`), `make option-drift`, type hints on new Python, no function above cyclomatic complexity 10. Register new options in `lib/options.sh`, then run `make completions options-docs`.

# Deliverables
Code and tests (tests-first history), `docs/SCRIPTS.md` (library layout, how to add a script, the vetting rules), `docs/ARCHITECTURE.md` update, README and CHANGELOG updates, and a final report with before/after metrics and remaining risks.

# Start now
Step 1: explore the repo and run the baseline (`make test`, `make lint`). Step 2: show me the plan and the Script Library domain model. Do not modify code before I approve the plan.