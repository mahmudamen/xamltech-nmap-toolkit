#!/usr/bin/env bash
# XamlTech Nmap Toolkit - test suite (no network required; uses localhost only).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TK="$ROOT/nmap-toolkit.sh"
RPT="$ROOT/lib/report.py"
FIX="$ROOT/tests/fixtures"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [[ -n "${MOCK_PID:-}" ]] && kill "$MOCK_PID" 2>/dev/null' EXIT
PASS=0; FAIL=0; SKIP=0
export NO_COLOR=1 LANG=C.UTF-8
T() { "$TK" --no-color --no-banner -o "$TMP/res" "$@"; }

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '       %s\n' "$2"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
check_not() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$name (should have failed)"; else ok "$name"; fi; }
contains() { local name="$1" hay="$2" needle="$3"; if grep -qF -- "$needle" <<< "$hay"; then ok "$name"; else bad "$name" "missing: $needle"; fi; }
absent()   { local name="$1" hay="$2" needle="$3"; if grep -qF -- "$needle" <<< "$hay"; then bad "$name" "unexpected: $needle"; else ok "$name"; fi; }

echo "== static"
for f in "$TK" "$ROOT"/lib/*.sh "$ROOT"/install.sh; do check "bash -n $(basename "$f")" bash -n "$f"; done
check "python compiles" python3 -I -c "import ast,sys; [ast.parse(open(p).read()) for p in sys.argv[1:]]" "$RPT" "$ROOT/lib/projects.py"
if command -v shellcheck >/dev/null; then check "shellcheck (warning level)" shellcheck -x -S warning "$TK" "$ROOT"/lib/*.sh "$ROOT/install.sh"; else skip "shellcheck not installed"; fi
"$ROOT/install.sh" --prefix "$TMP/install" >/dev/null 2>&1
check "install ships project engine" test -s "$TMP/install/share/xamltech-nmap-toolkit/lib/projects.py"
check "install ships sample project" test -s "$TMP/install/share/xamltech-nmap-toolkit/config/projects/sample-assessment.json"

echo "== cli basics"
contains "--version" "$("$TK" --version)" "2."
contains "--help lists --export" "$("$TK" --no-color --help)" "--export"
contains "--help lists --no-open" "$("$TK" --no-color --help)" "--no-open"
mkdir -p "$TMP/openres/openrun" "$TMP/bin"
: > "$TMP/openres/openrun/report.html"; : > "$TMP/openres/openrun/service.html"
printf '#!/bin/sh\nprintf "%%s\\n" "$1" > "%s/opened"\n' "$TMP" > "$TMP/bin/xdg-open"
chmod +x "$TMP/bin/xdg-open"
PATH="$TMP/bin:$PATH" DISPLAY=:99 "$TK" --no-color --no-banner -o "$TMP/openres" --open-report openrun >/dev/null 2>&1
sleep 0.3
contains "--open-report opens service page first" "$(<"$TMP/opened")" "service.html"
out="$(T --list-profiles)"
for p in discovery quick standard odoo pos audit recon vuln-safe; do contains "profile listed: $p" "$out" "$p"; done

echo "== input validation"
for bad_t in 'a;b' '$(id)' '`id`' 'x|y' '-oN' 'a b;c'; do
    check_not "rejects target [$bad_t]" "$TK" --no-color --no-banner -o "$TMP/res" -t "$bad_t" -p discovery -y --dry-run
done
for good in 192.168.1.0/24 10.0.0.1-5 ::1 localhost 'host-1.example.com' '192.168.1-3.*'; do
    check "accepts target [$good]" "$TK" --no-color --no-banner -o "$TMP/res" -t "$good" -p discovery -y --authorized --dry-run
done
out="$(T -t '10.0.0.1 10.0.0.2' -p discovery -y --authorized --dry-run 2>&1)"
contains "space-separated targets: first"  "$out" "10.0.0.1"
contains "space-separated targets: second" "$out" "10.0.0.2"
out="$(T -t 10.0.0.1 -t 10.0.0.2 -p discovery -y --authorized --dry-run 2>&1)"
contains "repeatable -t: first"  "$out" "10.0.0.1"
contains "repeatable -t: second" "$out" "10.0.0.2"
check_not "rejects unknown profile" "$TK" --no-color --no-banner -t 127.0.0.1 -p nope -y
check_not "rejects bad timing"   "$TK" --no-color --no-banner -o "$TMP/res" -t 127.0.0.1 -p quick -T 9 -y --dry-run
check_not "rejects bad ports"    "$TK" --no-color --no-banner -o "$TMP/res" -t 127.0.0.1 -p quick --ports '80;id' -y --dry-run

echo "== guard rails"
for a in "--script brute" "--script=ssh-brute" "--script exploit" "--script dos" "-oN /tmp/x" "-oX /tmp/x" "--script-updatedb"; do
    check_not "custom args blocked [$a]" "$TK" --no-color --no-banner -o "$TMP/res" -t 127.0.0.1 -p custom -a "$a" -y --dry-run
done
check_not "--scripts brute blocked" "$TK" --no-color --no-banner -o "$TMP/res" -t 127.0.0.1 -p quick --scripts ssh-brute -y --dry-run
check_not "public target needs --authorized" "$TK" --no-color --no-banner -o "$TMP/res" -t 8.8.8.8 -p discovery -y --dry-run
check "public target with --authorized" "$TK" --no-color --no-banner -o "$TMP/res" -t 8.8.8.8 -p discovery -y --authorized --dry-run
printf '10.0.0.0/8\nlab.example.com\n*.corp.example.com\n' > "$TMP/scope.txt"
check_not "scope: out-of-scope refused" "$TK" --no-color --no-banner -o "$TMP/res" -t 192.168.0.1 -p discovery --scope "$TMP/scope.txt" -y --dry-run
check "scope: in-scope accepted" "$TK" --no-color --no-banner -o "$TMP/res" -t 10.1.2.0/24 -p discovery --scope "$TMP/scope.txt" -y --dry-run
check "scope: hostname in scope" "$TK" --no-color --no-banner -o "$TMP/res" -t lab.example.com -p discovery --scope "$TMP/scope.txt" -y --authorized --dry-run
check_not "scope: CIDR wider than scope" "$TK" --no-color --no-banner -o "$TMP/res" -t 10.0.0.0/7 -p discovery --scope "$TMP/scope.txt" -y --dry-run

echo "== config is data, never code"
printf 'THEME=ocean\nOUTPUT_DIR=$(touch %s/PWNED)\nEVIL=1\n' "$TMP" > "$TMP/evil.conf"
T --config "$TMP/evil.conf" --list-profiles >/dev/null 2>&1
[[ ! -e "$TMP/PWNED" ]] && ok "config values are not executed" || bad "config executed code!"
msg="$(T --config "$TMP/evil.conf" --list-profiles 2>&1 >/dev/null)"
contains "unknown config key warned" "$msg" "unknown key 'EVIL'"

echo "== dry-run & quote-aware args"
out="$(T -t 127.0.0.1 -p custom -a '-sV --script-args "a=b c" --top-ports 5' --dry-run 2>&1)"
contains "custom args split correctly" "$out" 'a=b\ c'
contains "dry-run executes nothing" "$out" "Dry run"
out="$(T -t 127.0.0.1 -p quick -T 2 --ports 22,80 --max-rate 100 --dry-run 2>&1)"
contains "timing override" "$out" "-T2"
contains "ports override" "$out" "-p22,80"
absent "top-ports replaced by --ports" "$out" "--top-ports 100"
contains "max-rate override" "$out" "--max-rate 100"
out="$(T -t 127.0.0.1 -p odoo --dry-run 2>&1)"
contains "odoo profile uses bundled NSE" "$out" "odoo-info.nse"
contains "honest user-agent" "$out" "XamlTech-Nmap-Toolkit"

echo "== report engine (fixture)"
mkdir -p "$TMP/rep"
python3 -I "$ROOT/lib/projects.py" summaries > "$TMP/rep/projects.json"
python3 -I "$RPT" report --xml "$FIX/sample-vuln.xml" --outdir "$TMP/rep" --formats json,csv,md,html \
    --projects-json "$TMP/rep/projects.json"
for f in report.json hosts.csv services.csv findings.csv report.md report.html service.html projects.html; do check "created $f" test -s "$TMP/rep/$f"; done
service_html="$(cat "$TMP/rep/service.html")"
contains "service page links report" "$service_html" 'href="report.html"'
contains "service page links projects" "$service_html" 'href="projects.html"'
contains "service page has keyboard focus styles" "$service_html" ':focus-visible'
contains "service page states run metrics" "$service_html" 'Current run'
projects_html="$(cat "$TMP/rep/projects.html")"
contains "projects page links back to service" "$projects_html" 'href="service.html"'
contains "projects page lists bundled sample" "$projects_html" 'sample-assessment'
fj="$(cat "$TMP/rep/findings.csv")"
contains "finding: MS17-010 critical" "$fj" "CRITICAL"
contains "finding: telnet"            "$fj" "Telnet"
contains "finding: SMBv1"             "$fj" "SMBv1 enabled"
contains "finding: redis unauth"      "$fj" "Redis answers without authentication"
contains "finding: expired cert"      "$fj" "certificate expired"
contains "finding: self-signed"       "$fj" "Self-signed"
contains "finding: deprecated TLS"    "$fj" "Deprecated protocol enabled: TLSv1.0"
contains "finding: weak cipher grade" "$fj" "Weak cipher strength grade C"
contains "finding: RC4"               "$fj" "Insecure cipher suites"
contains "finding: SHA-1 cert"        "$fj" "weak hash"
contains "finding: db port"           "$fj" "port reachable"
absent "CSV formula neutralised"      "$(cut -d, -f1-12 "$TMP/rep/services.csv" | grep -E '(^|,)=cmd')" "=cmd"
contains "CSV formula prefixed with quote" "$(cat "$TMP/rep/services.csv")" "'=cmd"
html="$(cat "$TMP/rep/report.html")"
absent "HTML: no raw <script> from banner" "$html" "<script>alert(1)</script>"
contains "HTML: banner escaped" "$html" "&lt;script&gt;alert(1)&lt;/script&gt;"
md="$(cat "$TMP/rep/report.md")"
contains "markdown has findings table" "$md" "| Severity | Host |"
check "report.json is valid JSON" python3 -I -c "import json;json.load(open('$TMP/rep/report.json'))"
dash="$(python3 -I "$RPT" dashboard "$TMP/rep/report.json" --width 100)"
contains "dashboard shows hosts up" "$dash" "HOSTS UP 2/2"
contains "dashboard top findings" "$dash" "Top findings"

echo "== exports"
contains "export urls (https via ssl tunnel)" "$(python3 -I "$RPT" export urls "$TMP/rep")" "https://192.0.2.20"
contains "export urls (non-default port)"     "$(python3 -I "$RPT" export urls "$TMP/rep")" "http://192.0.2.10:8080"
contains "export hostports" "$(python3 -I "$RPT" export hostports "$TMP/rep")" "192.0.2.10:445"
contains "export ports"     "$(python3 -I "$RPT" export ports "$TMP/rep")" "22,23,443,445,6379,8080"
contains "export openvas"   "$(python3 -I "$RPT" export openvas "$TMP/rep")" "192.0.2.10,192.0.2.20"

echo "== diff"
sed 's/portid="23"/portid="2323"/; s/<host><status state="up" reason="syn-ack"\/><address addr="192.0.2.20"/<host><status state="up" reason="syn-ack"\/><address addr="192.0.2.99"/' "$FIX/sample-vuln.xml" > "$TMP/changed.xml"
mkdir -p "$TMP/rep2"; python3 -I "$RPT" report --xml "$TMP/changed.xml" --outdir "$TMP/rep2" --formats json
d="$(python3 -I "$RPT" diff "$TMP/rep" "$TMP/rep2")"
contains "diff: new host"      "$d" "host up        192.0.2.99"
contains "diff: gone host"     "$d" "host gone      192.0.2.20"
contains "diff: port opened"   "$d" "2323/tcp"
contains "diff: port closed"   "$d" "23/tcp"
check_not "diff --fail-on-change exits non-zero" python3 -I "$RPT" diff "$TMP/rep" "$TMP/rep2" --fail-on-change
check "diff identical = exit 0" python3 -I "$RPT" diff "$TMP/rep" "$TMP/rep" --fail-on-change
mkdir -p "$TMP/mix-a" "$TMP/mix-b"
python3 -I - "$TMP" <<'PY'
import json, os, sys
root = sys.argv[1]
def rep(findings):
    return {"schema": 1, "generated": "x", "meta": {}, "scan": {"stages": [], "elapsed": 0,
            "nmap_version": "", "args": ""}, "stats": {"hosts_total": 1, "hosts_up": 1,
            "open_ports": 1, "services": {}, "findings": {}}, "hosts": [], "prescripts": [],
            "findings": findings}
f = [{"severity": "LOW", "host": "same", "port": None, "proto": None, "title": "A",
      "detail": "", "advice": "", "source": "x"},
     {"severity": "LOW", "host": "same", "port": 80, "proto": "tcp", "title": "B",
      "detail": "", "advice": "", "source": "x"}]
for name, findings in (("mix-a", f), ("mix-b", [])):
    with open(os.path.join(root, name, "report.json"), "w") as fh:
        json.dump(rep(findings), fh)
PY
check "diff mixed port=None/int findings" python3 -I "$RPT" diff "$TMP/mix-a" "$TMP/mix-b"
python3 -I "$RPT" diff "$TMP/mix-b" "$TMP/mix-a" --fail-on LOW >/dev/null 2>&1; rc=$?
[[ $rc -eq 10 ]] && ok "diff --fail-on LOW exits 10" || bad "diff --fail-on LOW rc=$rc"
python3 -I "$RPT" diff "$TMP/mix-b" "$TMP/mix-a" --fail-on HIGH >/dev/null 2>&1; rc=$?
[[ $rc -eq 0 ]] && ok "diff --fail-on HIGH stays 0" || bad "diff --fail-on HIGH rc=$rc"
check "baseline create" python3 -I "$RPT" baseline create "$TMP/mix-a" -b "$TMP/baseline.json"
check "baseline check" python3 -I "$RPT" baseline check "$TMP/mix-a" -b "$TMP/baseline.json"
check_not "XML with entities rejected" bash -c "printf '<!DOCTYPE x [<!ENTITY a \"b\">]><nmaprun/>' > '$TMP/ent.xml'; python3 -I '$RPT' report --xml '$TMP/ent.xml' --outdir '$TMP/rep3'"

echo "== compliance"
plan1="$(T -t 127.0.0.1 -p discovery --dry-run --json)"
plan2="$(T -t 127.0.0.1 -p discovery --dry-run --json)"
[[ "$plan1" == "$plan2" ]] && ok "dry-run JSON plan deterministic" || bad "plan drift"
hash1="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["plan_hash"])' "$plan1")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); open(sys.argv[2],"w").write(json.dumps(d))' "$plan1" "$TMP/plan.json"
check "approved plan accepted" bash -c "'$TK' -t 127.0.0.1 -p discovery --dry-run --plan-file '$TMP/plan.json' --plan-hash '$hash1'"
check_not "tampered plan rejected" bash -c "'$TK' -t 127.0.0.1 -p discovery --dry-run --plan-file '$TMP/plan.json' --plan-hash deadbeef"
printf '{"allow":["127.0.0.0/8"],"deny":["127.0.0.1/32"],"max_hosts":2,"valid_from":"2020-01-01T00:00:00Z"}\n' > "$TMP/scope-v2.json"
python3 -I "$RPT" scope "$TMP/scope-v2.json" 127.0.0.1 >/dev/null 2>&1; rc=$?
[[ $rc -eq 4 ]] && ok "scope v2 deny exits 4" || bad "scope v2 deny rc=$rc"
printf '10.0.0.0/8\n' > "$TMP/scope-legacy.txt"
check "legacy scope still works" python3 -I "$RPT" scope "$TMP/scope-legacy.txt" 10.0.0.1

echo "== presets, groups, history, estimate"
export XAMLTECH_NMAP_CONFIG_DIR="$TMP/cfg"
mkdir -p "$XAMLTECH_NMAP_CONFIG_DIR/groups"
out="$(T -t 127.0.0.1 -p discovery --dry-run --save-preset smoke 2>&1)"
contains "save preset confirmation" "$out" "Saved preset 'smoke'"
check "preset file is JSON array" python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert isinstance(d,list) and '127.0.0.1' in d" "$XAMLTECH_NMAP_CONFIG_DIR/presets/smoke.json"
out="$(T --preset smoke --dry-run 2>&1)"
contains "preset round-trip target" "$out" "127.0.0.1"
[[ ! -e "$XAMLTECH_NMAP_CONFIG_DIR/history.jsonl" ]] && ok "dry-run writes no history" || bad "dry-run wrote history"
check_not "invalid preset name rejected" "$TK" --no-color --no-banner --preset '../evil' --dry-run
python3 - "$XAMLTECH_NMAP_CONFIG_DIR/history.jsonl" "$TMP/res" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    fh.write(json.dumps({"ts": "2026-01-01T00:00:00+00:00",
                         "argv": ["--no-color", "--no-banner", "-o", sys.argv[2],
                                  "-t", "127.0.0.1", "-p", "discovery", "--dry-run"]}) + "\n")
PY
out="$(T --replay 1 --dry-run 2>&1)"
contains "history replay target" "$out" "127.0.0.1"
printf '10.0.0.1\n10.0.0.2\n' > "$XAMLTECH_NMAP_CONFIG_DIR/groups/lab.txt"
out="$(T --target-group lab -p discovery --dry-run 2>&1)"
contains "target group first" "$out" "10.0.0.1"
contains "target group second" "$out" "10.0.0.2"
mkdir -p "$TMP/estres/20260101_000000_discovery_localhost"
printf '{"started_epoch": 1767225600}\n' > "$TMP/estres/20260101_000000_discovery_localhost/metadata.json"
printf '{"generated": "2026-01-01T00:01:40+00:00"}\n' > "$TMP/estres/20260101_000000_discovery_localhost/report.json"
out="$("$TK" --no-color --no-banner -o "$TMP/estres" -t 127.0.0.1 -p discovery --estimate)"
contains "estimate stages" "$out" "Workflow stages"
contains "estimate prior duration" "$out" "Prior duration"
contains "registry categories exposed" "$(bash -c 'source "$0/lib/options.sh"; options_emit_categories' "$ROOT")" "tuning|TUNING"
out="$(printf '1\n1\n127.0.0.1\n' | bash -c 'source "$0/lib/options.sh"; source "$0/lib/ui.sh"; source "$0/lib/core.sh"; source "$0/lib/nse.sh"; source "$0/lib/profiles.sh"; source "$0/lib/scan.sh"; source "$0/lib/interactive.sh"; THEME=cyber; ui_init; ui_theme "$THEME"; ui_define_colors; advanced_options_menu' "$ROOT" 2>&1)"
contains "advanced menu non-TTY fallback" "$out" "Advanced option categories"
unset XAMLTECH_NMAP_CONFIG_DIR

echo "== profiles and workflows"
xdg="$TMP/xdg"; mkdir -p "$xdg/xamltech-nmap-toolkit/profiles"
printf 'extends=standard\nports=80,443\ndesc=Test user profile\n' > "$xdg/xamltech-nmap-toolkit/profiles/myweb.txt"
out="$(XDG_CONFIG_HOME="$xdg" T -t 127.0.0.1 -p myweb --dry-run -y 2>&1)"
contains "user profile loaded" "$out" "myweb"
contains "user profile ports" "$out" '-p80,443'
contains "user profile description" "$out" "Test user profile"
check_not "invalid --stage rejected" bash -c "'$TK' --stage bogus --version"
check_not "resume needs workflow" bash -c "'$TK' --resume '$TMP' --version"
out="$(T -t 127.0.0.1 -p recon --stage discovery --dry-run -y 2>&1)"
contains "workflow stage select" "$out" "Workflow: recon"
printf 'stage|recon|1|bad|discovery|original||||0|nope\n' > "$TMP/bad-stages.txt"
check_not "malformed stage record rejected" bash -c "XAMLTECH_NMAP_STAGES_FILE='$TMP/bad-stages.txt' source '$ROOT/lib/options.sh'; XAMLTECH_NMAP_STAGES_FILE='$TMP/bad-stages.txt' source '$ROOT/lib/ui.sh'; XAMLTECH_NMAP_STAGES_FILE='$TMP/bad-stages.txt' source '$ROOT/lib/core.sh'; XAMLTECH_NMAP_STAGES_FILE='$TMP/bad-stages.txt' source '$ROOT/lib/nse.sh'; XAMLTECH_NMAP_STAGES_FILE='$TMP/bad-stages.txt' source '$ROOT/lib/profiles.sh'"
check "stage condition port match" bash -c "source '$ROOT/lib/options.sh'; source '$ROOT/lib/ui.sh'; source '$ROOT/lib/core.sh'; source '$ROOT/lib/nse.sh'; source '$ROOT/lib/profiles.sh'; source '$ROOT/lib/scan.sh'; stage_condition_met 'port in 22,80' '22' 1"
check_not "stage condition port miss" bash -c "source '$ROOT/lib/options.sh'; source '$ROOT/lib/ui.sh'; source '$ROOT/lib/core.sh'; source '$ROOT/lib/nse.sh'; source '$ROOT/lib/profiles.sh'; source '$ROOT/lib/scan.sh'; stage_condition_met 'port in 22,80' '443' 1"
check "stage abort on failure" bash -c "source '$ROOT/lib/options.sh'; source '$ROOT/lib/ui.sh'; source '$ROOT/lib/core.sh'; source '$ROOT/lib/nse.sh'; source '$ROOT/lib/profiles.sh'; source '$ROOT/lib/scan.sh'; stage_should_abort 1 abort"
check_not "stage continue on failure" bash -c "source '$ROOT/lib/options.sh'; source '$ROOT/lib/ui.sh'; source '$ROOT/lib/core.sh'; source '$ROOT/lib/nse.sh'; source '$ROOT/lib/profiles.sh'; source '$ROOT/lib/scan.sh'; stage_should_abort 1 continue"
check_not "stage success never aborts" bash -c "source '$ROOT/lib/options.sh'; source '$ROOT/lib/ui.sh'; source '$ROOT/lib/core.sh'; source '$ROOT/lib/nse.sh'; source '$ROOT/lib/profiles.sh'; source '$ROOT/lib/scan.sh'; stage_should_abort 0 abort"
python3 - "$TMP/baseline.json" <<'PY'
import json, sys
json.dump({"schema_version": 2, "hosts": [{"address": "127.0.0.1", "status": "up",
    "ports": [{"port": 22, "proto": "tcp", "state": "open", "service": "ssh"}]}], "findings": []},
    open(sys.argv[1], "w", encoding="utf-8"))
PY
out="$(T -t 127.0.0.1 -p discovery --incremental "$TMP/baseline.json" --dry-run 2>&1)"
contains "incremental skips known targets" "$out" "All targets are already present in the baseline"

echo "== advanced nmap options"
out="$(T -t 127.0.0.1 -p standard --min-rate 50 --max-parallelism 3 --version-intensity 7 --exclude-ports 9999 --fast-scan --data-length 20 --ttl 64 --mtu 1400 --dry-run -y 2>&1)"
contains "advanced: --min-rate"        "$out" '--min-rate\ 50'
contains "advanced: --max-parallelism" "$out" '--max-parallelism\ 3'
contains "advanced: --version-intensity" "$out" '--version-intensity\ 7'
contains "advanced: --exclude-ports"   "$out" '--exclude-ports\ 9999'
contains "advanced: -F"                "$out" '-F'
contains "advanced: --data-length"     "$out" '--data-length\ 20'
contains "advanced: --ttl"             "$out" '--ttl\ 64'
contains "advanced: --mtu"             "$out" '--mtu\ 1400'
out="$(T -t 127.0.0.1 -p standard -PS80,443 --scanflags 'S|AF' --dry-run -y --ack-risk --explain 2>&1)"
contains "advanced: -PS probe adapted"  "$out" '-PS80,443 dropped'
contains "advanced: --scanflags trace"  "$out" '--scanflags S|AF (from --scanflags)'
contains "explain: override reason"     "$out" 'from --scanflags'
check_not "invalid --min-rate"         bash -c "'$TK' --min-rate 0 --version"
check_not "invalid --scanflags hex"    bash -c "'$TK' --scanflags 0x1 --version"
check_not "invalid --ttl"              bash -c "'$TK' --ttl 999 --version"
check_not "invalid --mtu"              bash -c "'$TK' --mtu 4 --version"
check_not "packet-trace needs verbose" bash -c "'$TK' --packet-trace --version"
check_not "advanced policy needs ack"  bash -c "'$TK' --policy advanced --version"
check_not "moderate option needs ack"  bash -c "'$TK' --syn-scan --version"
for bad in '-D 1.2.3.4' '-S 1.2.3.4' '-g 1234' '--proxy http://p:8080' '--badsum' '-f'; do
    check_not "blocked custom arg [$bad]" bash -c "'$TK' -t 127.0.0.1 -p custom -a '$bad' --dry-run -y --authorized"
done

echo "== option registry"
mapfile -t _flags < <(sed -n '/^parse_args()/,/^}/p' "$TK" | tr '|' '\n' | grep -oE -- '^ *--?[0-9A-Za-z][A-Za-z0-9-]*' | tr -d ' ' | sort -u)
for f in "${_flags[@]}"; do
    if bash -c "source '$ROOT/lib/options.sh'; option_check_flag '$f'"; then ok "registry covers $f"; else bad "registry missing $f"; fi
done
contains "help generated from registry" "$("$TK" --help --no-color)" "--dump-options"
json="$("$TK" --dump-options 2>/dev/null)"
check "dump-options is JSON" python3 -I -c "import json,sys; d=json.loads(sys.argv[1]); assert len(d) >= 50" "$json"
check "completion drift" diff -u "$ROOT/completions/xamltech-nmap.bash" <(bash -c "source '$ROOT/lib/options.sh'; options_emit_completion")
check "option docs drift" diff -u "$ROOT/docs/OPTIONS.md" <(bash -c "source '$ROOT/lib/options.sh'; options_emit_docs")
keys="$(bash -c "source '$ROOT/lib/options.sh'; options_emit_config_keys" | paste -sd' ' -)"
contains "config keys generated" "$keys" "OUTPUT_DIR"

echo "== live integration (localhost, real nmap)"
if command -v nmap >/dev/null; then
    port=$((20000 + RANDOM % 20000))
    python3 "$FIX/mock_odoo.py" "$port" --version 15.0 --expose-db --expose-manager >/dev/null 2>&1 & MOCK_PID=$!
    sleep 1
    out="$(T -t 127.0.0.1 -p odoo --ports "$port" -y 2>&1)"; rc=$?
    [[ $rc -eq 0 ]] && ok "odoo scan exits 0" || bad "odoo scan rc=$rc" "$out"
    contains "live: Odoo version found"       "$out" "Odoo 15.0 detected"
    contains "live: DB manager flagged"       "$out" "database manager page is reachable"
    contains "live: DB listing flagged"       "$out" "database listing is public"
    contains "live: out-of-support flagged"   "$out" "likely out of support"
    run="$(find "$TMP/res" -mindepth 1 -maxdepth 1 -type d -name '*_odoo_*' | head -1)"
    [[ -n "$run" ]] && ok "dry runs left no directories behind (only the real run exists)" || bad "no odoo run dir"
    [[ "$(find "$TMP/res" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ]] && ok "exactly one run dir so far" || bad "stray run dirs from dry-runs"
    for f in nmap.txt nmap.xml nmap.gnmap metadata.json report.json report.html summary.txt toolkit.log command.txt audit.log; do check "run dir has $f" test -s "$run/$f"; done
    [[ "$(stat -c %a "$run/audit.log")" == 600 ]] && ok "audit.log is 0600" || bad "audit.log mode $(stat -c %a "$run/audit.log")"
    contains "report schema_version 2" "$(<"$run/report.json")" '"schema_version": 2'
    contains "report rule_id" "$(<"$run/report.json")" '"rule_id"'
    contains "report integrity manifest" "$(<"$run/report.json")" '"native_sha256"'
    check "sarif export" python3 -I "$RPT" sarif "$run" -o "$TMP/out.sarif"
    check "sarif valid JSON 2.1.0" python3 -I -c "import json,sys; d=json.load(open('$TMP/out.sarif')); assert d['version']=='2.1.0' and d['runs'][0]['tool']['driver']['name']"
    check "latest symlink" test -L "$TMP/res/latest"
    T -t 127.0.0.1 -p recon --ports "$port" -y >/dev/null 2>&1; sleep 1
    out="$(T -t 127.0.0.1 -p recon --ports "$port" -y 2>&1)"
    contains "workflow: stage 2 found port" "$out" "open ports: $port"
    contains "workflow: previous-run diff"  "$out" "Changes since previous run"
    latest_run="$(readlink -f "$TMP/res/latest")"
    contains "HTML findings columns sortable" "$(<"$latest_run/report.html")" 'class="sortable"'
    contains "HTML side-by-side diff" "$(<"$latest_run/report.html")" 'diffgrid'
    contains "history lists runs" "$(T --history)" "recon"
    out="$(T --export urls latest)"; contains "live export urls" "$out" "http://127.0.0.1:$port"
else
    skip "nmap not installed - live integration skipped"
fi

echo "== projects"
export XAMLTECH_NMAP_PROJECTS_DIR="$TMP/projects"
mkdir -p "$XAMLTECH_NMAP_PROJECTS_DIR"
out="$(T --project-create cli-lab --project-info 'Authorized lab' --project-goals 'Inventory hosts,Review ports' 2>&1)"
contains "project create" "$out" "Created project cli-lab"
out="$(T --project-step-add cli-lab --project-step discover --goal 'Find hosts' --project-args '-t 127.0.0.1 -p discovery' 2>&1)"
contains "project step add" "$out" "Added step discover"
out="$(T --project-step-add cli-lab --project-step ports --goal 'Find ports' 2>&1)"
contains "project second step add" "$out" "Added step ports"
out="$(T --project-show cli-lab 2>&1)"
contains "project show lists plan" "$out" "1. discover [todo] Find hosts"
contains "project show orders plan" "$out" "2. ports [todo] Find ports"
contains "project show next action" "$out" "Next action: discover"
out="$(T --project-resume cli-lab -y --dry-run 2>&1)"
contains "project resume loads saved args" "$out" "Profile        discovery"
contains "project resume keeps project" "$out" "Project        cli-lab"
out="$(T --project-step-status cli-lab discover=done --note 'Hosts found' 2>&1)"
contains "project step status" "$out" "discover: done"
out="$(T --project-show cli-lab 2>&1)"
contains "project advances next action" "$out" "Next action: ports"
out="$(T --project-list 2>&1)"
contains "project list shows status" "$out" "cli-lab"
contains "project sample bundled" "$(T --project-show sample-assessment 2>&1)" "Next action: discover"
check_not "project rejects hostile name" "$TK" --no-color --no-banner --project-create '../escape' --project-info x
out="$(T --project-step-status cli-lab ports=needs-action --note 'Waiting for operator' 2>&1)"
contains "project needs-action status" "$out" "ports: needs-action"

if [[ -f "$FIX/sample-vuln.xml" ]]; then
    report_dir="$TMP/project-report"; mkdir -p "$report_dir"
    cp "$FIX/sample-vuln.xml" "$report_dir/nmap.xml"
    XAMLTECH_PROJECT_ARGV=$'-t\n127.0.0.1\n-p\ndiscovery' \
        python3 -I "$ROOT/lib/projects.py" record-scan cli-lab \
        --run "$report_dir" --profile discovery --targets 127.0.0.1 \
        --status 'done' --step discover >/dev/null
    python3 -I "$ROOT/lib/projects.py" summary cli-lab > "$report_dir/project.json"
    python3 -I "$ROOT/lib/projects.py" summaries > "$report_dir/projects.json"
    python3 -I "$RPT" report --xml "$report_dir/nmap.xml" --outdir "$report_dir" --formats md,html \
        --projects-json "$report_dir/projects.json" >/dev/null 2>&1
    contains "markdown has project summary" "$(<"$report_dir/report.md")" "## Project"
    contains "markdown has plan order" "$(<"$report_dir/report.md")" "1 | discover | done"
    contains "markdown has timeline header" "$(<"$report_dir/report.md")" "Scan timeline (in order)"
    contains "html has project section" "$(<"$report_dir/report.html")" "<h2>Project</h2>"
    contains "service page shows next action" "$(<"$report_dir/service.html")" "Next action"
    contains "projects page lists test project" "$(<"$report_dir/projects.html")" "cli-lab"
    contains "projects page links current run" "$(<"$report_dir/projects.html")" "service.html"
    contains "dashboard has project section" "$(python3 -I "$RPT" dashboard "$report_dir/report.json")" "Project"
else
    skip "project report integration (fixture missing)"
fi

echo
printf 'Passed: %d   Failed: %d   Skipped: %d\n' "$PASS" "$FAIL" "$SKIP"
[[ $FAIL -eq 0 ]]
