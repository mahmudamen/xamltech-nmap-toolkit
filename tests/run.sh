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
check "python compiles" python3 -I -c "import ast,sys; ast.parse(open('$RPT').read())"
if command -v shellcheck >/dev/null; then check "shellcheck (warning level)" shellcheck -x -S warning "$TK" "$ROOT"/lib/*.sh "$ROOT/install.sh"; else skip "shellcheck not installed"; fi

echo "== cli basics"
contains "--version" "$("$TK" --version)" "2."
contains "--help lists --export" "$("$TK" --no-color --help)" "--export"
out="$(T --list-profiles)"
for p in discovery quick standard odoo pos audit recon vuln-safe; do contains "profile listed: $p" "$out" "$p"; done

echo "== input validation"
for bad_t in 'a;b' '$(id)' '`id`' 'x|y' '-oN' 'a b;c'; do
    check_not "rejects target [$bad_t]" "$TK" --no-color --no-banner -o "$TMP/res" -t "$bad_t" -p discovery -y --dry-run
done
for good in 192.168.1.0/24 10.0.0.1-5 ::1 localhost 'host-1.example.com' '192.168.1-3.*'; do
    check "accepts target [$good]" "$TK" --no-color --no-banner -o "$TMP/res" -t "$good" -p discovery -y --authorized --dry-run
done
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
python3 -I "$RPT" report --xml "$FIX/sample-vuln.xml" --outdir "$TMP/rep" --formats json,csv,md,html
for f in report.json hosts.csv services.csv findings.csv report.md report.html; do check "created $f" test -s "$TMP/rep/$f"; done
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
check_not "XML with entities rejected" bash -c "printf '<!DOCTYPE x [<!ENTITY a \"b\">]><nmaprun/>' > '$TMP/ent.xml'; python3 -I '$RPT' report --xml '$TMP/ent.xml' --outdir '$TMP/rep3'"

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
    for f in nmap.txt nmap.xml nmap.gnmap metadata.json report.json report.html summary.txt toolkit.log command.txt; do check "run dir has $f" test -s "$run/$f"; done
    check "latest symlink" test -L "$TMP/res/latest"
    T -t 127.0.0.1 -p recon --ports "$port" -y >/dev/null 2>&1; sleep 1
    out="$(T -t 127.0.0.1 -p recon --ports "$port" -y 2>&1)"
    contains "workflow: stage 2 found port" "$out" "open ports: $port"
    contains "workflow: previous-run diff"  "$out" "Changes since previous run"
    contains "history lists runs" "$(T --history)" "recon"
    out="$(T --export urls latest)"; contains "live export urls" "$out" "http://127.0.0.1:$port"
else
    skip "nmap not installed - live integration skipped"
fi

echo
printf 'Passed: %d   Failed: %d   Skipped: %d\n' "$PASS" "$FAIL" "$SKIP"
[[ $FAIL -eq 0 ]]
