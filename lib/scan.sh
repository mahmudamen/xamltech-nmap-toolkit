# shellcheck shell=bash
# XamlTech Nmap Toolkit - scan engine
# Run directories, single-profile scans, multi-stage workflows, live rendering,
# post-processing (inventory, latency, reports, diff against previous run).

RUN_DIR=""
START_EPOCH=0
RUN_XMLS=()
STAGE_FILES=()
NMAP_PID=""

# py_report SUBCOMMAND ARGS...  (adds --color to terminal-facing views when enabled)
py_report() {
    local cmd="$1"; shift
    local -a extra=()
    case "$cmd" in dashboard|diff|history) (( UI_COLOR )) && extra=(--color) ;; esac
    python3 -I "$LIB_DIR/report.py" "$cmd" "$@" "${extra[@]}"
}
have_py()   { command_exists python3 && [[ -f "$LIB_DIR/report.py" ]]; }

# ---------- run directory & metadata ----------

prepare_run_dir() {
    local stamp label base n=0
    stamp="$(safe_timestamp)"; label="$(target_label)"
    base="$OUTPUT_DIR/${stamp}_${PROFILE}_${label}"
    RUN_DIR="$base"
    if (( DRY_RUN )); then return 0; fi     # dry runs never touch the disk
    while [[ -e "$RUN_DIR" ]]; do n=$(( n + 1 )); RUN_DIR="${base}-$n"; done
    mkdir -p "$RUN_DIR"
    RUN_DIR="$(cd "$RUN_DIR" && pwd)"
    log_init
    ln -sfn "$(basename "$RUN_DIR")" "$OUTPUT_DIR/latest" 2>/dev/null || true
}

json_escape() { printf '%s' "$1" | tr '\n\r\t' '   ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

write_metadata() {
    local cmd_line="$1"
    (( DRY_RUN )) && return 0
    cat > "$RUN_DIR/metadata.txt" <<EOF
XamlTech Nmap Toolkit
=====================
Toolkit version : $SCRIPT_VERSION
Author          : $AUTHOR
Started         : $(timestamp)
Target          : $(target_display)
Profile         : $PROFILE
Nmap binary     : $NMAP_BIN
Nmap version    : $(nmap_version)
Privileged      : $( ((NMAP_PRIVILEGED)) && echo yes || echo no )
EOF
    cat > "$RUN_DIR/metadata.json" <<EOF
{
  "toolkit": "$SCRIPT_NAME",
  "toolkit_version": "$SCRIPT_VERSION",
  "started": "$(timestamp)",
  "started_epoch": $(date +%s),
  "targets": "$(json_escape "${TARGETS[*]:-}")",
  "profile": "$(json_escape "$PROFILE")",
  "nmap_version": "$(json_escape "$(nmap_version)")",
  "privileged": $( ((NMAP_PRIVILEGED)) && echo true || echo false ),
  "operator": "$(json_escape "${SUDO_USER:-${USER:-unknown}}")",
  "host": "$(json_escape "$(hostname 2>/dev/null || echo unknown)")",
  "command": "$(json_escape "$cmd_line")"
}
EOF
}

fix_ownership() {
    [[ -n "${SUDO_USER:-}" && -n "${RUN_DIR:-}" ]] || return 0
    is_root || return 0
    chown -R "$SUDO_USER" "$RUN_DIR" "$OUTPUT_DIR/latest" 2>/dev/null || true
    chown "$SUDO_USER" "$OUTPUT_DIR" 2>/dev/null || true
}

# ---------- plan display ----------

# Readable command display: quote only arguments that actually need it
shell_quote() {
    local a
    for a in "$@"; do
        if [[ "$a" =~ ^[A-Za-z0-9_@%+=:,./-]+$ ]]; then printf ' %s' "$a"; else printf ' %q' "$a"; fi
    done
}

show_plan() {
    local cmd_display="$1"
    section "Scan plan"
    kv "Target"  "$(target_display)"
    kv "Profile" "$PROFILE  ($(profile_desc "$PROFILE" 2>/dev/null || echo custom))"
    local risk; risk="$(profile_risk "$PROFILE" 2>/dev/null || echo safe)"
    kv "Risk"    "$(risk_badge "$risk")" ""
    kv "Privileges" "$( ((NMAP_PRIVILEGED)) && echo 'raw sockets available' || echo 'unprivileged (TCP-connect mode)' )" \
        "$( ((NMAP_PRIVILEGED)) && echo "$C_GREEN" || echo "$C_YELLOW" )"
    kv "Output"  "$RUN_DIR"
    kv "Formats" "${REPORT_FORMATS}"
    if (( ${#ADAPT_NOTES[@]} )); then
        local n
        for n in "${ADAPT_NOTES[@]}"; do printf '  %s%s adapted:%s %s\n' "$C_YELLOW" "$S_WARN" "$C_RESET" "$n"; done
        hint "Run with sudo (or --sudo) to enable the full profile."
    fi
    if (( ${#NSE_MISSING[@]} )); then
        printf '  %s%s skipped (not installed):%s %s\n' "$C_YELLOW" "$S_WARN" "$C_RESET" "${NSE_MISSING[*]}"
    fi
    printf '\n  %scommand%s%s\n' "$C_GRAY" "$C_RESET" "$C_DIM$cmd_display$C_RESET"
}

# ---------- nmap execution with live rendering ----------

render_stream() {
    local progress=0
    (( UI_TTY && UI_COLOR )) && progress=1
    (( UI_TTY && ! UI_COLOR )) && progress=1
    awk -v color="$UI_COLOR" -v progress="$progress" -v accent="$C_ACCENT" \
        -v on="$S_BAR_ON" -v off="$S_BAR_OFF" -f "$LIB_DIR/render.awk"
}

# run_nmap BASENAME [extra nmap args...]   (uses NMAP_ARGS; adds output files)
run_nmap() {
    local base="$1"; shift
    local -a cmd=("$NMAP_BIN" "${NMAP_ARGS[@]}")
    (( UI_TTY )) && cmd+=(--stats-every 3s)
    cmd+=(-oN "$RUN_DIR/$base.txt" -oX "$RUN_DIR/$base.xml" -oG "$RUN_DIR/$base.gnmap" "$@")
    debug "exec: $(shell_quote "${cmd[@]}")"
    printf '%s\n' "$(shell_quote "${cmd[@]}")" | sed 's/^ //' >> "$RUN_DIR/command.txt"
    local rc=0
    set +e
    "${cmd[@]}" 2>&1 | render_stream
    rc=${PIPESTATUS[0]}
    set -e
    STAGE_FILES+=("$base")
    return "$rc"
}

# ---------- single scan ----------

run_scan() {
    validate_profile "$PROFILE"
    if [[ "$PROFILE" != custom ]] && profile_needs_target "$PROFILE" && [[ ${#TARGETS[@]} -eq 0 ]]; then
        die "No target given."
    fi
    if workflow_exists "$PROFILE"; then run_workflow; return; fi

    build_nmap_args "$PROFILE"
    prepare_run_dir

    local -a tgt=("${TARGETS[@]}")
    local cmd_display
    cmd_display="$(shell_quote "$NMAP_BIN" "${NMAP_ARGS[@]}" -oN nmap.txt -oX nmap.xml -oG nmap.gnmap "${tgt[@]}")"
    write_metadata "$cmd_display"
    show_plan "$cmd_display"
    preflight_checks || return 0

    START_EPOCH="$(date +%s)"
    step "Scanning"
    local rc=0
    run_nmap nmap "${tgt[@]}" || rc=$?
    if (( rc != 0 )); then
        error "Nmap exited with status $rc"
        post_process "nmap" || true
        fix_ownership
        return "$rc"
    fi
    post_process "nmap"
}

# Confirmations shared by single scans and workflows. Returns 1 to cancel.
preflight_checks() {
    local risk
    risk="$(profile_risk "$PROFILE" 2>/dev/null || echo safe)"
    if (( DRY_RUN )); then
        info "Dry run - nothing was executed."
        return 1
    fi
    if [[ "$risk" == intrusive ]]; then
        warn "Intrusive profile: NSE checks may generate noise, trigger IDS alerts, or disturb fragile services."
        confirm "Proceed with '$PROFILE' on $(target_display)?" || { info "Cancelled."; return 1; }
    fi
    if [[ "$PROFILE" == vulners ]]; then
        warn "The vulners script sends detected service versions to vulners.com."
        confirm "Allow that?" || { info "Cancelled."; return 1; }
    fi
    confirm "Run this scan?" || { info "Cancelled."; return 1; }
    return 0
}

# ---------- workflows ----------

stage_banner() { printf '\n%s%s Stage %s/%s%s  %s%s%s\n' "$C_ACCENT" "$S_STEP" "$1" "$2" "$C_RESET" "$C_BOLD" "$3" "$C_RESET"; }

run_workflow() {
    local wf="$PROFILE"
    prepare_run_dir
    local with_os=0
    [[ "$wf" == inventory ]] && with_os=1

    section "Workflow: $wf"
    printf '  %s1)%s discovery  ->  %s2)%s fast port scan of live hosts  ->  %s3)%s versions + scripts%s on open ports only\n' \
        "$C_ACCENT" "$C_RESET" "$C_ACCENT" "$C_RESET" "$C_ACCENT" "$C_RESET" "$( ((with_os)) && echo ' + OS + traceroute' )"
    kv "Target" "$(target_display)"
    kv "Output" "$RUN_DIR"
    write_metadata "workflow:$wf targets:${TARGETS[*]}"
    (( DRY_RUN )) && { info "Dry run - nothing was executed."; return 0; }
    confirm "Run this workflow?" || { info "Cancelled."; return 0; }
    START_EPOCH="$(date +%s)"

    # ---- stage 1: discovery
    stage_banner 1 3 "Host discovery"
    local sp="${PORTS:-}" st="${TOP_PORTS:-}"
    PORTS=""; TOP_PORTS=""
    build_nmap_args discovery
    PORTS="$sp"; TOP_PORTS="$st"
    (( ${#ADAPT_NOTES[@]} )) && printf '  %s%s%s\n' "$C_YELLOW" "${ADAPT_NOTES[*]}" "$C_RESET"
    run_nmap stage1-discovery "${TARGETS[@]}" || true
    extract_hosts "$RUN_DIR/stage1-discovery.xml" "$RUN_DIR/hosts-up.txt"
    local up; up=$(grep -c . "$RUN_DIR/hosts-up.txt" || true)
    if (( up == 0 )); then
        warn "No live hosts found. Hosts may block ping - try again with --no-ping (-Pn)."
        post_process "stage1-discovery" "$RUN_DIR/stage1-discovery.xml" || true
        return 0
    fi
    ok "$up live host(s)"

    # ---- stage 2: fast ports on live hosts
    stage_banner 2 3 "Fast port scan ($up hosts)"
    build_nmap_args quick
    NMAP_ARGS+=(-Pn -n)
    run_nmap stage2-ports -iL "$RUN_DIR/hosts-up.txt" || true

    local open_ports=""
    if have_py; then
        py_report ports "$RUN_DIR/stage2-ports.xml" > "$RUN_DIR/ports-open.txt" || true
        open_ports="$(tr -d '\n' < "$RUN_DIR/ports-open.txt")"
        py_report hosts-open "$RUN_DIR/stage2-ports.xml" > "$RUN_DIR/hosts-open.txt" || true
    else
        # shellcheck disable=SC2016
        open_ports="$(grep -oE 'Ports: .*' "$RUN_DIR/stage2-ports.gnmap" 2>/dev/null | grep -oE '[0-9]+/open' | cut -d/ -f1 | sort -un | paste -sd, - || true)"
        grep 'Ports:' "$RUN_DIR/stage2-ports.gnmap" 2>/dev/null | awk '/\/open\//{print $2}' > "$RUN_DIR/hosts-open.txt" || true
    fi
    if [[ -z "$open_ports" ]]; then
        warn "No open ports found on live hosts."
        post_process "stage2-ports" "$RUN_DIR/stage1-discovery.xml" "$RUN_DIR/stage2-ports.xml" || true
        return 0
    fi
    local nh; nh=$(grep -c . "$RUN_DIR/hosts-open.txt" || true)
    ok "${nh} host(s) with open ports: ${open_ports}"

    # ---- stage 3: deep dive on what actually exists
    stage_banner 3 3 "Service & script analysis on ports ${open_ports}"
    local save_ports="${PORTS:-}" save_top="${TOP_PORTS:-}"
    PORTS="$open_ports"; TOP_PORTS=""
    build_nmap_args default
    PORTS="$save_ports"; TOP_PORTS="$save_top"
    NMAP_ARGS+=(--script "$SCRIPTS_DIR/odoo-info.nse")
    if (( with_os )); then NMAP_ARGS+=(-O --traceroute --osscan-guess); adapt_args_for_privileges; fi
    NMAP_ARGS+=(-Pn -n)
    run_nmap nmap -iL "$RUN_DIR/hosts-open.txt" || true
    post_process "nmap" "$RUN_DIR/stage1-discovery.xml" "$RUN_DIR/stage2-ports.xml" "$RUN_DIR/nmap.xml"
}

# ---------- post-processing ----------

# extract_hosts XML OUT
extract_hosts() {
    local xml="$1" out="$2"
    : > "$out"
    [[ -f "$xml" ]] || return 0
    if have_py; then
        py_report hosts-up "$xml" | sort -V -u > "$out" || true
    else
        awk '
            /<host[ >]/ { up = 0; addr = "" }
            /<status state="up"/ { up = 1 }
            /<address addr="[^"]*" addrtype="ipv[46]"/ { match($0, /addr="[^"]*"/); addr = substr($0, RSTART + 6, RLENGTH - 7) }
            /<\/host>/ { if (up && addr != "") print addr }
        ' "$xml" | sort -V -u > "$out" || true
    fi
}

latency_report() {
    local hosts="$RUN_DIR/hosts-up.txt"
    [[ -s "$hosts" ]] || return 0
    command_exists ping || return 0
    (( ${PING_LATENCY:-1} )) || return 0
    local n; n=$(wc -l < "$hosts" | tr -d ' ')
    (( n <= 512 )) || { hint "Latency probe skipped ($n hosts > 512)."; return 0; }

    spin_start "Measuring latency to $n host(s)"
    xargs -d '\n' -P 24 -I{} bash -c '
        r=$(ping -n -c 1 -W 1 "$1" 2>/dev/null | sed -n "s/.*time[=<]\([0-9.]*\) *ms.*/\1/p" | head -1)
        printf "%s\t%s\n" "$1" "${r:-timeout}"' _ {} < "$hosts" 2>/dev/null | sort -V > "$RUN_DIR/host-latency.tsv" || true
    spin_stop

    {
        printf '%s\n' "Reachable Hosts"
        printf '%s\n' "==============="
        printf '%-40s %s\n' "HOST" "LATENCY"
        printf '%-40s %s\n' "----------------------------------------" "--------"
        awk -F'\t' '{ printf "%-40s %s\n", $1, ($2 == "timeout" ? "no reply" : $2 " ms") }' "$RUN_DIR/host-latency.tsv"
    } > "$RUN_DIR/host-latency.txt"
}

write_summary() {
    local duration=$(( $(date +%s) - START_EPOCH ))
    {
        printf '%s\n' "XamlTech Nmap Toolkit - Run Summary"
        printf '%s\n' "==================================="
        printf 'Target       : %s\n' "$(target_display)"
        printf 'Profile      : %s\n' "$PROFILE"
        printf 'Started      : %s\n' "$(awk -F': ' '/^Started/ {print $2}' "$RUN_DIR/metadata.txt")"
        printf 'Finished     : %s\n' "$(timestamp)"
        printf 'Duration     : %ss\n' "$duration"
        printf 'Nmap version : %s\n' "$(nmap_version)"
        printf 'Hosts up     : %s\n' "$(wc -l < "$RUN_DIR/hosts-up.txt" 2>/dev/null | tr -d ' ')"
        printf '\nOutput files:\n'
        find "$RUN_DIR" -maxdepth 1 -type f ! -name '.*' -printf '  %f\n' | sort
    } > "$RUN_DIR/summary.txt"
}

# post_process BASENAME [XML ...]
post_process() {
    local base="$1"; shift
    local -a xmls=("$@")
    [[ ${#xmls[@]} -gt 0 ]] || xmls=("$RUN_DIR/$base.xml")

    if [[ ! -s "${xmls[-1]}" ]]; then
        warn "No XML output produced - nothing to report."
        write_summary; fix_ownership; return 0
    fi
    if [[ ${#xmls[@]} -eq 1 ]]; then extract_hosts "${xmls[0]}" "$RUN_DIR/hosts-up.txt"; fi
    latency_report
    write_summary

    if have_py; then
        local lat=() fmt_args=(--formats "$REPORT_FORMATS")
        [[ -s "$RUN_DIR/host-latency.tsv" ]] && lat=(--latency "$RUN_DIR/host-latency.tsv")
        py_report report --outdir "$RUN_DIR" --meta "$RUN_DIR/metadata.json" "${fmt_args[@]}" "${lat[@]}" \
            --xml "${xmls[@]}" > /dev/null || warn "Report generation failed (see toolkit.log)."
        py_report dashboard "$RUN_DIR/report.json" --width "$(( UI_COLS > 100 ? 100 : UI_COLS ))" || true
        compare_with_previous
    else
        warn "python3 not found - skipping JSON/CSV/Markdown/HTML reports."
    fi

    local dur=$(( $(date +%s) - START_EPOCH ))
    printf '\n'
    ok "Completed in ${dur}s"
    kv "Results" "$RUN_DIR"
    if have_py && [[ "$REPORT_FORMATS" == *html* && -f "$RUN_DIR/report.html" ]]; then
        kv "HTML report" "$RUN_DIR/report.html" "$C_ACCENT"
    fi
    fix_ownership
    finish_hooks
}

compare_with_previous() {
    local label prev d
    label="_${PROFILE}_$(target_label)"
    prev=""
    while IFS= read -r d; do
        [[ "$d" == "$RUN_DIR" ]] && continue
        [[ -f "$d/report.json" ]] && prev="$d"
    done < <(find "$OUTPUT_DIR" -maxdepth 1 -type d -name "*${label}*" 2>/dev/null | sort)
    [[ -n "$prev" ]] || return 0
    # only compare against runs older than this one
    [[ "$(basename "$prev")" < "$(basename "$RUN_DIR")" ]] || return 0
    section "Changes since previous run"
    hint "baseline: $(basename "$prev")"
    py_report diff "$prev/report.json" "$RUN_DIR/report.json" || true
    python3 -I "$LIB_DIR/report.py" diff "$prev/report.json" "$RUN_DIR/report.json" > "$RUN_DIR/diff-vs-previous.txt" || true
}

finish_hooks() {
    (( ${NOTIFY:-0} )) || { (( ${OPEN_REPORT:-0} )) || return 0; }
    if (( ${NOTIFY:-0} )); then
        printf '\a'
        command_exists notify-send && notify-send "XamlTech Nmap Toolkit" "Scan finished: $(target_display)" 2>/dev/null || true
    fi
    if (( ${OPEN_REPORT:-0} )) && [[ -f "$RUN_DIR/report.html" ]]; then open_path "$RUN_DIR/report.html"; fi
}

open_path() {
    if command_exists xdg-open && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then xdg-open "$1" >/dev/null 2>&1 &
    elif command_exists open; then open "$1" >/dev/null 2>&1 &
    else hint "Open this file in your browser: $1"; fi
    return 0
}

# ---------- history / diff / reports of past runs ----------

resolve_run() {   # resolve_run NAME|PATH|latest -> directory
    local r="$1"
    [[ "$r" == latest ]] && r="$OUTPUT_DIR/latest"
    [[ -d "$r" ]] || r="$OUTPUT_DIR/$r"
    [[ -d "$r" ]] || return 1
    (cd "$r" && pwd -P)
}

show_history() {
    have_py || die "History view requires python3."
    [[ -d "$OUTPUT_DIR" ]] || { info "No results yet in $OUTPUT_DIR"; return 0; }
    py_report history "$OUTPUT_DIR" --width "$(( UI_COLS > 120 ? 120 : UI_COLS ))"
}

diff_runs() {
    have_py || die "Diff requires python3."
    local a b
    a="$(resolve_run "$1")" || die "Run not found: $1"
    b="$(resolve_run "$2")" || die "Run not found: $2"
    section "Diff: $(basename "$a")  ->  $(basename "$b")"
    py_report diff "$a/report.json" "$b/report.json"
}

open_report() {
    local d
    d="$(resolve_run "${1:-latest}")" || die "Run not found: ${1:-latest}"
    [[ -f "$d/report.html" ]] || die "No HTML report in $d"
    info "$d/report.html"
    open_path "$d/report.html"
}

export_run() {
    have_py || die "Export requires python3."
    local kind="$1" d
    d="$(resolve_run "$2")" || die "Run not found: $2"
    [[ -f "$d/report.json" ]] || die "No report.json in $d"
    python3 -I "$LIB_DIR/report.py" export "$kind" "$d"
}
