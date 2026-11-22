# shellcheck shell=bash
# XamlTech Nmap Toolkit - scan engine
# Run directories, single-profile scans, multi-stage workflows, live rendering,
# post-processing (inventory, latency, reports, diff against previous run).

RUN_DIR=""
START_EPOCH=0
STAGE_FILES=()
STAGE_SKIPPED=()
PREV_REPORT=""

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
    local stamp label base n=0 tmp_link
    [[ -L "$OUTPUT_DIR" ]] && die "Output directory is a symlink: $OUTPUT_DIR"
    stamp="$(safe_timestamp)"; label="$(target_label)"
    base="$OUTPUT_DIR/${stamp}_${PROFILE}_${label}"
    RUN_DIR="$base"
    if (( DRY_RUN )); then return 0; fi     # dry runs never touch the disk
    umask 077
    while [[ -e "$RUN_DIR" ]]; do n=$(( n + 1 )); RUN_DIR="${base}-$n"; done
    mkdir -p "$RUN_DIR"
    RUN_DIR="$(cd "$RUN_DIR" && pwd)"
    log_init
    tmp_link="$(mktemp -u "$OUTPUT_DIR/.latest.XXXXXX")"
    ln -s "$(basename "$RUN_DIR")" "$tmp_link" 2>/dev/null || true
    mv -Tf "$tmp_link" "$OUTPUT_DIR/latest" 2>/dev/null || ln -sfn "$(basename "$RUN_DIR")" "$OUTPUT_DIR/latest" 2>/dev/null || true
}

json_escape() { printf '%s' "$1" | tr '\n\r\t' '   ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

write_metadata() {
    local cmd_line="$1" skipped_json="" s
    (( DRY_RUN )) && return 0
    for s in "${STAGE_SKIPPED[@]}"; do skipped_json+="${skipped_json:+,}\"$s\""; done
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
  "command": "$(json_escape "$cmd_line")",
  "skipped_stages": [$skipped_json]
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

estimate_plan() {
    local stages=1
    command_exists python3 || { warn "python3 is required for --estimate."; return 0; }
    workflow_exists "$PROFILE" && stages=3
    python3 - "$OUTPUT_DIR" "$stages" "$PROFILE" "${TARGETS[@]}" <<'PY'
import datetime as dt
import ipaddress
import json
import os
import sys

root, stages, profile, *targets = sys.argv[1:]
hosts = 0
for target in targets:
    try:
        hosts += ipaddress.ip_network(target, strict=False).num_addresses
    except ValueError:
        hosts += 1
durations = []
if os.path.isdir(root):
    for name in sorted(os.listdir(root), reverse=True):
        run = os.path.join(root, name)
        meta_path = os.path.join(run, "metadata.json")
        report_path = os.path.join(run, "report.json")
        if not (os.path.isfile(meta_path) and os.path.isfile(report_path)):
            continue
        try:
            with open(meta_path, encoding="utf-8") as fh:
                start = float(json.load(fh)["started_epoch"])
            with open(report_path, encoding="utf-8") as fh:
                end = dt.datetime.fromisoformat(
                    json.load(fh)["generated"].replace("Z", "+00:00")
                ).timestamp()
            if end > start:
                durations.append(end - start)
        except (KeyError, ValueError, TypeError, OSError):
            continue
        if len(durations) >= 5:
            break
average = sum(durations) / len(durations) if durations else None
print(f"Profile         : {profile}")
print(f"Targets         : {len(targets)} token(s), about {hosts} address(es)")
print(f"Workflow stages : {stages}")
if average is None:
    print("Prior duration  : no comparable run yet")
else:
    print(f"Prior duration  : about {average:.0f}s (last {len(durations)} run(s))")
PY
}

incremental_require() {
    [[ -z "$INCREMENTAL_BASELINE" ]] && return 1
    command_exists python3 || die "python3 is required for --incremental."
    return 0
}

incremental_filter_targets() {
    incremental_require || return 0
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "${TARGETS[@]}" > "$tmp"
    mapfile -t TARGETS < <(python3 - "$tmp" "$INCREMENTAL_BASELINE" <<'PY'
import json, sys
known = {h.get("address") for h in json.load(open(sys.argv[2], encoding="utf-8")).get("hosts", [])}
for line in open(sys.argv[1], encoding="utf-8"):
    target = line.strip()
    if target and target not in known:
        print(target)
PY
    )
    rm -f "$tmp"
}

incremental_filter_hosts_file() {
    incremental_require || return 0
    local file="$1" tmp
    tmp="$(mktemp)"
    python3 - "$file" "$INCREMENTAL_BASELINE" > "$tmp" <<'PY'
import json, sys
known = {h.get("address") for h in json.load(open(sys.argv[2], encoding="utf-8")).get("hosts", [])}
for line in open(sys.argv[1], encoding="utf-8"):
    host = line.strip()
    if host and host not in known:
        print(host)
PY
    mv -f "$tmp" "$file"
    chmod 600 "$file"
}

incremental_filter_ports_file() {
    incremental_require || return 0
    local file="$1" tmp
    tmp="$(mktemp)"
    python3 - "$file" "$INCREMENTAL_BASELINE" > "$tmp" <<'PY'
import json, sys
report = json.load(open(sys.argv[2], encoding="utf-8"))
known = set()
for host in report.get("hosts", []):
    for port in host.get("ports", []):
        if port.get("state") == "open":
            known.add(str(port.get("port")))
raw = open(sys.argv[1], encoding="utf-8").read().strip()
ports = [p.strip() for p in raw.split(",") if p.strip()]
print(",".join(p for p in ports if p not in known))
PY
    mv -f "$tmp" "$file"
    chmod 600 "$file"
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

explain_plan() {
    printf '\n%s%sEXPLANATION%s\n' "${C_ACCENT:-}" "${C_BOLD:-}" "${C_RESET:-}"
    printf '  profile origin:      %s\n' "${PROFILE:-<none>}"
    printf '  profile risk:        %s\n' "$(profile_risk "${PROFILE:-standard}" 2>/dev/null || echo safe)"
    if (( ${#OVERRIDE_TRACE[@]} )); then
        local line
        for line in "${OVERRIDE_TRACE[@]}"; do printf '  override:            %s\n' "$line"; done
    else
        printf '  override:            none\n'
    fi
    if (( ${#ADAPT_NOTES[@]} )); then
        for line in "${ADAPT_NOTES[@]}"; do printf '  privilege adaptation: %s\n' "$line"; done
    else
        printf '  privilege adaptation: none\n'
    fi
    if (( ${#NSE_MISSING[@]} )); then
        for line in "${NSE_MISSING[@]}"; do printf '  skipped NSE:         %s (not installed)\n' "$line"; done
    else
        printf '  skipped NSE:         none\n'
    fi
    printf '  policy:              %s%s\n' "${POLICY:-strict}" "$([[ ${ACK_RISK:-0} -eq 1 ]] && echo ' (ack-risk)')"
}

run_scan() {
    validate_profile "$PROFILE"
    if [[ "$PROFILE" != custom ]] && profile_needs_target "$PROFILE" && [[ ${#TARGETS[@]} -eq 0 ]]; then
        die "No target given."
    fi
    if workflow_exists "$PROFILE"; then run_workflow; return; fi

    incremental_filter_targets
    if (( ${#TARGETS[@]} == 0 )); then
        info "All targets are already present in the baseline; nothing to scan."
        return 0
    fi
    build_nmap_args "$PROFILE"
    prepare_run_dir

    local -a tgt=("${TARGETS[@]}")
    local cmd_display
    cmd_display="$(shell_quote "$NMAP_BIN" "${NMAP_ARGS[@]}" -oN nmap.txt -oX nmap.xml -oG nmap.gnmap "${tgt[@]}")"
    write_metadata "$cmd_display"
    show_plan "$cmd_display"
    (( EXPLAIN )) && explain_plan
    preflight_checks || return 0

    START_EPOCH="$(date +%s)"
    step "Scanning"
    local rc=0
    run_nmap nmap "${tgt[@]}" || rc=$?
    if (( rc != 0 )); then
        error "Nmap exited with status $rc"
        post_process "nmap" || true
        audit_log "$rc" "$cmd_display" "${PLAN_HASH:-}"
        fix_ownership
        return "$rc"
    fi
    post_process "nmap"
    audit_log 0 "$cmd_display" "${PLAN_HASH:-}"
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

stage_done() {
    (( DRY_RUN )) && return 0
    local files=() checksum=""
    for files in "$RUN_DIR/stage-$1-$2.xml" "$RUN_DIR/stage-$1-$2.gnmap" "$RUN_DIR/nmap.xml"; do
        [[ -f "$files" ]] || continue
        checksum+="$(sha256sum "$files" 2>/dev/null | cut -d' ' -f1) "
    done
    printf '%s %s %s\n' "$(date +%s)" "$2" "${checksum:-none}" > "$RUN_DIR/stage-$1-$2.done"
}

stage_condition_met() {
    local when="$1" ports_open="$2" count="$3" wanted p op n
    local IFS=' '
    [[ -z "$when" ]] && return 0
    if [[ "$when" == port\ in\ * ]]; then
        wanted="${when#port in }"
        local IFS=','
        for p in $wanted; do
            [[ ",${ports_open// /}," == *",$p,"* ]] && return 0
        done
        return 1
    fi
    read -r op n <<< "${when#host_count }"
    case "$op" in
        ">") (( count > n )) ;;
        "=") (( count == n )) ;;
        *)   return 1 ;;
    esac
}

stage_should_abort() {
    local rc="$1" on_fail="$2"
    (( rc != 0 )) && [[ "$on_fail" == abort ]]
}

stage_marker_valid() {
    local idx="$1" name="$2" marker label checksum actual="" f
    local IFS=' '
    marker="$RUN_DIR/stage-$idx-$name.done"
    [[ -f "$marker" ]] || return 1
    read -r _ label checksum < "$marker"
    checksum="$(printf '%s' "$checksum" | tr -s ' ' | sed 's/ $//')"
    for f in "$RUN_DIR/stage-$idx-$name.xml" "$RUN_DIR/stage-$idx-$name.gnmap" "$RUN_DIR/nmap.xml"; do
        [[ -f "$f" ]] || continue
        actual+="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1) "
    done
    actual="$(printf '%s' "$actual" | tr -s ' ' | sed 's/ $//')"
    [[ -n "$actual" && "$checksum" == "$actual" ]]
}

run_workflow() {
    local wf="$PROFILE"
    if [[ -n "${RESUME_DIR:-}" ]]; then
        [[ -d "$RESUME_DIR" ]] || die "Resume directory not found: $RESUME_DIR"
        umask 077
        RUN_DIR="$(cd "$RESUME_DIR" && pwd)"
        log_init
        info "Resuming workflow from $RUN_DIR"
    else
        prepare_run_dir
    fi
    local -a rows=()
    mapfile -t rows < <(stages_for_pipeline "$wf")
    (( ${#rows[@]} )) || die "No stage records for workflow: $wf"
    local total=${#rows[@]} row idx name wf_profile targets when stage_ports stage_scripts timeout on_fail
    local cmd_display="workflow:$wf targets:${TARGETS[*]}"
    local with_os=0
    [[ "$wf" == inventory ]] && with_os=1

    section "Workflow: $wf"
    printf '  %s%s%s stage(s) declared for %s%s\n' "$C_ACCENT" "$total" "$C_RESET" "$wf" \
        "$( ((with_os)) && echo ' (OS + traceroute enabled)' )"
    for row in "${rows[@]}"; do
        idx="$(stage_field "$row" 2)"; name="$(stage_field "$row" 3)"
        wf_profile="$(stage_field "$row" 4)"; targets="$(stage_field "$row" 5)"
        when="$(stage_field "$row" 6)"
        printf '    %s.%s %-10s %-10s %-11s %s\n' "$idx" "$C_RESET" "$name" "$wf_profile" "$targets" \
            "${when:-always}"
    done
    kv "Target" "$(target_display)"
    kv "Output" "$RUN_DIR"
    write_metadata "$cmd_display"
    (( DRY_RUN )) && { info "Dry run - nothing was executed."; return 0; }
    confirm "Run this workflow?" || { info "Cancelled."; return 0; }
    START_EPOCH="$(date +%s)"
    STAGE_SKIPPED=()

    local open_ports="" up=0 current_count=0 rc=0 base
    local -a tgt=() xmls=()
    for row in "${rows[@]}"; do
        idx="$(stage_field "$row" 2)"; name="$(stage_field "$row" 3)"
        wf_profile="$(stage_field "$row" 4)"; targets="$(stage_field "$row" 5)"
        when="$(stage_field "$row" 6)"; stage_ports="$(stage_field "$row" 7)"
        stage_scripts="$(stage_field "$row" 8)"; timeout="$(stage_field "$row" 9)"
        on_fail="$(stage_field "$row" 10)"
        debug "stage $name timeout=$timeout on_fail=$on_fail"
        if [[ -n "${STAGE:-}" && "$STAGE" != "$name" ]]; then
            STAGE_SKIPPED+=("$name")
            info "Skipping stage $name (--stage ${STAGE})."
            continue
        fi
        case "$targets" in
            original)
                tgt=("${TARGETS[@]}"); current_count=${#TARGETS[@]} ;;
            hosts-up)
                [[ -s "$RUN_DIR/hosts-up.txt" ]] || die "Stage artifact hosts-up.txt is missing; run discovery first."
                tgt=(-iL "$RUN_DIR/hosts-up.txt")
                current_count=$(grep -c . "$RUN_DIR/hosts-up.txt" || true)
                up="$current_count" ;;
            hosts-open)
                [[ -s "$RUN_DIR/hosts-open.txt" ]] || die "Stage artifact hosts-open.txt is missing; run ports first."
                tgt=(-iL "$RUN_DIR/hosts-open.txt")
                current_count=$(grep -c . "$RUN_DIR/hosts-open.txt" || true)
                open_ports="$(tr -d '\n' < "$RUN_DIR/ports-open.txt" 2>/dev/null || true)" ;;
        esac
        if ! stage_condition_met "$when" "$open_ports" "$current_count"; then
            STAGE_SKIPPED+=("$name")
            info "Skipping stage $name (condition: $when)."
            continue
        fi
        if [[ -n "${RESUME_DIR:-}" ]] && stage_marker_valid "$idx" "$name"; then
            info "Stage $name already complete; using existing artifacts."
            [[ "$name" == discovery ]] && up=$(grep -c . "$RUN_DIR/hosts-up.txt" || true)
            [[ "$name" == ports ]] && open_ports="$(tr -d '\n' < "$RUN_DIR/ports-open.txt" 2>/dev/null || true)"
            continue
        fi
        stage_banner "$idx" "$total" "$name"
        local save_ports="${PORTS:-}" save_top="${TOP_PORTS:-}"
        case "$name" in
            discovery) PORTS=""; TOP_PORTS="" ;;
            ports)     [[ -z "$stage_ports" ]] || PORTS="$stage_ports" ;;
            services)  PORTS="$open_ports"; TOP_PORTS="" ;;
        esac
        build_nmap_args "$wf_profile"
        PORTS="$save_ports"; TOP_PORTS="$save_top"
        [[ -z "$stage_scripts" ]] || NMAP_ARGS+=(--script "$stage_scripts")
        [[ "$name" == services ]] && NMAP_ARGS+=(--script "$SCRIPTS_DIR/odoo-info.nse")
        if (( with_os )) && [[ "$name" == services ]]; then
            NMAP_ARGS+=(-O --traceroute --osscan-guess)
            adapt_args_for_privileges
        fi
        [[ "$name" == discovery ]] || NMAP_ARGS+=(-Pn -n)
        base="stage$idx-$name"
        [[ "$name" == services ]] && base=nmap
        rc=0
        run_nmap "$base" "${tgt[@]}" || rc=$?
        if stage_should_abort "$rc" "$on_fail"; then
            audit_log "$rc" "$cmd_display" "${PLAN_HASH:-}"
            die "Stage $name failed with status $rc"
        fi
        (( rc != 0 )) && warn "Stage $name failed (on_fail=continue)."
        case "$name" in
            discovery)
                extract_hosts "$RUN_DIR/$base.xml" "$RUN_DIR/hosts-up.txt"
                incremental_filter_hosts_file "$RUN_DIR/hosts-up.txt"
                up=$(grep -c . "$RUN_DIR/hosts-up.txt" || true)
                (( up > 0 )) || warn "No live hosts found. Hosts may block ping - try again with --no-ping (-Pn)."
                ok "$up live host(s)" ;;
            ports)
                if have_py; then
                    py_report ports "$RUN_DIR/$base.xml" > "$RUN_DIR/ports-open.txt" || true
                    py_report hosts-open "$RUN_DIR/$base.xml" > "$RUN_DIR/hosts-open.txt" || true
                else
                    open_ports="$(grep -oE 'Ports: .*' "$RUN_DIR/$base.gnmap" 2>/dev/null | grep -oE '[0-9]+/open' | cut -d/ -f1 | sort -un | paste -sd, - || true)"
                    printf '%s' "$open_ports" > "$RUN_DIR/ports-open.txt"
                    grep 'Ports:' "$RUN_DIR/$base.gnmap" 2>/dev/null | awk '/\/open\//{print $2}' > "$RUN_DIR/hosts-open.txt" || true
                fi
                incremental_filter_ports_file "$RUN_DIR/ports-open.txt"
                incremental_filter_hosts_file "$RUN_DIR/hosts-open.txt"
                open_ports="$(tr -d '\n' < "$RUN_DIR/ports-open.txt" 2>/dev/null || true)"
                if [[ -z "$open_ports" ]]; then
                    warn "No open ports found on live hosts."
                else
                    ok "$(grep -c . "$RUN_DIR/hosts-open.txt" || true) host(s) with open ports: $open_ports"
                fi ;;
        esac
        stage_done "$idx" "$name"
        [[ "$name" == discovery && $up -eq 0 ]] && break
        [[ "$name" == ports && -z "$open_ports" ]] && break
    done
    xmls=()
    for idx in "${STAGE_FILES[@]}"; do
        [[ -f "$RUN_DIR/$idx.xml" ]] && xmls+=("$RUN_DIR/$idx.xml")
    done
    (( ${#xmls[@]} )) && post_process nmap "${xmls[@]}"
    write_metadata "$cmd_display"
    audit_log 0 "$cmd_display" "${PLAN_HASH:-}"
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
        local lat=() fmt_args=(--formats "$REPORT_FORMATS") diff_args=()
        find_previous_report
        [[ -n "$PREV_REPORT" ]] && diff_args=(--diff-report "$PREV_REPORT")
        [[ -s "$RUN_DIR/host-latency.tsv" ]] && lat=(--latency "$RUN_DIR/host-latency.tsv")
        py_report report --outdir "$RUN_DIR" --meta "$RUN_DIR/metadata.json" "${fmt_args[@]}" "${lat[@]}" \
            "${diff_args[@]}" --xml "${xmls[@]}" > /dev/null || warn "Report generation failed (see toolkit.log)."
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

find_previous_report() {
    local label d
    PREV_REPORT=""
    label="_${PROFILE}_$(target_label)"
    while IFS= read -r d; do
        [[ "$d" == "$RUN_DIR" ]] && continue
        [[ -f "$d/report.json" ]] || continue
        [[ "$(basename "$d")" < "$(basename "$RUN_DIR")" ]] || continue
        PREV_REPORT="$d/report.json"
    done < <(find "$OUTPUT_DIR" -maxdepth 1 -type d -name "*${label}*" 2>/dev/null | sort)
}

compare_with_previous() {
    [[ -n "$PREV_REPORT" ]] || find_previous_report
    [[ -n "$PREV_REPORT" ]] || return 0
    section "Changes since previous run"
    hint "baseline: $(basename "$(dirname "$PREV_REPORT")")"
    py_report diff "$PREV_REPORT" "$RUN_DIR/report.json" || true
    python3 -I "$LIB_DIR/report.py" diff "$PREV_REPORT" "$RUN_DIR/report.json" > "$RUN_DIR/diff-vs-previous.txt" || true
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
