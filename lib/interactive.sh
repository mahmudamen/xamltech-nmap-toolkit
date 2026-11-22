# shellcheck shell=bash
# XamlTech Nmap Toolkit - interactive mode (arrow-key menus)

# Run a function in an isolated subshell so die() inside it returns to the menu
# instead of ending the whole session.
run_isolated() {
    set +e
    ( set -e; "$@" )
    set -e
    return 0
}

pause() {
    [[ -t 0 ]] || return 0
    printf '\n%sPress Enter to return to the menu...%s' "$C_GRAY" "$C_RESET"
    read -r _ || true
}

# ---------- target selection ----------

detect_networks() {   # prints "cidr|iface|ip"
    command_exists ip || return 0
    ip -o -4 addr show scope global 2>/dev/null | awk '{print $2 "|" $4}' | while IFS='|' read -r iface cidr; do
        if command_exists python3; then
            python3 -I -c 'import ipaddress,sys; i=ipaddress.ip_interface(sys.argv[1]); print(f"{i.network}|{sys.argv[2]}|{i.ip}")' "$cidr" "$iface" 2>/dev/null || true
        else
            printf '%s|%s|%s\n' "$cidr" "$iface" "${cidr%%/*}"
        fi
    done
}

choose_target() {
    local -a items=() nets=()
    local line cidr iface ip
    while IFS= read -r line; do
        [[ -n "$line" ]] && nets+=("$line")
    done < <(detect_networks)
    for line in "${nets[@]}"; do
        IFS='|' read -r cidr iface ip <<< "$line"
        items+=("$cidr|$cidr|${iface} (this machine: $ip)")
    done
    items+=("127.0.0.1|localhost|Scan this machine only")
    items+=("__manual__|Enter manually|IP, hostname, CIDR, range or several separated by spaces")
    items+=("__file__|From file|One target per line")

    ui_menu "Select target" "${items[@]}" || return 1
    case "$MENU_REPLY" in
        __manual__)
            hint "Examples: 192.168.1.10   192.168.1.0/24   192.168.1.1-254   router.local   10.0.0.5 10.0.0.9"
            ask "Target(s)" ""
            set_targets "$REPLY" ;;
        __file__)
            ask "Path to target file" ""
            TARGETS=(); load_targets_file "$REPLY" ;;
        *) TARGETS=("$MENU_REPLY") ;;
    esac
}

# ---------- profile selection ----------

choose_profile() {
    local filter="${1:-}"   # optional comma separated category filter
    local -a items=()
    local row name cat risk desc
    for row in "${PROFILE_TABLE[@]}"; do
        IFS='|' read -r name cat risk _ _ desc <<< "$row"
        if [[ -n "$filter" && ",$filter," != *",$cat,"* ]]; then continue; fi
        [[ "$name" == broadcast ]] && continue
        items+=("$name|$name [$risk]|$desc")
    done
    ui_menu "Select profile" "${items[@]}" || return 1
    PROFILE="$MENU_REPLY"
}

choose_timing() {
    ui_menu "Timing / speed" \
        "|Profile default|Use the profile's own timing" \
        "2|2 - Polite|Slower, lower load on the network" \
        "3|3 - Normal|Nmap default" \
        "4|4 - Aggressive|Fast on reliable LANs" \
        "5|5 - Insane|Very fast, may miss results" || return 0
    TIMING="$MENU_REPLY"
}

advanced_options() {
    choose_timing
    ask "Ports (e.g. 22,80,443 or empty for profile default)" ""; PORTS="$REPLY"
    ask "Exclude hosts (empty for none)" ""; EXCLUDE="$REPLY"
    ask "Extra NSE scripts, comma separated (empty for none)" ""; EXTRA_SCRIPTS="$REPLY"
    if confirm "Treat hosts as up (skip ping, -Pn)?"; then NO_PING=1; fi
}

apply_registry_option() {
    local canon="$1" value="$2" var current
    option_validate "$canon" "$value" || return 1
    opt_store_override "$canon" "$value"
    var="${OPTION_CONFIG_MAP[$canon]:-}"
    [[ -n "$var" ]] || return 0
    current="${!var:-}"
    case "$var" in
        PING_LATENCY) PING_LATENCY=$([[ "$value" == 0 ]] && echo 0 || echo 1) ;;
        OPEN_REPORT|NOTIFY) printf -v "$var" '%s' "$([[ "$value" == 0 ]] && echo 0 || echo 1)" ;;
        *) printf -v "$var" '%s' "$value" ;;
    esac
}

registry_current_value() {
    local canon="$1" var="${OPTION_CONFIG_MAP[$1]:-}"
    if [[ -n "$var" ]]; then printf '%s' "${!var:-}"; else printf '%s' "${OVERRIDE_VALUES[$canon]:-}"; fi
}

advanced_options_menu() {
    local -a cats=() recs=() opts=()
    local row cat title desc rec canon vkind current
    while IFS='|' read -r cat title desc; do
        cats+=("$cat|$title|$desc")
    done < <(options_emit_categories)
    ui_menu "Advanced option categories" "${cats[@]}" || return 0
    cat="$MENU_REPLY"
    mapfile -t recs < <(options_in_category "$cat")
    for rec in "${recs[@]}"; do
        _option_parse "$rec"
        canon="${OPT_FLAG%%,*}"
        vkind="${OPT_VALUE:-none}"
        current="$(registry_current_value "$canon")"
        opts+=("$canon|${OPT_FLAG}|${OPT_DESC}${current:+ (now: $current)}")
    done
    ui_menu "Registry options: ${OPTION_CATEGORY_TITLE[$cat]}" "${opts[@]}" || return 0
    canon="$MENU_REPLY"
    vkind="$(option_lookup "$canon" value)"
    if [[ "$vkind" == none ]]; then
        apply_registry_option "$canon" 1
        ok "Enabled $canon"
    else
        current="$(registry_current_value "$canon")"
        ask "$canon value" "${current:-$(option_lookup "$canon" default)}"
        apply_registry_option "$canon" "$REPLY" && ok "Set $canon=$REPLY"
    fi
}

# ---------- flows ----------

authorization_notice() {
    section "Authorization notice"
    warn "Scan only hosts and networks you own or are explicitly authorized to test."
    confirm "I understand and want to continue." || { info "Cancelled."; return 1; }
}

guided_scan() {
    local mode="${1:-scan}"
    TARGETS=(); PROFILE=""; TIMING=""; PORTS=""; EXCLUDE=""; EXTRA_SCRIPTS=""; NO_PING=0
    choose_target || return 0
    case "$mode" in
        recon)
            ui_menu "Pipeline" \
                "recon|Recon|discover -> fast ports -> versions & scripts on open ports" \
                "inventory|Inventory|Recon + OS detection + traceroute" || return 0
            PROFILE="$MENU_REPLY" ;;
        nse)  choose_profile "Scripts,Services,XamlTech,Audit" || return 0 ;;
        *)    choose_profile || return 0 ;;
    esac
    if confirm "Configure advanced options (timing, ports, exclusions, scripts)?"; then
        ASSUME_YES_SAVE=$ASSUME_YES; ASSUME_YES=0
        advanced_options
        ASSUME_YES=$ASSUME_YES_SAVE
    fi
    authorization_notice || return 0
    enforce_scope
    authorization_gate || return 0
    if [[ "$(profile_root "$PROFILE" 2>/dev/null || echo no)" == yes ]] && (( ! NMAP_PRIVILEGED )); then
        warn "Profile '$PROFILE' works best with raw sockets; it will adapt to TCP-connect mode."
        hint "For the full profile, quit and start with:  sudo $(basename "$SCRIPT_PATH")   (or add --sudo)"
    fi
    run_scan
}

history_menu() {
    show_history
    local -a items=() runs=()
    local d
    while IFS= read -r d; do runs+=("$d"); done < <(find "$OUTPUT_DIR" -maxdepth 1 -mindepth 1 -type d ! -name latest -printf '%f\n' 2>/dev/null | sort -r | head -12)
    (( ${#runs[@]} )) || return 0
    ui_menu "History actions" \
        "open|Open an HTML report|Pick a run" \
        "diff|Compare two runs|Pick baseline and current" \
        "back|Back" || return 0
    case "$MENU_REPLY" in
        open)
            for d in "${runs[@]}"; do items+=("$d|$d|"); done
            ui_menu "Open report" "${items[@]}" || return 0
            open_report "$MENU_REPLY" ;;
        diff)
            for d in "${runs[@]}"; do items+=("$d|$d|"); done
            ui_menu "Baseline (older run)" "${items[@]}" || return 0
            local a="$MENU_REPLY"
            ui_menu "Current (newer run)" "${items[@]}" || return 0
            diff_runs "$a" "$MENU_REPLY" ;;
    esac
}

tools_menu() {
    ui_menu "Tools" \
        "doctor|Environment doctor|Check Nmap, Python, privileges, terminal" \
        "updates|Nmap update check|Installed vs available version" \
        "scripts|Browse NSE scripts|Search by name or category" \
        "help|NSE script help|Read a script's documentation" \
        "back|Back" || return 0
    case "$MENU_REPLY" in
        doctor)  doctor ;;
        updates) confirm "Also query nmap.org?" && ONLINE_CHECK=1; check_updates ;;
        scripts) ask "Filter (name or category, empty = all)" ""; nse_list "$REPLY" ;;
        help)    ask "Script name" ""; [[ -n "$REPLY" ]] && nse_help "$REPLY" ;;
    esac
}

save_settings() {
    local dir="${XDG_CONFIG_HOME:-$HOME/.config}/xamltech-nmap-toolkit"
    mkdir -p "$dir"
    {
        printf '# XamlTech Nmap Toolkit settings (written %s)\n' "$(timestamp)"
        printf 'THEME=%s\nOUTPUT_DIR=%s\nREPORT_FORMATS=%s\nPING_LATENCY=%s\nOPEN_REPORT=%s\nNOTIFY=%s\n' \
            "$THEME_NAME" "$OUTPUT_DIR" "$REPORT_FORMATS" "$PING_LATENCY" "$OPEN_REPORT" "$NOTIFY"
        [[ -n "$TIMING" ]] && printf 'TIMING=%s\n' "$TIMING"
        [[ -n "$SCOPE_FILE" ]] && printf 'SCOPE_FILE=%s\n' "$SCOPE_FILE"
    } > "$dir/config"
    ok "Saved to $dir/config"
}

settings_menu() {
    while :; do
        ui_menu "Settings   (theme: $THEME_NAME, formats: $REPORT_FORMATS, open report: $OPEN_REPORT)" \
            "theme|Theme|Change colors and headline gradient" \
            "formats|Report formats|Choose which reports are generated" \
            "open|Auto-open HTML report|Toggle" \
            "output|Output directory|Currently $OUTPUT_DIR" \
            "save|Save settings|Write ~/.config/xamltech-nmap-toolkit/config" \
            "back|Back" || return 0
        case "$MENU_REPLY" in
            theme)
                local -a ths=() t
                while IFS= read -r t; do ths+=("$t|$t|"); done < <(ui_themes)
                ui_menu "Theme" "${ths[@]}" && { ui_theme "$MENU_REPLY"; ui_define_colors; THEME="$MENU_REPLY"; banner; } ;;
            formats)
                ui_menu "Report formats" \
                    "json,csv,md,html|All|JSON + CSV + Markdown + HTML" \
                    "json,html|JSON + HTML|Machine and human friendly" \
                    "json|JSON only|Minimal (needed for diff/history)" && REPORT_FORMATS="$MENU_REPLY" ;;
            open)    OPEN_REPORT=$(( 1 - OPEN_REPORT )); ok "Auto-open: $OPEN_REPORT" ;;
            output)  ask "Output directory" "$OUTPUT_DIR"; OUTPUT_DIR="$REPLY"; mkdir -p "$OUTPUT_DIR" ;;
            save)    save_settings ;;
            back)    return 0 ;;
        esac
    done
}

# ---------- main menu ----------

interactive_mode() {
    banner
    env_line
    printf '\n'
    while :; do
        ui_menu "What would you like to do?" \
            "scan|Guided scan|Pick a target and any of the 30+ profiles" \
            "recon|Smart recon|Pipeline: discover -> ports -> services & scripts" \
            "nse|NSE script packs|Web, TLS, SSH, SMB, DB, mail, Odoo, POS, IoT, audit" \
            "advanced|Advanced options|Registry categories: targets, tuning, NSE, Nmap, safety" \
            "profiles|Browse profiles|Risk, privileges and speed for every profile" \
            "history|History & reports|Past runs, compare, open HTML reports" \
            "tools|Tools|Doctor, updates, NSE script browser" \
            "settings|Settings|Theme, report formats, output directory" \
            "quit|Quit" || break
        case "$MENU_REPLY" in
            scan)     run_isolated guided_scan scan;  pause ;;
            recon)    run_isolated guided_scan recon; pause ;;
            nse)      run_isolated guided_scan nse;   pause ;;
            advanced) run_isolated advanced_options_menu; pause ;;
            profiles) list_profiles; pause ;;
            history)  run_isolated history_menu; pause ;;
            tools)    run_isolated tools_menu; pause ;;
            settings) settings_menu ;;
            quit)     break ;;
        esac
        printf '\n'
    done
    printf '\n%sThanks for using XamlTech Nmap Toolkit.%s\n' "$C_GRAY" "$C_RESET"
}
