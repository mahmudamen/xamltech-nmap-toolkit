# shellcheck shell=bash
# XamlTech Nmap Toolkit - option registry
# Single source of truth for flags, validation, help, completion and config keys.
# Record: FLAG|VALUE|VALIDATOR|NMAP_TEMPLATE|RISK|ROOT|CATEGORY|DEFAULT|DESCRIPTION
# Aliases are comma separated with the long form first.

OPTION_TABLE=(
'--target,-t|csv|v_hostspec||safe|no|target||Host, hostname, CIDR or range; repeatable'
'--target-file,-L|str|v_path||safe|no|target||Read targets from file (one per line)'
'--exclude|csv|v_hostspec||safe|no|target||Exclude hosts or networks'
'--scope|str|v_path||safe|no|target||Authorized scope file; refuse targets outside it'
'--stage|str|v_name||safe|no|tool||Run one workflow stage (discovery|ports|services)'
'--resume|str|v_path||safe|no|tool||Resume a workflow from an existing run directory'
'--incremental|str|v_path||safe|no|tool||Scan only hosts/ports absent from a baseline report'
'--target-group|str|v_storage_name||safe|no|target||Expand a named target group'
'--save-preset|str|v_storage_name||safe|no|tool||Save current options as a named JSON preset'
'--preset|str|v_storage_name||safe|no|tool||Load options from a named JSON preset'
'--replay|str|v_count||safe|no|tool||Replay a numbered command from history'
'--project|str|v_storage_name||safe|no|tool||Associate this scan with a project'
'--project-create|str|v_storage_name||safe|no|tool||Create a named project'
'--project-info|str|v_optional||safe|no|tool||Description for a new project'
'--project-goals|str|v_optional||safe|no|tool||Comma separated goals for a new project'
'--project-list|none|||safe|no|tool||List projects with their status'
'--project-show|str|v_storage_name||safe|no|tool||Show project plan, timeline and next action'
'--project-step-add|str|v_storage_name||safe|no|tool||Add an ordered step to a project'
'--project-step|str|v_storage_name||safe|no|tool||Step id for --project-step-add'
'--goal|str|v_optional||safe|no|tool||Goal text for --project-step-add'
'--project-args|str|v_optional||safe|no|tool||Saved toolkit arguments for the step'
'--project-step-status|str|v_optional||safe|no|tool||Set step status: NAME STEP=STATUS'
'--note|str|v_optional||safe|no|tool||Note for --project-step-status'
'--project-resume|str|v_storage_name||safe|no|tool||Resume the next project step and its saved arguments'
'--estimate|none|||safe|no|tool||Estimate hosts, stages and duration'
'--profile,-p|str|v_profile||safe|no|profile||Scan profile name'
'--args,-a|str|v_args||moderate|no|profile||Quote-aware arguments for the custom profile'
'--timing,-T|str|v_timing|-T%v|safe|no|tuning||Nmap timing template 0-5'
'--ports|str|v_ports|-p%v|safe|no|tuning||Port specification, e.g. 22,80,443 or T:22,U:53'
'--top-ports|int|v_count|--top-ports %v|safe|no|tuning||Scan the N most common ports'
'--max-rate|int|v_rate|--max-rate %v|safe|no|tuning||Maximum packets per second'
'--max-retries|int|v_count|--max-retries %v|safe|no|tuning||Probe retransmissions'
'--host-timeout|str|v_duration|--host-timeout %v|safe|no|tuning||Give up on slow hosts'
'--dns-servers|csv|v_dns|--dns-servers %v|safe|no|tuning||Custom resolvers'
'--interface,-e|str|v_iface|-e %v|safe|no|tuning||Network interface'
'--scripts|csv|v_script|--script %v|safe|no|nse||Extra NSE scripts (validated)'
'--script-args|str|v_args|--script-args %v|moderate|no|nse||NSE script arguments'
'--output,-o|str|v_path||safe|no|output|./results|Result directory'
'--formats|csv|v_formats||safe|no|output|json,csv,md,html|Report formats'
'--theme|str|v_theme||safe|no|output|cyber|Color theme'
'--no-latency|none|||safe|no|output||Skip the parallel ping latency table'
'--open|none|||safe|no|output||Open the HTML report when done'
'--notify|none|||safe|no|output||Bell or desktop notification when done'
'--no-color|none|||safe|no|output||Force colors off'
'--color|none|||safe|no|output||Force colors on'
'--no-banner|none|||safe|no|output||Hide the headline'
'--authorized|none|||safe|no|safety||Confirm authorization for non-private targets'
'--json|none|||safe|no|safety||Emit the dry-run plan as deterministic JSON'
'--plan-file|str|v_path||safe|no|safety||Require an approved JSON scan plan'
'--plan-hash|str|v_name||safe|no|safety||SHA-256 hash of the approved plan'
'--dry-run|none|||safe|no|safety||Show the plan and exact command, run nothing'
'--sudo|none|||safe|no|safety||Re-run the toolkit through sudo'
'--yes,-y|none|||safe|no|safety||Skip confirmation prompts'
'--no-ping,-Pn|none||-Pn|safe|no|tuning||Treat hosts as up'
'--no-dns,-n|none||-n|safe|no|tuning||Skip DNS resolution'
'--ipv6,-6|none||-6|safe|no|tuning||IPv6 scanning'
'--policy|str|v_policy||safe|no|policy|strict|strict or advanced (requires --ack-risk)'
'--ack-risk|none|||moderate|no|policy||Acknowledge advanced policy risks'
'--tcp-syn-probe,-PS|csv|v_portlist|-PS%v|safe|no|nmap||TCP SYN discovery probe ports'
'--tcp-ack-probe,-PA|csv|v_portlist|-PA%v|safe|no|nmap||TCP ACK discovery probe ports'
'--udp-probe,-PU|csv|v_portlist|-PU%v|safe|no|nmap||UDP discovery probe ports'
'--sctp-probe,-PY|csv|v_portlist|-PY%v|safe|no|nmap||SCTP discovery probe ports'
'--icmp-echo,-PE|none||-PE|safe|no|nmap||ICMP echo discovery'
'--icmp-timestamp,-PP|none||-PP|safe|no|nmap||ICMP timestamp discovery'
'--icmp-netmask,-PM|none||-PM|safe|no|nmap||ICMP netmask discovery'
'--ip-proto-ping,-PO|csv|v_portlist|-PO%v|safe|no|nmap||IP protocol ping'
'--arp-ping,-PR|none||-PR|safe|no|nmap||ARP discovery (local network)'
'--disable-arp-ping|none||--disable-arp-ping|safe|no|nmap||Skip ARP discovery'
'--send-ip|none||--send-ip|safe|no|nmap||Send raw IP packets'
'--send-eth|none||--send-eth|safe|no|nmap||Send raw Ethernet frames'
'--connect-scan,-sT|none||-sT|safe|no|nmap||TCP connect scan'
'--syn-scan,-sS|none||-sS|moderate|yes|nmap||TCP SYN scan'
'--ack-scan,-sA|none||-sA|moderate|yes|nmap||TCP ACK scan'
'--window-scan,-sW|none||-sW|moderate|yes|nmap||TCP window scan'
'--maimon-scan,-sM|none||-sM|moderate|yes|nmap||TCP Maimon scan'
'--fin-scan,-sF|none||-sF|moderate|yes|nmap||TCP FIN scan'
'--null-scan,-sN|none||-sN|moderate|yes|nmap||TCP NULL scan'
'--xmas-scan,-sX|none||-sX|moderate|yes|nmap||TCP XMAS scan'
'--udp-scan,-sU|none||-sU|moderate|yes|nmap||UDP scan'
'--ip-proto-scan,-sO|none||-sO|moderate|yes|nmap||IP protocol scan'
'--sctp-init-scan,-sY|none||-sY|moderate|yes|nmap||SCTP INIT scan'
'--sctp-cookie-scan,-sZ|none||-sZ|moderate|yes|nmap||SCTP COOKIE-ECHO scan'
'--scanflags|str|v_flagset|--scanflags %v|moderate|yes|nmap||Custom TCP flag set (no raw hex)'
'--min-rate|int|v_rate|--min-rate %v|safe|no|nmap||Minimum packets per second'
'--min-parallelism|int|v_count|--min-parallelism %v|safe|no|nmap||Minimum parallel probes'
'--max-parallelism|int|v_count|--max-parallelism %v|safe|no|nmap||Maximum parallel probes'
'--min-hostgroup|int|v_count|--min-hostgroup %v|safe|no|nmap||Minimum hosts per group'
'--max-hostgroup|int|v_count|--max-hostgroup %v|safe|no|nmap||Maximum hosts per group'
'--initial-rtt-timeout|str|v_duration|--initial-rtt-timeout %v|safe|no|nmap||Initial RTT timeout'
'--min-rtt-timeout|str|v_duration|--min-rtt-timeout %v|safe|no|nmap||Minimum RTT timeout'
'--max-rtt-timeout|str|v_duration|--max-rtt-timeout %v|safe|no|nmap||Maximum RTT timeout'
'--scan-delay|str|v_duration|--scan-delay %v|safe|no|nmap||Delay between probes'
'--max-scan-delay|str|v_duration|--max-scan-delay %v|safe|no|nmap||Maximum probe delay'
'--max-attempts|int|v_count|--max-attempts %v|safe|no|nmap||Maximum probe attempts'
'--script-timeout|str|v_duration|--script-timeout %v|safe|no|nse||Timeout per NSE script'
'--exclude-ports|str|v_ports|--exclude-ports %v|safe|no|nmap||Ports to exclude'
'--fast-scan,-F|none||-F|safe|no|nmap||Fast (100 most common ports)'
'--randomize-ports,-r|none||-r|safe|no|nmap||Scan ports in random order'
'--all-ports,-p-|none||-p-|safe|no|nmap||Scan all 65535 ports'
'--version-intensity|int|v_version_int|--version-intensity %v|safe|no|nmap||Version detection intensity 0-9'
'--version-light|none||--version-light|safe|no|nmap||Light version detection'
'--version-all|none||--version-all|safe|no|nmap||Aggressive version detection'
'--version-trace|none||--version-trace|safe|no|nmap||Trace version detection'
'--os-detection,-O|none||-O|moderate|yes|nmap||OS detection'
'--fuzzy|none||--fuzzy|moderate|yes|nmap||Fuzzy OS match'
'--script-args-file|str|v_path|--script-args-file %v|safe|no|nse||Read NSE arguments from a file'
'--script-trace|none||--script-trace|safe|no|nse||Trace NSE traffic'
'--script-updatedb|none|||safe|no|tool||Update the local NSE script database'
'--packet-trace|none||--packet-trace|safe|no|nmap||Trace sent/received packets (needs --verbose)'
'--extra-verbose,-vv|none||-vv|safe|no|nmap||Extra verbose output'
'--debug,-ddd|none||-ddd|safe|no|nmap||Debug output'
'--source-port|int|v_port|--source-port %v|safe|no|nmap||Fixed source port'
'--data-length|int|v_count|--data-length %v|safe|no|nmap||Append random data to probes'
'--ttl|int|v_ttl|--ttl %v|safe|no|nmap||Set IPv4 TTL'
'--mtu|int|v_mtu|--mtu %v|safe|no|nmap||Set IP MTU'
'--config|str|v_path||safe|no|tool||Load an extra config file'
'--list-profiles|none|||safe|no|tool||Show every profile'
'--list-scripts|str|v_optional||safe|no|tool||Browse local NSE scripts'
'--script-help|str|v_name||safe|no|tool||Show NSE script documentation'
'--history|none|||safe|no|tool||List previous runs'
'--diff|str|v_name||safe|no|tool||Compare two runs'
'--open-report|str|v_optional||safe|no|tool||Open an HTML report'
'--export|str|v_export||safe|no|tool||Handoff list (urls, hosts, ports, openvas)'
'--doctor|none|||safe|no|tool||Check the environment'
'--check-updates|none|||safe|no|tool||Nmap version information'
'--online|none|||safe|no|tool||Query nmap.org for the latest version'
'--dump-options|none|||safe|no|tool||Print the option registry as JSON'
'--explain|none|||safe|no|tool||Explain why each Nmap argument was added'
'--verbose,-v|none|||safe|no|tool||Debug output'
'--version|none|||safe|no|tool||Print version'
'--help,-h|none|||safe|no|tool||Show help'
)

declare -A OPTION_CONFIG_MAP=(
    [--output]=OUTPUT_DIR
    [--profile]=DEFAULT_PROFILE
    [--timing]=TIMING
    [--theme]=THEME
    [--formats]=REPORT_FORMATS
    [--scope]=SCOPE_FILE
    [--max-rate]=MAX_RATE
    [--max-retries]=MAX_RETRIES
    [--host-timeout]=HOST_TIMEOUT
    [--dns-servers]=DNS_SERVERS
    [--no-latency]=PING_LATENCY
    [--open]=OPEN_REPORT
    [--notify]=NOTIFY
    [--color]=COLOR_MODE
)

OPTION_CATEGORY_ORDER=(target profile tuning nse nmap output safety policy tool)
declare -A OPTION_CATEGORY_TITLE=(
    [target]=TARGETS [profile]=PROFILES [tuning]=TUNING [nse]=NSE [nmap]=NMAP
    [output]=OUTPUT [safety]=SAFETY [policy]=POLICY [tool]=TOOLS
)

_option_parse() {
    IFS='|' read -r OPT_FLAG OPT_VALUE OPT_VALIDATOR OPT_NMAP OPT_RISK OPT_ROOT \
        OPT_CATEGORY OPT_DEFAULT OPT_DESC <<< "$1"
}

opt_canonical() { printf '%s' "${1%%,*}"; }

option_each() {
    local rec
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        "$@"
    done
}

declare -A OVERRIDE_VALUES=()

opt_store_override() {
    local canon
    canon="$(option_lookup "$1" canonical || true)"
    [[ -n "$canon" ]] || return 0
    OVERRIDE_VALUES["$canon"]="${2:-1}"
}

opt_resolve() {
    local rec flag wanted="$1" IFS=','
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        for flag in $OPT_FLAG; do
            if [[ "$flag" == "$wanted" ]]; then
                printf '%s' "$(opt_canonical "$OPT_FLAG")"; return 0
            fi
            if [[ "$OPT_NMAP" == "$flag%v"* && "$wanted" == "$flag"* && "$wanted" != "$flag" ]]; then
                printf '%s' "$(opt_canonical "$OPT_FLAG")"; return 0
            fi
        done
    done
    return 1
}

option_check_flag() { opt_resolve "$1" >/dev/null; }

opt_attached_value() {
    local rec alias canon wanted="$1" flag IFS=','
    canon="$(opt_resolve "$wanted")" || return 1
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        [[ "$(opt_canonical "$OPT_FLAG")" == "$canon" && "$OPT_NMAP" == *%v* ]] || continue
        flag="${OPT_NMAP%% *}"
        flag="${flag%%%v}"
        for alias in $OPT_FLAG; do
            if [[ "$alias" == "$flag" && "$wanted" == "$alias"* && "$wanted" != "$alias" ]]; then
                printf '%s' "${wanted#"$alias"}"; return 0
            fi
        done
    done
    return 1
}

option_lookup() {
    local rec flag canon wanted field="$2" IFS=','
    canon="$(opt_resolve "$1")" || return 1
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        for flag in $OPT_FLAG; do
            [[ "$flag" != "$canon" ]] && continue
            case "$field" in
                flag)      printf '%s' "$OPT_FLAG" ;;
                canonical) printf '%s' "$canon" ;;
                value)     printf '%s' "$OPT_VALUE" ;;
                validator) printf '%s' "$OPT_VALIDATOR" ;;
                nmap)      printf '%s' "$OPT_NMAP" ;;
                risk)      printf '%s' "$OPT_RISK" ;;
                root)      printf '%s' "$OPT_ROOT" ;;
                category)  printf '%s' "$OPT_CATEGORY" ;;
                default)   printf '%s' "$OPT_DEFAULT" ;;
                desc)      printf '%s' "$OPT_DESC" ;;
                *) return 1 ;;
            esac
            return 0
        done
    done
    return 1
}

option_validate() {
    local flag="$1" value="${2:-}" canon val
    canon="$(option_lookup "$flag" canonical || true)"
    [[ -n "$canon" ]] || return 0
    val="$(option_lookup "$flag" validator || true)"
    if [[ -z "$val" ]]; then
        [[ "$OPT_VALUE" != none || -z "$value" ]] || :
        return 0
    fi
    case "$val" in
        v_timing)
            [[ "$value" =~ ^[0-5]$ || "$value" =~ ^(paranoid|sneaky|polite|normal|aggressive|insane)$ ]] \
                || die "Invalid value for $canon: $value (use 0-5 or a timing name)." ;;
        v_ports)
            [[ "$value" =~ ^[0-9TUSP:,-]+$ ]] || die "Invalid port specification for $canon: $value" ;;
        v_portlist)
            [[ "$value" =~ ^[0-9,-]+$ ]] || die "Invalid probe port list for $canon: $value" ;;
        v_flagset)
            [[ "$value" =~ ^[A-Za-z0-9()|]+$ && "$value" != 0x* ]] \
                || die "Invalid scan flags for $canon: $value" ;;
        v_port)
            [[ "$value" =~ ^[0-9]+$ && "$value" -ge 1 && "$value" -le 65535 ]] \
                || die "$canon needs a port number (1-65535)." ;;
        v_ttl)
            [[ "$value" =~ ^[0-9]+$ && "$value" -le 255 ]] || die "$canon needs a TTL (0-255)." ;;
        v_mtu)
            [[ "$value" =~ ^[0-9]+$ && "$value" -ge 8 && "$value" -le 9000 ]] \
                || die "$canon needs an MTU (8-9000)." ;;
        v_version_int)
            [[ "$value" =~ ^[0-9]$ ]] || die "$canon needs a digit 0-9." ;;
        v_range)
            [[ "$value" =~ ^[0-9]+(-[0-9]+)?$ ]] || die "$canon needs a number or range." ;;
        v_count)
            [[ "$value" =~ ^[0-9]+$ ]] || die "$canon needs a number." ;;
        v_rate)
            [[ "$value" =~ ^[0-9]+$ && "$value" -gt 0 ]] || die "$canon needs a positive number." ;;
        v_duration)
            [[ "$value" =~ ^[0-9]+[smhd]?$ ]] || die "$canon needs a duration like 90s, 5m, 1h." ;;
        v_dns)
            [[ "$value" =~ ^[0-9a-fA-F.:,]+$ ]] || die "Invalid DNS servers for $canon." ;;
        v_iface)
            [[ "$value" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid interface name for $canon." ;;
        v_script)
            [[ -n "$value" ]] || die "$canon needs a value."
            guard_script_spec "$value" ;;
        v_formats)
            [[ "$value" =~ ^[a-z,]+$ ]] || die "Invalid formats for $canon." ;;
        v_theme)
            ui_themes | grep -qx "$value" || die "Unknown theme '$value'." ;;
        v_policy)
            [[ "$value" == strict || "$value" == advanced ]] || die "$canon must be strict or advanced." ;;
        v_export)
            [[ "$value" =~ ^(urls|hostports|hosts|ports|openvas|csv-coords|json-arm)$ ]] \
                || die "Invalid export kind '$value'." ;;
        v_name)
            [[ "$value" =~ ^[A-Za-z0-9_.:/*@-]+$ ]] || die "Invalid name for $canon." ;;
        v_storage_name)
            [[ "$value" =~ ^[A-Za-z0-9_-]+$ ]] || die "Invalid storage name for $canon: $value" ;;
        v_optional) : ;;
        v_args)
            [[ -n "$value" ]] || die "$canon needs a value." ;;
        v_path)
            [[ -n "$value" ]] || die "$canon needs a path." ;;
        v_profile) : ;;
        v_hostspec)
            validate_target_token "$value" ;;
    esac
    return 0
}

opt_all_flags() {
    local rec flag IFS=','
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        for flag in $OPT_FLAG; do printf '%s\n' "$flag"; done
    done
}

options_emit_config_keys() {
    printf '%s\n' "${OPTION_CONFIG_MAP[@]}" | sort
}

options_emit_categories() {
    local cat count rec
    for cat in "${OPTION_CATEGORY_ORDER[@]}"; do
        count=0
        for rec in "${OPTION_TABLE[@]}"; do
            _option_parse "$rec"
            [[ "$OPT_CATEGORY" == "$cat" ]] && count=$(( count + 1 ))
        done
        printf '%s|%s|%d option(s)\n' "$cat" "${OPTION_CATEGORY_TITLE[$cat]}" "$count"
    done
}

options_in_category() {
    local wanted="$1" rec
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        [[ "$OPT_CATEGORY" == "$wanted" ]] && printf '%s\n' "$rec"
    done
}

options_emit_help() {
    local cat rec flag flags display
    for cat in "${OPTION_CATEGORY_ORDER[@]}"; do
        printf '\n%s%s%s\n' "${C_ACCENT:-}" "${C_BOLD:-}" "${OPTION_CATEGORY_TITLE[$cat]}${C_RESET:-}"
        for rec in "${OPTION_TABLE[@]}"; do
            _option_parse "$rec"
            [[ "$OPT_CATEGORY" == "$cat" ]] || continue
            flags=""
            local IFS=','
            for flag in $OPT_FLAG; do
                flags+="${flags:+, }$flag"
            done
            [[ "$OPT_VALUE" == none ]] || flags+=" VALUE"
            display="$flags"
            printf '  %-28s %s%s\n' "$display" "$OPT_DESC" "${C_RESET:-}"
        done
    done
}

options_emit_json() {
    local rec first=1 esc
    _json_esc() { printf '%s' "$1" | tr '\n\r\t' '   ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
    printf '[\n'
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        (( first )) || printf ',\n'
        first=0
        esc="$(_json_esc "$OPT_FLAG")"
        printf '  {"flag":"%s","aliases":%d,"value":"%s","validator":"%s","nmap":"%s","risk":"%s","root":"%s","category":"%s","default":"%s","description":"%s"}' \
            "$esc" "$(awk -F, '{print NF}' <<< "$OPT_FLAG")" "$OPT_VALUE" "$OPT_VALIDATOR" \
            "$(_json_esc "$OPT_NMAP")" "$OPT_RISK" "$OPT_ROOT" "$OPT_CATEGORY" \
            "$(_json_esc "$OPT_DEFAULT")" "$(_json_esc "$OPT_DESC")"
    done
    printf '\n]\n'
}

options_emit_docs() {
    local rec flag flags
    printf '# Generated option reference\n\n'
    printf 'Generated from `lib/options.sh` by `make docs`. Do not edit by hand.\n\n'
    printf '| Flag | Value | Risk | Root | Description |\n|---|---|---|---|---|\n'
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        flags=""
        local IFS=','
        for flag in $OPT_FLAG; do flags+="${flags:+, }\\\`$flag\\\`"; done
        printf '| %s | %s | %s | %s | %s |\n' "$flags" "$OPT_VALUE" "$OPT_RISK" "$OPT_ROOT" "$OPT_DESC"
    done
}

options_emit_completion() {
    local flags body
    flags="$(opt_all_flags | paste -sd' ' -)"
    profiles="discovery arp sweep diagnostic list broadcast quick standard deep full os udp firewall polite default safe-nse discovery-nse vuln-safe vuln vulners web tls ssh smb dns db mail rdp ftp odoo pos iot audit recon inventory custom"
    IFS= read -r -d '' body <<'EOF' || true
# bash completion for xamltech-nmap / nmap-toolkit.sh (generated by `make completions`)
_xamltech_nmap() {
    local cur prev opts profiles
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="__OPTS__"
    profiles="__PROFILES__"
    case "$prev" in
        -p|--profile) mapfile -t COMPREPLY < <(compgen -W "$profiles" -- "$cur"); return ;;
        --theme)      mapfile -t COMPREPLY < <(compgen -W "cyber ocean sunset matrix aurora mono" -- "$cur"); return ;;
        -T|--timing)  mapfile -t COMPREPLY < <(compgen -W "0 1 2 3 4 5" -- "$cur"); return ;;
        --export)     mapfile -t COMPREPLY < <(compgen -W "urls hostports hosts ports openvas" -- "$cur"); return ;;
        --formats)    mapfile -t COMPREPLY < <(compgen -W "json,csv,md,html json,html json" -- "$cur"); return ;;
        -o|--output|--scope|--config|-L|--target-file|--diff|--open-report)
                      mapfile -t COMPREPLY < <(compgen -f -- "$cur"); return ;;
    esac
    if [[ "$cur" == -* ]]; then
        mapfile -t COMPREPLY < <(compgen -W "$opts" -- "$cur")
    fi
}
complete -F _xamltech_nmap xamltech-nmap nmap-toolkit.sh ./nmap-toolkit.sh
EOF
    printf '%s' "${body//__OPTS__/$flags}" | sed "s|__PROFILES__|$profiles|"
}

options_emit_zsh() {
    local rec flag short long
    printf '#compdef xamltech-nmap nmap-toolkit.sh\n'
    printf '# Generated by `make completions`; do not edit by hand.\n'
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        short=""; long=""
        local IFS=','
        for flag in $OPT_FLAG; do
            if [[ "$flag" == --* ]]; then long="$flag"; else short="$flag"; fi
        done
        printf '%s\n' "  '${long:-$short}[${OPT_DESC}]' \\"
        [[ -z "$short" || "$short" == "$long" ]] || printf '%s\n' "  '${short}[${OPT_DESC}]' \\"
    done
}

options_emit_fish() {
    local rec flag short long
    printf '# Generated by `make completions`; do not edit by hand.\n'
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        short=""; long=""
        local IFS=','
        for flag in $OPT_FLAG; do
            if [[ "$flag" == --* ]]; then long="$flag"; else short="$flag"; fi
        done
        [[ -z "$long" ]] || printf 'complete -c xamltech-nmap -l %s -d %q\n' "${long#--}" "$OPT_DESC"
        [[ -z "$short" || "$short" == "$long" ]] || printf 'complete -c xamltech-nmap -s %s -d %q\n' "${short#-}" "$OPT_DESC"
    done
}

options_emit_man() {
    local rec flag flags
    printf '.TH XAMLTECH-NMAP 1 "2026-01-01" "xamltech-nmap-toolkit" "User Commands"\n'
    printf '.SH NAME\nxamltech-nmap \\- authorized network discovery and diagnostics\n'
    printf '.SH SYNOPSIS\n.B xamltech-nmap\n[OPTIONS]\n'
    printf '.SH DESCRIPTION\nGenerated from lib/options.sh by `make docs`. Do not edit by hand.\n'
    printf '.SH OPTIONS\n'
    for rec in "${OPTION_TABLE[@]}"; do
        _option_parse "$rec"
        flags=""
        local IFS=','
        for flag in $OPT_FLAG; do flags+="${flags:+, }\\fB$flag\\fR"; done
        printf '.TP\n%s\n%s\n' "$flags" "$OPT_DESC"
    done
    printf '.SH SEE ALSO\n.BR nmap (1)\n'
}
