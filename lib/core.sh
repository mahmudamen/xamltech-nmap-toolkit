# shellcheck shell=bash
# XamlTech Nmap Toolkit - core helpers
# Config, validation, scope/authorization guard, privileges, dependency checks.

NMAP_BIN=""
NMAP_PRIVILEGED=0       # 1 when raw sockets are available (root or cap_net_raw)
NMAP_NEEDS_FLAG=0       # 1 when running via capabilities (needs --privileged)
ADAPT_NOTES=()
SPLIT_RESULT=()
RUN_LOG=""

command_exists() { command -v "$1" >/dev/null 2>&1; }

timestamp()      { date '+%Y-%m-%d %H:%M:%S %z'; }
safe_timestamp() { date '+%Y-%m-%d_%H%M%S'; }
is_root()        { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }

# ---------- logging ----------

log_init() {
    RUN_LOG="$RUN_DIR/toolkit.log"
    : > "$RUN_LOG"
    _log_hook() {
        printf '%s [%-5s] %s\n' "$(date '+%F %T')" "$1" "$(printf '%s' "$2" | strip_ansi)" >> "$RUN_LOG"
    }
}

# ---------- argument splitting (quote aware, never eval) ----------

# split_args "string with 'quoted args'"  -> SPLIT_RESULT[]
split_args() {
    SPLIT_RESULT=()
    [[ -n "${1:-}" ]] || return 0
    local out
    if command_exists python3; then
        if ! out="$(python3 -I -c 'import shlex,sys; print("\n".join(shlex.split(sys.argv[1])))' "$1" 2>&1)"; then
            die "Could not parse arguments: $out"
        fi
        [[ -z "$out" ]] || mapfile -t SPLIT_RESULT <<< "$out"
    else
        local IFS=' '
        read -r -a SPLIT_RESULT <<< "$1"
    fi
}

# ---------- config (key=value, whitelist, never sourced) ----------

CONFIG_KEYS=(OUTPUT_DIR DEFAULT_PROFILE TIMING THEME REPORT_FORMATS SCOPE_FILE PING_LATENCY
             COLOR_MODE DNS_SERVERS MAX_RATE HOST_TIMEOUT OPEN_REPORT NOTIFY MAX_RETRIES)

load_config() {
    local file="$1" line key val k ok_key lineno=0
    [[ -r "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$(( lineno + 1 ))
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        if [[ ! "$line" =~ ^([A-Z_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            warn "$file:$lineno: ignored malformed line"
            continue
        fi
        key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
        val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
        ok_key=0
        for k in "${CONFIG_KEYS[@]}"; do [[ "$k" == "$key" ]] && ok_key=1; done
        if (( ok_key )); then
            printf -v "$key" '%s' "$val"
            debug "config: $key=$val"
        else
            warn "$file:$lineno: unknown key '$key' ignored"
        fi
    done < "$file"
}

# ---------- tools / dependencies ----------

require_basic_tools() {
    local cmd
    for cmd in awk sed grep date mkdir tee sort find; do
        command_exists "$cmd" || { DIE_CODE=3 die "Required command not found: $cmd"; }
    done
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
        DIE_CODE=3 die "Bash 4.4+ required (found ${BASH_VERSION}). On macOS: brew install bash"
    fi
}

detect_nmap() {
    if command_exists nmap; then
        NMAP_BIN="$(command -v nmap)"
    else
        DIE_CODE=3 die "Nmap is not installed. See docs/USAGE.md for installation instructions."
    fi
    detect_privileges
}

nmap_version() { "$NMAP_BIN" --version 2>/dev/null | awk 'NR==1 {print $3}'; }

nmap_datadir() {
    local d
    for d in "${NMAPDIR:-}" /usr/share/nmap /usr/local/share/nmap /opt/homebrew/share/nmap /opt/local/share/nmap; do
        [[ -n "$d" && -d "$d/scripts" ]] && { printf '%s' "$d"; return 0; }
    done
    return 1
}

version_ge() {
    local -a a b
    local i av bv
    IFS=. read -r -a a <<< "$1"
    IFS=. read -r -a b <<< "$2"
    for i in 0 1 2 3; do
        av="${a[$i]:-0}"; bv="${b[$i]:-0}"
        av="${av//[^0-9]/}"; bv="${bv//[^0-9]/}"
        (( 10#${av:-0} > 10#${bv:-0} )) && return 0
        (( 10#${av:-0} < 10#${bv:-0} )) && return 1
    done
    return 0
}

# Raw-socket capability: root, or cap_net_raw on the nmap binary (then --privileged is required)
detect_privileges() {
    NMAP_PRIVILEGED=0; NMAP_NEEDS_FLAG=0
    if is_root; then
        NMAP_PRIVILEGED=1
    elif command_exists getcap && getcap "$NMAP_BIN" 2>/dev/null | grep -q 'cap_net_raw'; then
        NMAP_PRIVILEGED=1; NMAP_NEEDS_FLAG=1
    fi
}

check_dependencies() {
    printf '%s\n' "Dependency check:"
    local cmd
    for cmd in nmap awk sed grep date mkdir tee sort find; do
        if command_exists "$cmd"; then ok "$cmd"; else warn "$cmd missing"; fi
    done
    command_exists python3 && ok "python3 (rich reports enabled)" || warn "python3 missing - HTML/JSON/Markdown reports disabled"
    command_exists ping    && ok "ping" || hint "ping missing - latency table disabled"
}

# One-line environment status shown before scans
env_line() {
    local py priv
    command_exists python3 && py="${C_GREEN}python3 ${S_OK}${C_RESET}" || py="${C_YELLOW}python3 ${S_ERR} (reports limited)${C_RESET}"
    (( NMAP_PRIVILEGED )) && priv="${C_GREEN}raw sockets ${S_OK}${C_RESET}" || priv="${C_YELLOW}unprivileged${C_RESET}"
    printf '  %snmap %s%s  %s  %s  %s%s%s\n' "$C_GRAY" "$(nmap_version)" "$C_RESET" "$py" "$priv" "$C_GRAY" "theme:$THEME_NAME" "$C_RESET"
}

# ---------- doctor ----------

doctor() {
    section "Environment doctor"
    local v d
    kv "Toolkit"  "$SCRIPT_VERSION"
    kv "Bash"     "$BASH_VERSION" "$C_GREEN"
    if command_exists nmap; then
        NMAP_BIN="$(command -v nmap)"; detect_privileges
        kv "Nmap" "$(nmap_version)  ($NMAP_BIN)" "$C_GREEN"
        d="$(nmap_datadir || true)"
        if [[ -n "$d" ]]; then
            kv "NSE scripts" "$(find "$d/scripts" -name '*.nse' 2>/dev/null | wc -l | tr -d ' ') installed ($d/scripts)" "$C_GREEN"
            [[ -f "$d/scripts/vulners.nse" ]] && kv "vulners" "available (queries vulners.com - data leaves your network)" "$C_YELLOW" \
                || kv "vulners" "not installed" "$C_GRAY"
        else
            kv "NSE scripts" "data directory not found" "$C_YELLOW"
        fi
    else
        kv "Nmap" "NOT FOUND" "$C_RED"
    fi
    if command_exists python3; then
        v="$(python3 --version 2>&1)"; kv "Python" "$v  (reports: json csv md html)" "$C_GREEN"
    else
        kv "Python" "missing - reports limited to Nmap native formats" "$C_YELLOW"
    fi
    if is_root; then kv "Privileges" "root (raw sockets, SYN/UDP/OS scans)" "$C_GREEN"
    elif (( NMAP_PRIVILEGED )); then kv "Privileges" "cap_net_raw on nmap (uses --privileged)" "$C_GREEN"
    else kv "Privileges" "unprivileged - SYN/UDP/OS scans adapt to TCP-connect" "$C_YELLOW"; fi
    command_exists sudo && kv "sudo" "available (use --sudo to re-run elevated)" "$C_GRAY" || kv "sudo" "not found" "$C_GRAY"
    command_exists ping && kv "ping" "available" "$C_GREEN" || kv "ping" "missing (latency table off)" "$C_YELLOW"
    command_exists ip   && kv "ip" "available (network auto-detection)" "$C_GREEN" || kv "ip" "missing (manual targets only)" "$C_YELLOW"
    kv "Terminal" "${UI_COLS} cols, $( ((UI_TRUECOLOR)) && echo truecolor || echo 256-color ), $( ((UI_UTF8)) && echo UTF-8 || echo ASCII )"
    kv "Theme" "$THEME_NAME"
    mkdir -p "$OUTPUT_DIR" 2>/dev/null && [[ -w "$OUTPUT_DIR" ]] \
        && kv "Output dir" "$OUTPUT_DIR (writable)" "$C_GREEN" || kv "Output dir" "$OUTPUT_DIR (NOT writable)" "$C_RED"
    printf '\n'
}

# ---------- update info ----------

latest_nmap_from_apt() {
    command_exists apt-cache || return 0
    apt-cache policy nmap 2>/dev/null | awk '/Candidate:/ {print $2; exit}' || true
}

latest_nmap_online() {
    command_exists curl || return 0
    curl -fsSL --max-time 6 https://nmap.org/dist/ 2>/dev/null \
        | grep -oE 'nmap-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.bz2' | sed -E 's/^nmap-//; s/\.tar\.bz2$//' \
        | sort -V | tail -1 || true
}

check_updates() {
    detect_nmap
    local installed candidate online
    installed="$(nmap_version)"
    candidate="$(latest_nmap_from_apt)"

    section "Nmap version information"
    kv "Installed" "${installed:-unknown}"
    if [[ -n "$candidate" && "$candidate" != "(none)" ]]; then
        kv "APT candidate" "$candidate"
        if version_ge "${installed:-0}" "${candidate%%[-+~]*}"; then
            ok "Installed Nmap is at least the configured APT candidate."
        else
            warn "A newer APT candidate is available:  sudo apt update && sudo apt install nmap"
        fi
    else
        hint "No local APT candidate - use your distribution package manager."
    fi
    if (( ${ONLINE_CHECK:-0} )); then
        online="$(latest_nmap_online)"
        if [[ -n "$online" ]]; then
            kv "nmap.org latest" "$online"
            version_ge "${installed:-0}" "$online" && ok "Installed Nmap is current." \
                || warn "nmap.org lists a newer release ($online)."
        else
            warn "Could not reach nmap.org (offline, blocked, or curl missing)."
        fi
    else
        hint "Add --online to also query https://nmap.org/dist/"
    fi
    printf '\n  Official project: https://nmap.org/\n'
}

# ---------- target validation ----------

TARGETS=()

validate_target_token() {
    local t="$1"
    [[ -n "$t" ]] || die "Target cannot be empty."
    [[ "$t" != -* ]] || die "Target cannot begin with '-' ($t)."
    # Allowlist, not blocklist: hostnames, IPv4/IPv6, CIDR, octet ranges/lists, wildcards.
    [[ "$t" =~ ^[A-Za-z0-9:*][][A-Za-z0-9._:/*,-]*$ ]] \
        || die "Target '$t' contains unsupported characters."
    (( ${#t} <= 253 )) || die "Target is too long."
}

# set_targets "a b c"   (whitespace separated)
set_targets() {
    local t IFS=$' \t\n'
    TARGETS=()
    for t in $1; do
        validate_target_token "$t"
        TARGETS+=("$t")
    done
    [[ ${#TARGETS[@]} -gt 0 ]] || die "Target cannot be empty."
}

load_targets_file() {
    local file="$1" line
    [[ -r "$file" ]] || die "Cannot read target file: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        validate_target_token "$line"
        TARGETS+=("$line")
    done < "$file"
    [[ ${#TARGETS[@]} -gt 0 ]] || die "Target file is empty: $file"
}

target_label() {
    local first="${TARGETS[0]:-broadcast}" slug
    slug="${first//[^A-Za-z0-9._-]/_}"
    slug="${slug:0:40}"
    (( ${#TARGETS[@]} > 1 )) && slug="${slug}+$(( ${#TARGETS[@]} - 1 ))"
    printf '%s' "$slug"
}

target_display() {
    local out="${TARGETS[*]:-<none>}"
    (( ${#out} > 70 )) && out="${out:0:67}..."
    printf '%s' "$out"
}

# ---------- authorization / scope ----------

# internal | external | unknown for the whole target set (worst wins)
classify_targets() {
    if command_exists python3 && [[ -f "$LIB_DIR/report.py" ]]; then
        python3 -I "$LIB_DIR/report.py" classify "${TARGETS[@]}" 2>/dev/null || echo unknown
        return
    fi
    local t worst=internal
    for t in "${TARGETS[@]}"; do
        if [[ "$t" =~ ^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then :; else worst=external; fi
    done
    printf '%s' "$worst"
}

enforce_scope() {
    [[ -n "${SCOPE_FILE:-}" && ${#TARGETS[@]} -gt 0 ]] || return 0
    [[ -r "$SCOPE_FILE" ]] || die "Scope file not readable: $SCOPE_FILE"
    command_exists python3 || die "Scope enforcement requires python3."
    local out
    if ! out="$(python3 -I "$LIB_DIR/report.py" scope "$SCOPE_FILE" "${TARGETS[@]}" 2>&1)"; then
        error "Target is outside the authorized scope file ($SCOPE_FILE):"
        printf '%s\n' "$out" >&2
        DIE_CODE=4 die "Refusing to scan out-of-scope targets."
    fi
    ok "All targets are inside the authorized scope ($SCOPE_FILE)."
}

# Public/unknown targets need explicit, typed consent. Internal ones keep the quick flow.
authorization_gate() {
    [[ ${#TARGETS[@]} -gt 0 ]] || return 0      # target-less profiles (broadcast) only touch the local segment
    local cls phrase="I AM AUTHORIZED" typed
    cls="$(classify_targets)"
    TARGET_CLASS="$cls"
    case "$cls" in
        internal) return 0 ;;
    esac
    warn "Target class: ${cls} (not clearly a private/loopback address)."
    warn "Scanning systems you do not own or lack written permission to test may be illegal."
    if (( ${AUTHORIZED:-0} )); then
        info "Authorization asserted via --authorized."
        return 0
    fi
    if [[ -t 0 ]]; then
        read -r -p "${C_YELLOW}?${C_RESET} Type '${phrase}' to confirm you have permission: " typed || typed=""
        [[ "$typed" == "$phrase" ]] && return 0
        info "Cancelled."; return 1
    fi
    DIE_CODE=4 die "Non-private target. Re-run with --authorized to confirm you have permission."
}

# ---------- guard rails for custom arguments ----------

# The toolkit manages output files and refuses offensive NSE categories.
guard_custom_args() {
    local a next lower
    local -a arr=("$@")
    local i
    for (( i = 0; i < ${#arr[@]}; i++ )); do
        a="${arr[i]}"; lower="${a,,}"
        case "$a" in
            -oN|-oX|-oG|-oA|-oS|-oJ|--resume|--append-output|--stylesheet|--webxml|--datadir|--script-updatedb)
                die "Option '$a' is managed by the toolkit and cannot be passed through." ;;
            -o[NXGASJ]*) die "Output option '$a' is managed by the toolkit." ;;
        esac
        if [[ "$a" == --script=* || "$a" == "--script" ]]; then
            if [[ "$a" == --script=* ]]; then next="${a#--script=}"; else next="${arr[i+1]:-}"; fi
            guard_script_spec "$next"
        fi
    done
}

guard_script_spec() {
    local spec="${1,,}"
    if [[ "$spec" =~ (^|[^a-z])(brute|dos|exploit|fuzzer|intrusive)([^a-z]|$) || "$spec" == *-brute* || "$spec" == *-dos* ]]; then
        DIE_CODE=4 die "Blocked NSE selection '$1': brute-force, DoS, exploit, fuzzer and intrusive scripts are intentionally not supported by this toolkit."
    fi
}

# ---------- privilege adaptation ----------

# Rewrites NMAP_ARGS so unprivileged runs degrade gracefully instead of failing.
adapt_args_for_privileges() {
    ADAPT_NOTES=()
    (( NMAP_PRIVILEGED )) && return 0
    local -a out=()
    local a
    for a in "${NMAP_ARGS[@]}"; do
        case "$a" in
            -sS|-sA|-sW|-sM|-sF|-sN|-sX) out+=("-sT"); ADAPT_NOTES+=("$a -> -sT (raw sockets unavailable)") ;;
            -sU) ADAPT_NOTES+=("-sU dropped (UDP scan needs root)") ;;
            -O|--osscan-limit|--osscan-guess|--fuzzy) ADAPT_NOTES+=("$a dropped (OS detection needs root)") ;;
            -PE|-PP|-PM|-PR|-PO*|--traceroute) ADAPT_NOTES+=("$a dropped (needs raw sockets)") ;;
            *) out+=("$a") ;;
        esac
    done
    # de-duplicate repeated -sT
    local -a dedup=(); local seen_st=0
    for a in "${out[@]}"; do
        if [[ "$a" == "-sT" ]]; then (( seen_st )) && continue; seen_st=1; fi
        dedup+=("$a")
    done
    NMAP_ARGS=("${dedup[@]}")
}

# Re-exec the whole toolkit through sudo (explicit opt-in via --sudo)
reexec_with_sudo() {
    command_exists sudo || die "sudo is not installed."
    info "Re-running with sudo (you may be prompted for your password)..."
    exec sudo -E "$SCRIPT_PATH" "${ORIGINAL_ARGS[@]}"
}
