#!/usr/bin/env bash
#
# XamlTech Nmap Toolkit
# Authorized network discovery and diagnostics toolkit.
#
# Author: Mahmoud Mohamed Amin
# GitHub: mahmudamen
# Website: https://xamltech.com
#
# License: MIT
#

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="xamltech-nmap-toolkit"
readonly SCRIPT_VERSION="1.0.0"
readonly AUTHOR="Mahmoud Mohamed Amin"
readonly GITHUB_USER="mahmudamen"
readonly WEBSITE="https://xamltech.com"

TARGET=""
PROFILE="interactive"
OUTPUT_DIR="./results"
NMAP_BIN=""
SUDO_REQUIRED=0
VERBOSE=0
ASSUME_YES=0
CUSTOM_ARGS=()
START_EPOCH=0
RUN_DIR=""

# ---------- UI ----------

bold() { printf '\033[1m%s\033[0m' "$*"; }
dim() { printf '\033[2m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
red() { printf '\033[31m%s\033[0m' "$*"; }
cyan() { printf '\033[36m%s\033[0m' "$*"; }

info()  { printf '%s %s\n' "$(cyan '[INFO]')" "$*"; }
ok()    { printf '%s %s\n' "$(green '[ OK ]')" "$*"; }
warn()  { printf '%s %s\n' "$(yellow '[WARN]')" "$*"; }
error() { printf '%s %s\n' "$(red '[ERR ]')" "$*" >&2; }
die()   { error "$*"; exit 1; }

banner() {
    printf '\n'
    printf '%s\n' '╔══════════════════════════════════════════════════════════╗'
    printf '%s\n' '║                  XamlTech Nmap Toolkit                  ║'
    printf '%s\n' '║       Network Discovery & Diagnostics for Linux         ║'
    printf '%s\n' '╚══════════════════════════════════════════════════════════╝'
    printf ' Version: %-6s Author: %s\n\n' "$SCRIPT_VERSION" "$AUTHOR"
}

usage() {
    cat <<EOF
$SCRIPT_NAME $SCRIPT_VERSION

Authorized network discovery and diagnostics using Nmap.

USAGE
  $0 [OPTIONS]

OPTIONS
  -t, --target TARGET       Host, hostname, range, or CIDR target
  -p, --profile PROFILE     discovery|quick|standard|deep|os|diagnostic|custom
  -o, --output DIR          Result directory (default: ./results)
  -a, --args "ARGS"         Additional Nmap arguments (custom profile recommended)
  -v, --verbose             Show more command/output information
  -y, --yes                 Skip confirmation prompts
      --check-updates       Check Nmap version/update information and exit
      --version             Print toolkit version
  -h, --help                Show this help

PROFILES
  discovery    Host discovery only; useful for inventory
  quick        Fast TCP port scan
  standard     Common TCP ports + service/version detection
  deep         Broad TCP scan + service/version detection
  os           Broad scan + service/version + OS detection
  diagnostic   Host discovery + latency-oriented diagnostics
  custom       Run user-supplied Nmap arguments

EXAMPLES
  $0
  $0 --target 192.168.1.0/24 --profile discovery
  $0 --target 192.168.1.1 --profile standard
  $0 --target router.local --profile os
  $0 --target 192.168.1.0/24 --profile diagnostic
  $0 --target 192.168.1.1 --profile custom --args "-sV --top-ports 100"

NOTES
  - Scan only systems/networks you own or are explicitly authorized to test.
  - Some profiles require root privileges for best results.
  - Results are written under the selected output directory.
EOF
}

# ---------- Helpers ----------

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_basic_tools() {
    local cmd
    for cmd in awk sed grep date mkdir tee timeout sort; do
        command_exists "$cmd" || die "Required command not found: $cmd"
    done
}

detect_nmap() {
    if command_exists nmap; then
        NMAP_BIN="$(command -v nmap)"
    else
        die "Nmap is not installed. See docs/USAGE.md for installation instructions."
    fi
}

nmap_version() {
    "$NMAP_BIN" --version 2>/dev/null | awk 'NR==1 {print $3}'
}

version_ge() {
    # Returns true when $1 >= $2 for dotted numeric versions.
    local a b i
    IFS=. read -r -a a <<< "$1"
    IFS=. read -r -a b <<< "$2"
    for i in 0 1 2 3; do
        local av="${a[$i]:-0}" bv="${b[$i]:-0}"
        ((10#$av > 10#$bv)) && return 0
        ((10#$av < 10#$bv)) && return 1
    done
    return 0
}

is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }

needs_root_for_profile() {
    case "$1" in
        os) return 0 ;;
        deep|standard) return 0 ;;
        *) return 1 ;;
    esac
}

validate_profile() {
    case "$1" in
        discovery|quick|standard|deep|os|diagnostic|custom) ;;
        *) die "Unknown profile: $1" ;;
    esac
}

validate_target() {
    [[ -n "$1" ]] || die "Target cannot be empty."
    [[ "$1" != -* ]] || die "Target cannot begin with '-'."
    # Deliberately reject shell metacharacters often used for command injection.
    if [[ "$1" =~ [\;\&\|\`\$\(\)\<\>] ]]; then
        die "Target contains unsupported shell metacharacters."
    fi
}

timestamp() { date '+%Y-%m-%d %H:%M:%S %z'; }
safe_timestamp() { date '+%Y-%m-%d_%H%M%S'; }

confirm() {
    local prompt="${1:-Continue?}"
    (( ASSUME_YES )) && return 0
    read -r -p "$prompt [y/N]: " answer
    [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# ---------- Dependency / update information ----------

check_dependencies() {
    printf '%s\n' "Dependency check:"
    local tools=(nmap awk sed grep date mkdir tee timeout sort)
    local cmd
    for cmd in "${tools[@]}"; do
        if command_exists "$cmd"; then
            ok "$cmd"
        else
            warn "$cmd missing"
        fi
    done
}

latest_nmap_from_apt() {
    command_exists apt-cache || return 0
    apt-cache policy nmap 2>/dev/null |
        awk '/Candidate:/ {print $2; exit}' || true
}

check_updates() {
    detect_nmap
    local installed candidate
    installed="$(nmap_version)"
    candidate="$(latest_nmap_from_apt)"

    printf '\nNmap version information\n'
    printf '%s\n' '────────────────────────────────────────────'
    printf 'Installed : %s\n' "${installed:-unknown}"

    if [[ -n "$candidate" && "$candidate" != "(none)" ]]; then
        printf 'APT       : %s\n' "$candidate"
        if version_ge "$installed" "$candidate"; then
            ok "Installed Nmap is at least the configured APT candidate."
        else
            warn "An APT candidate newer than the installed version is available."
            printf '  Ubuntu/Debian: sudo apt update && sudo apt install nmap\n'
        fi
    else
        warn "No local APT candidate detected; use your distribution package manager."
    fi

    printf '\n'
    printf 'Official Nmap project: https://nmap.org/\n'
}

# ---------- Profile construction ----------

build_nmap_args() {
    local profile="$1"

    case "$profile" in
        discovery)
            NMAP_ARGS=(-sn --reason)
            ;;
        quick)
            NMAP_ARGS=(-T4 --top-ports 100 --open --reason)
            ;;
        standard)
            NMAP_ARGS=(-sS -T4 --top-ports 1000 -sV --open --reason)
            ;;
        deep)
            NMAP_ARGS=(-sS -T3 -p- -sV --open --reason)
            ;;
        os)
            NMAP_ARGS=(-sS -T3 -p- -sV -O --osscan-limit --open --reason)
            ;;
        diagnostic)
            NMAP_ARGS=(-sn -T4 --reason --traceroute)
            ;;
        custom)
            [[ ${#CUSTOM_ARGS[@]} -gt 0 ]] || die "Custom profile requires --args."
            NMAP_ARGS=("${CUSTOM_ARGS[@]}")
            ;;
        *)
            die "Invalid profile: $profile"
            ;;
    esac
}

# ---------- Results ----------

prepare_run_dir() {
    local stamp
    stamp="$(safe_timestamp)"
    RUN_DIR="$OUTPUT_DIR/$stamp"
    mkdir -p "$RUN_DIR"
}

write_metadata() {
    cat > "$RUN_DIR/metadata.txt" <<EOF
XamlTech Nmap Toolkit
=====================
Toolkit version : $SCRIPT_VERSION
Author          : $AUTHOR
Started         : $(timestamp)
Target          : $TARGET
Profile         : $PROFILE
Nmap binary     : $NMAP_BIN
Nmap version    : $(nmap_version)
Root            : $(is_root && echo yes || echo no)
EOF
}

write_summary() {
    local duration
    duration=$(( $(date +%s) - START_EPOCH ))

    {
        printf '%s\n' "XamlTech Nmap Toolkit - Run Summary"
        printf '%s\n' "=================================="
        printf 'Target       : %s\n' "$TARGET"
        printf 'Profile      : %s\n' "$PROFILE"
        printf 'Started      : %s\n' "$(cat "$RUN_DIR/metadata.txt" | awk -F': ' '/^Started/ {print $2}')"
        printf 'Finished     : %s\n' "$(timestamp)"
        printf 'Duration     : %ss\n' "$duration"
        printf 'Nmap version : %s\n' "$(nmap_version)"
        printf '\nOutput files:\n'
        find "$RUN_DIR" -maxdepth 1 -type f -printf '  %f\n' | sort
    } > "$RUN_DIR/summary.txt"
}

# ---------- Host inventory ----------

extract_hosts() {
    # Nmap XML is the reliable machine-readable source.
    if [[ -f "$RUN_DIR/nmap.xml" ]]; then
        awk '
            /<host / { up=1 }
            /<status state="up"/ { state="up" }
            /<status state="down"/ { state="down" }
            /<address addr="/ {
                if (match($0, /addr="[^"]+"/)) {
                    v=substr($0, RSTART+6, RLENGTH-7)
                    if (v !~ /:/ && v != "") print state, v
                }
            }
            /<\/host>/ {
                state=""
                up=0
            }
        ' "$RUN_DIR/nmap.xml" | awk '
            $1=="up" {print $2}
        ' | sort -V -u > "$RUN_DIR/hosts-up.txt" || true

    fi
}

latency_probe() {
    local host="$1"
    if command_exists ping; then
        local result
        result="$(ping -n -c 1 -W 1 "$host" 2>/dev/null || true)"
        awk -F'time=' '/time=/{split($2,a," "); print a[1]" ms"; found=1} END{if(!found) print "no reply"}' <<< "$result"
    else
        printf '%s\n' "ping unavailable"
    fi
}

generate_host_report() {
    [[ -s "$RUN_DIR/hosts-up.txt" ]] || return 0
    {
        printf '%s\n' "Reachable Hosts"
        printf '%s\n' "==============="
        printf '%-40s %s\n' "HOST" "LATENCY"
        printf '%-40s %s\n' "----------------------------------------" "--------"
        while IFS= read -r host; do
            printf '%-40s %s\n' "$host" "$(latency_probe "$host")"
        done < "$RUN_DIR/hosts-up.txt"
    } | tee "$RUN_DIR/host-latency.txt"
}

# ---------- Scan ----------

run_scan() {
    validate_target "$TARGET"
    validate_profile "$PROFILE"
    build_nmap_args "$PROFILE"
    prepare_run_dir
    write_metadata

    local cmd_display
    cmd_display="$(printf ' %q' "$NMAP_BIN" "${NMAP_ARGS[@]}" "$TARGET")"

    printf '\n'
    printf '%s\n' 'Scan Configuration'
    printf '%s\n' '────────────────────────────────────────────────────'
    printf 'Target  : %s\n' "$TARGET"
    printf 'Profile : %s\n' "$PROFILE"
    printf 'Output  : %s\n' "$RUN_DIR"
    printf 'Command :%s\n\n' "$cmd_display"

    if needs_root_for_profile "$PROFILE" && ! is_root; then
        warn "Profile '$PROFILE' may produce better results with root privileges."
        warn "The toolkit will run without sudo unless you restart it as root."
    fi

    confirm "Run this scan?" || { info "Cancelled."; return 0; }

    START_EPOCH="$(date +%s)"
    {
        printf '%s\n' "XamlTech Nmap Toolkit"
        printf 'Started: %s\n' "$(timestamp)"
        printf 'Command:%s\n\n' "$cmd_display"
        "$NMAP_BIN" "${NMAP_ARGS[@]}" -oX "$RUN_DIR/nmap.xml" "$TARGET"
    } 2>&1 | tee "$RUN_DIR/nmap.txt"

    extract_hosts
    generate_host_report
    write_summary

    printf '\n'
    ok "Scan completed."
    printf 'Results: %s\n' "$RUN_DIR"
}

# ---------- Interactive UI ----------

choose_target() {
    printf '%s\n' "Target"
    printf '%s\n' "────────────────────────────────────────────"
    printf 'Examples:\n'
    printf '  192.168.1.1\n'
    printf '  192.168.1.0/24\n'
    printf '  192.168.1.1-254\n'
    printf '  router.local\n\n'
    read -r -p "Enter target: " TARGET
    validate_target "$TARGET"
}

choose_profile() {
    printf '\n%s\n' "Scan Profile"
    printf '%s\n' "────────────────────────────────────────────"
    printf '  1) Discovery   Host discovery only\n'
    printf '  2) Quick       Fast top-100 TCP ports\n'
    printf '  3) Standard    Top-1000 + service/version\n'
    printf '  4) Deep        All TCP ports + service/version\n'
    printf '  5) OS          All TCP ports + service + OS\n'
    printf '  6) Diagnostic  Discovery + traceroute\n'
    printf '  7) Custom      Your Nmap arguments\n\n'

    local choice
    read -r -p "Select profile [1-7]: " choice
    case "$choice" in
        1) PROFILE=discovery ;;
        2) PROFILE=quick ;;
        3) PROFILE=standard ;;
        4) PROFILE=deep ;;
        5) PROFILE=os ;;
        6) PROFILE=diagnostic ;;
        7)
            PROFILE=custom
            read -r -p 'Nmap arguments: ' custom
            # Word splitting is intentional here because this is an interactive
            # argument line. It is never concatenated into a shell command.
            read -r -a CUSTOM_ARGS <<< "$custom"
            ;;
        *) die "Invalid profile." ;;
    esac
}

interactive_mode() {
    banner
    check_dependencies
    printf '\n'
    if confirm "Check Nmap update information first?"; then
        check_updates
    fi

    choose_target
    choose_profile

    printf '\n'
    printf '%s\n' 'Authorization Notice'
    printf '%s\n' '────────────────────────────────────────────'
    warn "Scan only hosts/networks you own or are authorized to test."
    confirm "I understand and want to continue." || { info "Cancelled."; return 0; }

    run_scan
}

# ---------- Argument parsing ----------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                TARGET="$2"; shift 2 ;;
            -p|--profile)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                PROFILE="$2"; shift 2 ;;
            -o|--output)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                OUTPUT_DIR="$2"; shift 2 ;;
            -a|--args)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                read -r -a CUSTOM_ARGS <<< "$2"
                shift 2 ;;
            -v|--verbose)
                VERBOSE=1; shift ;;
            -y|--yes)
                ASSUME_YES=1; shift ;;
            --check-updates)
                check_dependencies
                check_updates
                exit 0 ;;
            --version)
                printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
                exit 0 ;;
            -h|--help)
                usage
                exit 0 ;;
            --)
                shift
                CUSTOM_ARGS=("$@")
                break ;;
            *)
                die "Unknown option: $1. Use --help." ;;
        esac
    done
}

main() {
    require_basic_tools
    parse_args "$@"
    detect_nmap

    if [[ "$PROFILE" == "interactive" || -z "$TARGET" ]]; then
        interactive_mode
    else
        validate_profile "$PROFILE"
        check_dependencies
        run_scan
    fi
}

main "$@"
