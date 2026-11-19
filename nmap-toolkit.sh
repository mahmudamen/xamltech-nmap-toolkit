#!/usr/bin/env bash
#
# XamlTech Nmap Toolkit
# Authorized network discovery, diagnostics and NSE intelligence for Linux.
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
readonly SCRIPT_VERSION="2.0.0"
readonly AUTHOR="Mahmoud Mohamed Amin"
readonly GITHUB_USER="mahmudamen"
readonly WEBSITE="https://xamltech.com"

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
TOOLKIT_HOME="${XAMLTECH_NMAP_HOME:-$(dirname "$SCRIPT_PATH")}"
LIB_DIR="$TOOLKIT_HOME/lib"
SCRIPTS_DIR="$TOOLKIT_HOME/scripts"
readonly SCRIPT_PATH TOOLKIT_HOME LIB_DIR SCRIPTS_DIR
ORIGINAL_ARGS=("$@")

for _lib in ui core nse profiles scan interactive; do
    [[ -r "$LIB_DIR/$_lib.sh" ]] || { echo "xamltech-nmap-toolkit: missing $LIB_DIR/$_lib.sh" >&2; exit 3; }
    # shellcheck source=/dev/null
    source "$LIB_DIR/$_lib.sh"
done
unset _lib

# ---------- defaults (config files and CLI flags override) ----------

PROFILE=""
OUTPUT_DIR="./results"
THEME="cyber"
COLOR_MODE="auto"
REPORT_FORMATS="json,csv,md,html"
SCOPE_FILE=""
TIMING=""; PORTS=""; TOP_PORTS=""; EXTRA_SCRIPTS=""; SCRIPT_ARGS=""
MAX_RATE=""; MAX_RETRIES=""; HOST_TIMEOUT=""; DNS_SERVERS=""; IFACE=""; EXCLUDE=""
NO_PING=0; NO_DNS=0; IPV6=0; EXTRA_VERBOSE=0
PING_LATENCY=1; OPEN_REPORT=0; NOTIFY=0
VERBOSE=0; ASSUME_YES=0; DRY_RUN=0; AUTHORIZED=0; USE_SUDO=0; NO_BANNER=0; ONLINE_CHECK=0
CUSTOM_ARGS=()
ACTION=""; ACTION_ARG1=""; ACTION_ARG2=""
TARGET_CLASS=""
CONFIG_FILE=""
DEFAULT_PROFILE="standard"
INTERACTIVE_SESSION=0

# ---------- help ----------

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME} ${SCRIPT_VERSION}${C_RESET}
Authorized network discovery, diagnostics and NSE intelligence powered by Nmap.

${C_ACCENT}${C_BOLD}USAGE${C_RESET}
  $(basename "$0") [OPTIONS]                      interactive menu
  $(basename "$0") -t TARGET -p PROFILE [OPTIONS] scan directly

${C_ACCENT}${C_BOLD}TARGETS${C_RESET}
  -t, --target TARGET       Host, hostname, CIDR, range (192.168.1.1-254); repeatable / space separated
  -L, --target-file FILE    Read targets from file (one per line, # comments)
      --exclude LIST        Exclude hosts/networks
      --scope FILE          Authorized scope file; refuse anything outside it

${C_ACCENT}${C_BOLD}PROFILES${C_RESET}
  -p, --profile NAME        See --list-profiles (${#PROFILE_TABLE[@]} profiles + recon/inventory workflows)
  -a, --args "ARGS"         Arguments for the 'custom' profile (quote-aware)

${C_ACCENT}${C_BOLD}TUNING${C_RESET}
  -T, --timing 0-5          Nmap timing template        --ports SPEC        e.g. 22,80,443 or T:22,U:53
      --top-ports N         Most common N ports         --scripts LIST      Extra NSE scripts (names/paths)
      --script-args K=V     NSE script arguments        --max-rate N        Max packets/second
      --max-retries N       Probe retransmissions       --host-timeout 5m   Give up on slow hosts
      --dns-servers LIST    Custom resolvers            -e, --interface IF  Network interface
      --no-ping, -Pn        Treat hosts as up           --no-dns, -n        Skip DNS resolution
  -6, --ipv6                IPv6 scanning

${C_ACCENT}${C_BOLD}OUTPUT${C_RESET}
  -o, --output DIR          Result directory (default: ./results)
      --formats LIST        json,csv,md,html (default: all)
      --open                Open the HTML report when done
      --notify              Terminal bell / desktop notification when done
      --no-latency          Skip the parallel ping latency table
      --theme NAME          cyber ocean sunset matrix aurora mono
      --no-color, --color   Force colors off/on        --no-banner   Hide the headline

${C_ACCENT}${C_BOLD}SAFETY${C_RESET}
      --authorized          Confirm authorization for non-private targets (required in non-interactive mode)
      --dry-run             Show the plan and exact Nmap command, run nothing
      --sudo                Re-run this toolkit through sudo (raw-socket scans)
  -y, --yes                 Skip confirmation prompts

${C_ACCENT}${C_BOLD}TOOLS${C_RESET}
      --list-profiles       Show every profile with risk/root/speed
      --list-scripts [F]    Browse local NSE scripts (filter by name/category)
      --script-help NAME    Show NSE script documentation
      --history             List previous runs
      --diff A B            Compare two runs (dir name, path or 'latest')
      --open-report [RUN]   Open an HTML report (default: latest)
      --export KIND [RUN]   Handoff list: urls | hostports | hosts | ports | openvas
                            (feed ZAP/Burp, Masscan, OpenVAS/Nessus - see docs/INTEGRATIONS.md)
      --doctor              Check your environment
      --check-updates       Nmap version information (add --online to query nmap.org)
      --config FILE         Load an extra config file
  -v, --verbose             Debug output        --version   Print version     -h, --help   This help

${C_ACCENT}${C_BOLD}EXAMPLES${C_RESET}
  $(basename "$0")                                              ${C_GRAY}# guided menu${C_RESET}
  $(basename "$0") -t 192.168.1.0/24 -p discovery
  $(basename "$0") -t 192.168.1.0/24 -p recon                    ${C_GRAY}# discover -> ports -> services${C_RESET}
  $(basename "$0") -t erp.lan -p odoo --open                     ${C_GRAY}# Odoo exposure review${C_RESET}
  $(basename "$0") -t 10.0.0.5 -p tls --ports 443,8443
  $(basename "$0") -t 10.0.0.0/24 -p audit --scope scope.txt --sudo
  $(basename "$0") -t 192.168.1.1 -p custom -a "-sV --top-ports 100"
  $(basename "$0") --diff results/<old> latest

${C_GRAY}Scan only systems and networks you own or are explicitly authorized to test.${C_RESET}
EOF
}

# ---------- argument parsing ----------

need_val() { [[ $2 -ge 2 ]] || die "Missing value for $1"; }

parse_args() {
    local t
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)      need_val "$1" $#; for t in $2; do validate_target_token "$t"; TARGETS+=("$t"); done; shift 2 ;;
            -L|--target-file) need_val "$1" $#; load_targets_file "$2"; shift 2 ;;
            -p|--profile)     need_val "$1" $#; PROFILE="$2"; shift 2 ;;
            -o|--output)      need_val "$1" $#; OUTPUT_DIR="$2"; shift 2 ;;
            -a|--args)        need_val "$1" $#; split_args "$2"; CUSTOM_ARGS=("${SPLIT_RESULT[@]}"); shift 2 ;;
            -T|--timing)      need_val "$1" $#; TIMING="$2"; shift 2 ;;
            --ports)          need_val "$1" $#; PORTS="$2"; shift 2 ;;
            --top-ports)      need_val "$1" $#; TOP_PORTS="$2"; shift 2 ;;
            --scripts)        need_val "$1" $#; EXTRA_SCRIPTS="$2"; shift 2 ;;
            --script-args)    need_val "$1" $#; SCRIPT_ARGS="$2"; shift 2 ;;
            --max-rate)       need_val "$1" $#; MAX_RATE="$2"; shift 2 ;;
            --max-retries)    need_val "$1" $#; MAX_RETRIES="$2"; shift 2 ;;
            --host-timeout)   need_val "$1" $#; HOST_TIMEOUT="$2"; shift 2 ;;
            --dns-servers)    need_val "$1" $#; DNS_SERVERS="$2"; shift 2 ;;
            -e|--interface)   need_val "$1" $#; IFACE="$2"; shift 2 ;;
            --exclude)        need_val "$1" $#; EXCLUDE="$2"; shift 2 ;;
            --scope)          need_val "$1" $#; SCOPE_FILE="$2"; shift 2 ;;
            --formats)        need_val "$1" $#; REPORT_FORMATS="$2"; shift 2 ;;
            --theme)          need_val "$1" $#; THEME="$2"; shift 2 ;;
            --config)         need_val "$1" $#; shift 2 ;;   # handled in pre-scan
            --no-ping|-Pn)    NO_PING=1; shift ;;
            --no-dns|-n)      NO_DNS=1; shift ;;
            -6|--ipv6)        IPV6=1; shift ;;
            --no-latency)     PING_LATENCY=0; shift ;;
            --open)           OPEN_REPORT=1; shift ;;
            --notify)         NOTIFY=1; shift ;;
            --no-color)       COLOR_MODE=never; shift ;;
            --color)          COLOR_MODE=always; shift ;;
            --no-banner)      NO_BANNER=1; shift ;;
            --authorized)     AUTHORIZED=1; shift ;;
            --dry-run)        DRY_RUN=1; shift ;;
            --sudo)           USE_SUDO=1; shift ;;
            --online)         ONLINE_CHECK=1; shift ;;
            -v|--verbose)     VERBOSE=1; shift ;;
            -y|--yes)         ASSUME_YES=1; shift ;;
            --list-profiles)  ACTION=list-profiles; shift ;;
            --list-scripts)
                ACTION=list-scripts; shift
                if [[ $# -gt 0 && "$1" != -* ]]; then ACTION_ARG1="$1"; shift; fi ;;
            --script-help)    need_val "$1" $#; ACTION=script-help; ACTION_ARG1="$2"; shift 2 ;;
            --history)        ACTION=history; shift ;;
            --diff)           [[ $# -ge 3 ]] || die "--diff needs two runs"; ACTION="diff"; ACTION_ARG1="$2"; ACTION_ARG2="$3"; shift 3 ;;
            --open-report)
                ACTION=open-report; shift
                if [[ $# -gt 0 && "$1" != -* ]]; then ACTION_ARG1="$1"; shift; fi ;;
            --export)         [[ $# -ge 2 ]] || die "--export needs a kind"; ACTION="export"; ACTION_ARG1="$2"; shift 2
                              if [[ $# -gt 0 && "$1" != -* ]]; then ACTION_ARG2="$1"; shift; fi ;;
            --doctor)         ACTION=doctor; shift ;;
            --check-updates)  ACTION=check-updates; shift ;;
            --version)        ACTION=version; shift ;;
            -h|--help)        ACTION=help; shift ;;
            --)               shift; CUSTOM_ARGS=("$@"); break ;;
            *)                DIE_CODE=2 die "Unknown option: $1. Use --help." ;;
        esac
    done
}

# ---------- cleanup ----------

on_exit() {
    local rc=$?
    spin_stop 2>/dev/null || true
    cursor_show 2>/dev/null || true
    printf '%s' "${C_RESET:-}"
    return "$rc"
}

on_interrupt() {
    spin_stop 2>/dev/null || true
    cursor_show 2>/dev/null || true
    printf '\n'
    warn "Interrupted."
    if [[ -n "${RUN_DIR:-}" && -d "${RUN_DIR:-}" ]]; then
        hint "Partial results kept in: $RUN_DIR"
        hint "Native Nmap logs written so far are kept; re-run the profile for full reports."
        fix_ownership 2>/dev/null || true
    fi
    exit 130
}

# ---------- main ----------

main() {
    ui_init
    trap on_exit EXIT
    trap on_interrupt INT TERM
    require_basic_tools

    # config files: system, user, project, then --config
    local cfg i
    for cfg in /etc/xamltech-nmap-toolkit.conf "${XDG_CONFIG_HOME:-$HOME/.config}/xamltech-nmap-toolkit/config" ./.xamltech-nmap.conf; do
        load_config "$cfg"
    done
    local -a argv=("$@")
    for (( i = 0; i < ${#argv[@]}; i++ )); do
        if [[ "${argv[i]}" == --config ]]; then
            [[ -n "${argv[i+1]:-}" ]] || die "Missing value for --config"
            CONFIG_FILE="${argv[i+1]}"
            [[ -r "$CONFIG_FILE" ]] || die "Cannot read config file: $CONFIG_FILE"
            load_config "$CONFIG_FILE"
        fi
    done

    parse_args "$@"
    ui_init
    ui_theme "$THEME" || die "Unknown theme '$THEME' (use: $(ui_themes | paste -sd' '))"
    ui_define_colors

    case "$ACTION" in
        version)       printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; return 0 ;;
        help)          usage; return 0 ;;
        list-profiles) list_profiles; return 0 ;;
        history)       show_history; return 0 ;;
        diff)          diff_runs "$ACTION_ARG1" "$ACTION_ARG2"; return 0 ;;
        export)        export_run "$ACTION_ARG1" "${ACTION_ARG2:-latest}"; return 0 ;;
        open-report)   open_report "${ACTION_ARG1:-latest}"; return 0 ;;
        doctor)        (( NO_BANNER )) || banner; doctor; return 0 ;;
    esac

    detect_nmap
    case "$ACTION" in
        list-scripts)    nse_list "$ACTION_ARG1"; return 0 ;;
        script-help)     nse_help "$ACTION_ARG1"; return 0 ;;
        check-updates)   (( NO_BANNER )) || banner; check_dependencies; check_updates; return 0 ;;
    esac

    if (( USE_SUDO )) && ! is_root; then reexec_with_sudo; fi
    mkdir -p "$OUTPUT_DIR"

    # No target and no explicit non-interactive profile -> interactive menu
    if [[ ${#TARGETS[@]} -eq 0 && "$PROFILE" != broadcast ]]; then
        if [[ ! -t 0 ]]; then
            DIE_CODE=2 die "No target given and stdin is not a terminal. Use -t TARGET -p PROFILE (see --help)."
        fi
        INTERACTIVE_SESSION=1
        interactive_mode
        return 0
    fi

    [[ -n "$PROFILE" ]] || PROFILE="$DEFAULT_PROFILE"
    validate_profile "$PROFILE"
    (( NO_BANNER )) || banner
    env_line
    enforce_scope
    authorization_gate || return 0
    run_scan
}

main "$@"
