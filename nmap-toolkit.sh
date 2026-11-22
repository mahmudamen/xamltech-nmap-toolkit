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
SCRIPT_VERSION=""
readonly AUTHOR="Mahmoud Mohamed Amin"
readonly GITHUB_USER="mahmudamen"
readonly WEBSITE="https://xamltech.com"

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
TOOLKIT_HOME="${XAMLTECH_NMAP_HOME:-$(dirname "$SCRIPT_PATH")}"
LIB_DIR="$TOOLKIT_HOME/lib"
SCRIPTS_DIR="$TOOLKIT_HOME/scripts"
readonly SCRIPT_PATH TOOLKIT_HOME LIB_DIR SCRIPTS_DIR
SCRIPT_VERSION="$(python3 -I "$LIB_DIR/report.py" version 2>/dev/null || printf '2.5.0')"
readonly SCRIPT_VERSION
ORIGINAL_ARGS=("$@")

for _lib in options ui core nse profiles projects scan interactive; do
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
PING_LATENCY=1; OPEN_REPORT=1; NOTIFY=0
VERBOSE=0; ASSUME_YES=0; DRY_RUN=0; AUTHORIZED=0; USE_SUDO=0; NO_BANNER=0; ONLINE_CHECK=0
CUSTOM_ARGS=()
ACTION=""; ACTION_ARG1=""; ACTION_ARG2=""
TARGET_CLASS=""
CONFIG_FILE=""
DEFAULT_PROFILE="standard"
INTERACTIVE_SESSION=0
POLICY="strict"
ACK_RISK=0
EXPLAIN=0
STAGE=""
RESUME_DIR=""
INCREMENTAL_BASELINE=""
JSON_PLAN=0
PLAN_FILE=""
PLAN_HASH_EXPECTED=""
PLAN_JSON=""
PLAN_HASH=""
PROJECT_NAME=""
PROJECT_INFO=""
PROJECT_GOALS=""
PROJECT_STEP=""
PROJECT_STATUS=""
PROJECT_NOTE=""
PROJECT_ARGS=""
PROJECT_GOAL_TEXT=""

# ---------- help ----------

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME} ${SCRIPT_VERSION}${C_RESET}
Authorized network discovery, diagnostics and NSE intelligence powered by Nmap.

${C_ACCENT}${C_BOLD}USAGE${C_RESET}
  $(basename "$0") [OPTIONS]                      interactive menu
  $(basename "$0") -t TARGET -p PROFILE [OPTIONS] scan directly

EOF
    options_emit_help
    cat <<EOF

${C_ACCENT}${C_BOLD}EXAMPLES${C_RESET}
  $(basename "$0")                                              ${C_GRAY}# guided menu${C_RESET}
  $(basename "$0") -t 192.168.1.0/24 -p discovery
  $(basename "$0") -t 192.168.1.0/24 -p recon              ${C_GRAY}# staged discovery${C_RESET}
  $(basename "$0") -t 192.168.1.0/24 -p mynetwork --open   ${C_GRAY}# local network review${C_RESET}
  $(basename "$0") -t 10.0.0.5 -p tls --ports 443,8443
  $(basename "$0") -t 10.0.0.0/24 -p audit --scope scope.txt --sudo
  $(basename "$0") -t 192.168.1.1 -p custom -a "-sV --top-ports 100"
  $(basename "$0") --diff results/<old> latest

${C_GRAY}Scan only systems and networks you own or are explicitly authorized to test.${C_RESET}
EOF
}

# ---------- argument parsing ----------

need_val() { [[ $2 -ge 2 ]] || die "Missing value for $1"; }

build_plan_json() {
    python3 - "$SCRIPT_VERSION" "$PROFILE" "$POLICY" "$TIMING" "$PORTS" \
        "${REPORT_FORMATS:-}" "${SCOPE_FILE:-}" "${TARGETS[@]}" <<'PY'
import hashlib, json, sys
(version, profile, policy, timing, ports, formats, scope, *targets) = sys.argv[1:]
plan = {"tool": "xamltech-nmap-toolkit", "version": version, "profile": profile,
        "policy": policy, "timing": timing, "ports": ports,
        "formats": [x for x in formats.split(",") if x], "scope": scope,
        "targets": sorted(targets)}
print(json.dumps(plan, sort_keys=True, separators=(",", ":")))
PY
}

plan_hash_file() {
    python3 - "$1" <<'PY'
import hashlib, json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
data.pop("plan_hash", None)
if "plan" in data and isinstance(data["plan"], dict):
    data = data["plan"]
print(hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
PY
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        if [[ "$1" != "--" ]]; then
            option_check_flag "$1" || DIE_CODE=2 die "Unknown option: $1. Use --help."
            local val vkind attached=""
            val="$(option_lookup "$1" validator || true)"
            vkind="$(option_lookup "$1" value || true)"
            attached="$(opt_attached_value "$1" || true)"
            if [[ -n "$attached" ]]; then
                [[ -z "$val" ]] || option_validate "$1" "$attached"
                opt_store_override "$1" "$attached"
                [[ "$(option_lookup "$1" canonical)" != --timing ]] || TIMING="$attached"
            else
                if [[ -n "$val" && "$vkind" != none && $# -ge 2 && "${2:-}" != -* ]]; then
                    option_validate "$1" "$2"
                fi
                if [[ "$vkind" != none && $# -ge 2 && "${2:-}" != -* ]]; then
                    opt_store_override "$1" "$2"
                else
                    opt_store_override "$1"
                fi
            fi
        fi
        case "$1" in
            -t|--target)      need_val "$1" $#; append_targets "$2"; shift 2 ;;
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
            --no-open)        OPEN_REPORT=0; shift ;;
            --notify)         NOTIFY=1; shift ;;
            --no-color)       COLOR_MODE=never; shift ;;
            --color)          COLOR_MODE=always; shift ;;
            --no-banner)      NO_BANNER=1; shift ;;
            --authorized)     AUTHORIZED=1; shift ;;
            --json)           JSON_PLAN=1; shift ;;
            --plan-file)      need_val "$1" $#; PLAN_FILE="$2"; shift 2 ;;
            --plan-hash)      need_val "$1" $#; PLAN_HASH_EXPECTED="$2"; shift 2 ;;
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
            --policy)         need_val "$1" $#; POLICY="$2"; shift 2 ;;
            --ack-risk)       ACK_RISK=1; shift ;;
            --explain)        EXPLAIN=1; shift ;;
            --dump-options)   ACTION=dump-options; shift ;;
            --script-updatedb) ACTION=script-updatedb; shift ;;
            --stage)          need_val "$1" $#; STAGE="$2"; shift 2 ;;
            --resume)         need_val "$1" $#; RESUME_DIR="$2"; shift 2 ;;
            --incremental)    need_val "$1" $#; INCREMENTAL_BASELINE="$2"; shift 2 ;;
            --target-group)   need_val "$1" $#; shift 2 ;;
            --save-preset)    need_val "$1" $#; shift 2 ;;
            --preset)         need_val "$1" $#; shift 2 ;;
            --replay)         need_val "$1" $#; shift 2 ;;
            --project)        need_val "$1" $#; PROJECT_NAME="$2"; shift 2 ;;
            --project-create) need_val "$1" $#; ACTION=project-create; PROJECT_NAME="$2"; shift 2 ;;
            --project-info)   need_val "$1" $#; PROJECT_INFO="$2"; shift 2 ;;
            --project-goals)  need_val "$1" $#; PROJECT_GOALS="$2"; shift 2 ;;
            --project-list)   ACTION=project-list; shift ;;
            --project-show)   need_val "$1" $#; ACTION=project-show; PROJECT_NAME="$2"; shift 2 ;;
            --project-step-add) need_val "$1" $#; ACTION=project-step-add; PROJECT_NAME="$2"; shift 2 ;;
            --project-step)   need_val "$1" $#; PROJECT_STEP="$2"; shift 2 ;;
            --goal)           need_val "$1" $#; PROJECT_GOAL_TEXT="$2"; shift 2 ;;
            --project-args)   need_val "$1" $#; PROJECT_ARGS="$2"; shift 2 ;;
            --project-step-status)
                [[ $# -ge 3 ]] || die "Missing value for $1"
                ACTION=project-step-status; PROJECT_NAME="$2"
                [[ "$3" == *=* ]] || DIE_CODE=2 die "--project-step-status needs STEP=STATUS"
                PROJECT_STEP="${3%%=*}"; PROJECT_STATUS="${3#*=}"; shift 3 ;;
            --note)           need_val "$1" $#; PROJECT_NOTE="$2"; shift 2 ;;
            --project-resume) need_val "$1" $#; PROJECT_NAME="$2"; shift 2 ;;
            --estimate)       ACTION=estimate; shift ;;
            --version)        ACTION=version; shift ;;
            -h|--help)        ACTION=help; shift ;;
            --)               shift; CUSTOM_ARGS=("$@"); break ;;
            *)
                if option_check_flag "$1"; then
                    if [[ -n "$(opt_attached_value "$1" || true)" ]]; then
                        shift
                    elif [[ "$(option_lookup "$1" value)" != none && $# -ge 2 && "${2:-}" != -* ]]; then
                        shift 2
                    else
                        shift
                    fi
                else
                    DIE_CODE=2 die "Unknown option: $1. Use --help."
                fi ;;
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
    trap on_exit EXIT
    trap on_interrupt INT TERM

    # config files: system, user, project, then --config
    local cfg i
    for cfg in /etc/xamltech-nmap-toolkit.conf "${XDG_CONFIG_HOME:-$HOME/.config}/xamltech-nmap-toolkit/config" ./.xamltech-nmap.conf; do
        load_config "$cfg"
    done
    local -a argv=("$@") expanded=()
    local preset_depth=0 group_name save_name
    for (( i = 0; i < ${#argv[@]}; i++ )); do
        if [[ "${argv[i]}" == --config ]]; then
            [[ -n "${argv[i+1]:-}" ]] || die "Missing value for --config"
            CONFIG_FILE="${argv[i+1]}"
            [[ -r "$CONFIG_FILE" ]] || die "Cannot read config file: $CONFIG_FILE"
            load_config "$CONFIG_FILE"
        fi
    done
    while :; do
        expanded=()
        local found=0
        for (( i = 0; i < ${#argv[@]}; i++ )); do
            if [[ "${argv[i]}" == --preset ]]; then
                [[ -n "${argv[i+1]:-}" ]] || die "Missing value for --preset"
                preset_depth=$(( preset_depth + 1 ))
                (( preset_depth <= 10 )) || die "Preset expansion too deep"
                load_preset "${argv[i+1]}"
                (( i == 0 )) || expanded+=("${argv[@]:0:i}")
                expanded+=("${STORAGE_ARGV[@]}")
                (( i + 1 >= ${#argv[@]} )) || expanded+=("${argv[@]:i+2}")
                argv=("${expanded[@]}")
                found=1
                break
            fi
        done
        (( found )) || break
    done
    local project_depth=0 pout pname
    while :; do
        local project_found=0
        for (( i = 0; i < ${#argv[@]}; i++ )); do
            if [[ "${argv[i]}" == --project-resume ]]; then
                [[ -n "${argv[i+1]:-}" ]] || die "Missing value for --project-resume"
                pname="${argv[i+1]}"
                project_depth=$(( project_depth + 1 ))
                (( project_depth <= 10 )) || die "Project resume expansion too deep"
                pout="$(project_resume_args "$pname")" || die "Cannot resume project '$pname'"
                [[ -n "$pout" ]] || die "Project '$pname' has no arguments to resume"
                local -a pexpanded=()
                mapfile -t pexpanded <<< "$pout"
                expanded=()
                (( i == 0 )) || expanded+=("${argv[@]:0:i}")
                expanded+=("${pexpanded[@]}")
                (( i + 1 >= ${#argv[@]} )) || expanded+=("${argv[@]:i+2}")
                argv=("${expanded[@]}")
                project_found=1
                break
            fi
        done
        (( project_found )) || break
    done
    for (( i = 0; i < ${#argv[@]}; i++ )); do
        if [[ "${argv[i]}" == --replay ]]; then
            [[ -n "${argv[i+1]:-}" ]] || die "Missing value for --replay"
            load_history_entry "${argv[i+1]}"
            argv=("${STORAGE_ARGV[@]}")
            break
        fi
    done
    expanded=()
    for (( i = 0; i < ${#argv[@]}; i++ )); do
        if [[ "${argv[i]}" == --target-group ]]; then
            [[ -n "${argv[i+1]:-}" ]] || die "Missing value for --target-group"
            group_name="${argv[i+1]}"
            option_validate --target-group "$group_name"
            expand_target_group "$group_name"
            i=$(( i + 1 ))
        else
            expanded+=("${argv[i]}")
        fi
    done
    argv=("${expanded[@]}")
    expanded=()
    for (( i = 0; i < ${#argv[@]}; i++ )); do
        if [[ "${argv[i]}" == --save-preset ]]; then
            [[ -n "${argv[i+1]:-}" ]] || die "Missing value for --save-preset"
            save_name="${argv[i+1]}"
            option_validate --save-preset "$save_name"
            i=$(( i + 1 ))
        else
            expanded+=("${argv[i]}")
        fi
    done
    argv=("${expanded[@]}")
    [[ -z "${save_name:-}" ]] || { save_preset "$save_name" "${argv[@]}"; info "Saved preset '$save_name'."; }

    parse_args "${argv[@]}"
    case "$ACTION" in
        project-create)
            [[ -n "$PROJECT_INFO" ]] || DIE_CODE=2 die "--project-create requires --project-info"
            project_create "$PROJECT_NAME" "$PROJECT_INFO" "$PROJECT_GOALS"
            return 0 ;;
        project-list)    project_list; return 0 ;;
        project-show)    project_show "$PROJECT_NAME"; return 0 ;;
        project-step-add)
            [[ -n "$PROJECT_STEP" && -n "$PROJECT_GOAL_TEXT" ]] \
                || DIE_CODE=2 die "--project-step-add requires --project-step and --goal"
            project_add_step "$PROJECT_NAME" "$PROJECT_STEP" "$PROJECT_GOAL_TEXT" "$PROJECT_ARGS"
            return 0 ;;
        project-step-status)
            project_set_step "$PROJECT_NAME" "$PROJECT_STEP" "$PROJECT_STATUS" "$PROJECT_NOTE"
            return 0 ;;
    esac
    if [[ -n "${OVERRIDE_VALUES[--packet-trace]+x}" ]] && (( ! VERBOSE )); then
        DIE_CODE=2 die "--packet-trace requires --verbose."
    fi
    enforce_policy
    [[ -z "$STAGE" || "$STAGE" == discovery || "$STAGE" == ports || "$STAGE" == services ]] \
        || DIE_CODE=2 die "--stage must be discovery, ports or services."
    [[ -z "$RESUME_DIR" ]] || workflow_exists "$PROFILE" \
        || DIE_CODE=2 die "--resume requires a workflow profile."
    [[ -z "$INCREMENTAL_BASELINE" || -r "$INCREMENTAL_BASELINE" ]] \
        || DIE_CODE=2 die "Cannot read baseline report: $INCREMENTAL_BASELINE"
    PLAN_JSON=""
    PLAN_HASH=""
    if (( JSON_PLAN )) || [[ -n "$PLAN_FILE" ]]; then
        command_exists python3 || DIE_CODE=3 die "python3 is required for JSON plans."
        PLAN_JSON="$(build_plan_json)"
        PLAN_HASH="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$PLAN_JSON")"
    fi
    if [[ -n "$PLAN_FILE" ]]; then
        [[ -r "$PLAN_FILE" ]] || DIE_CODE=4 die "Cannot read plan file: $PLAN_FILE"
        [[ -n "$PLAN_HASH_EXPECTED" ]] || DIE_CODE=4 die "--plan-file requires --plan-hash."
        local actual
        actual="$(plan_hash_file "$PLAN_FILE")" || DIE_CODE=4 die "Invalid plan file."
        [[ "$actual" == "$PLAN_HASH_EXPECTED" ]] || DIE_CODE=4 die "Plan hash mismatch."
        info "Approved plan verified ($actual)."
    fi
    if (( DRY_RUN && JSON_PLAN )); then
        printf '{"plan":%s,"plan_hash":"%s"}\n' "$PLAN_JSON" "$PLAN_HASH"
        return 0
    fi
    require_basic_tools
    ui_init
    ui_theme "$THEME" || die "Unknown theme '$THEME' (use: $(ui_themes | paste -sd' '))"
    ui_define_colors

    case "$ACTION" in
        version)       printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; return 0 ;;
        help)          usage; return 0 ;;
        dump-options)  options_emit_json; return 0 ;;
        script-updatedb) script_updatedb; return 0 ;;
        list-profiles) list_profiles; return 0 ;;
        history)       show_history; return 0 ;;
        diff)          diff_runs "$ACTION_ARG1" "$ACTION_ARG2"; return 0 ;;
        export)        export_run "$ACTION_ARG1" "${ACTION_ARG2:-latest}"; return 0 ;;
        open-report)   open_report "${ACTION_ARG1:-latest}"; return 0 ;;
        doctor)        (( NO_BANNER )) || banner; doctor; return 0 ;;
        estimate)      (( NO_BANNER )) || banner; estimate_plan; return 0 ;;
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
    (( DRY_RUN )) || append_history "${argv[@]}"
    run_scan
}

main "$@"
