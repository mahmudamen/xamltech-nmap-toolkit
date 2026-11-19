# shellcheck shell=bash
# XamlTech Nmap Toolkit - terminal UI primitives
# Colors (truecolor / 256 / none), gradient banner, themes, menus, spinner,
# progress bar, boxes. Sourced by nmap-toolkit.sh - never executed directly.

UI_COLOR=0
UI_TRUECOLOR=0
UI_UTF8=0
UI_TTY=0
UI_COLS=80
SPIN_PID=""
CURSOR_HIDDEN=0

# Theme: gradient start RGB, gradient end RGB, accent RGB
THEME_NAME="cyber"
TH_S="0 229 255"     # gradient start
TH_E="187 0 255"     # gradient end
TH_A="0 229 255"     # accent

# ---------- initialisation ----------

ui_init() {
    local mode="${COLOR_MODE:-auto}"

    [[ -t 1 ]] && UI_TTY=1
    case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
        *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) UI_UTF8=1 ;;
    esac

    case "$mode" in
        always) UI_COLOR=1 ;;
        never)  UI_COLOR=0 ;;
        *)
            if [[ $UI_TTY -eq 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
                UI_COLOR=1
            fi
            ;;
    esac
    [[ -n "${NO_COLOR:-}" && "$mode" == "auto" ]] && UI_COLOR=0

    case "${COLORTERM:-}" in
        truecolor|24bit) UI_TRUECOLOR=1 ;;
    esac

    UI_COLS="${COLUMNS:-}"
    if [[ -z "$UI_COLS" ]]; then
        UI_COLS="$(tput cols 2>/dev/null || echo 80)"
    fi
    [[ "$UI_COLS" =~ ^[0-9]+$ ]] || UI_COLS=80

    ui_theme "$THEME_NAME"
    ui_define_colors
    ui_define_symbols
}

ui_theme() {
    case "$1" in
        cyber)  THEME_NAME=cyber;  TH_S="0 229 255";   TH_E="187 0 255";   TH_A="0 229 255" ;;
        ocean)  THEME_NAME=ocean;  TH_S="0 180 216";   TH_E="3 4 94";      TH_A="72 202 228" ;;
        sunset) THEME_NAME=sunset; TH_S="255 183 3";   TH_E="214 40 40";   TH_A="251 133 0" ;;
        matrix) THEME_NAME=matrix; TH_S="170 255 0";   TH_E="0 168 84";    TH_A="57 255 20" ;;
        aurora) THEME_NAME=aurora; TH_S="0 255 160";   TH_E="94 96 206";   TH_A="100 223 223" ;;
        mono)   THEME_NAME=mono;   TH_S="230 230 230"; TH_E="120 120 120"; TH_A="230 230 230" ;;
        *) return 1 ;;
    esac
    [[ $UI_COLOR -eq 1 ]] && C_ACCENT="$(fg_rgb "$TH_A")"
    return 0
}

ui_themes() { printf '%s\n' cyber ocean sunset matrix aurora mono; }

# 24-bit foreground, falling back to the nearest xterm-256 color
fg_rgb() {
    local r g b
    if [[ $# -eq 1 ]]; then IFS=" " read -r r g b <<< "$1"; else r="$1"; g="$2"; b="$3"; fi
    if [[ $UI_TRUECOLOR -eq 1 ]]; then
        printf '\033[38;2;%d;%d;%dm' "$r" "$g" "$b"
    else
        printf '\033[38;5;%dm' "$(( 16 + 36 * (r * 5 / 255) + 6 * (g * 5 / 255) + (b * 5 / 255) ))"
    fi
}

ui_define_colors() {
    if [[ $UI_COLOR -eq 1 ]]; then
        C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_ITALIC=$'\033[3m'
        C_UL=$'\033[4m'
        C_RED=$'\033[38;5;203m';    C_GREEN=$'\033[38;5;84m'
        C_YELLOW=$'\033[38;5;221m'; C_BLUE=$'\033[38;5;75m'
        C_MAGENTA=$'\033[38;5;177m'; C_CYAN=$'\033[38;5;80m'
        C_ORANGE=$'\033[38;5;214m'; C_GRAY=$'\033[38;5;245m'
        C_WHITE=$'\033[38;5;255m'
        C_BG_RED=$'\033[48;5;160m\033[38;5;231m'
        C_ACCENT="$(fg_rgb "$TH_A")"
    else
        C_RESET=''; C_BOLD=''; C_DIM=''; C_ITALIC=''; C_UL=''
        C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_MAGENTA=''; C_CYAN=''
        C_ORANGE=''; C_GRAY=''; C_WHITE=''; C_BG_RED=''; C_ACCENT=''
    fi
}

ui_define_symbols() {
    if [[ $UI_UTF8 -eq 1 ]]; then
        S_OK="✔"; S_ERR="✖"; S_WARN="▲"; S_INFO="●"; S_ARROW="➜"; S_DOT="·"
        S_BAR_ON="█"; S_BAR_OFF="░"; S_H="─"; S_V="│"
        S_TL="╭"; S_TR="╮"; S_BL="╰"; S_BR="╯"; S_PTR="❯"; S_STEP="◆"
        SPIN_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
    else
        S_OK="+"; S_ERR="x"; S_WARN="!"; S_INFO="*"; S_ARROW=">"; S_DOT="-"
        S_BAR_ON="#"; S_BAR_OFF="."; S_H="-"; S_V="|"
        S_TL="+"; S_TR="+"; S_BL="+"; S_BR="+"; S_PTR=">"; S_STEP="*"
        SPIN_FRAMES=('|' '/' '-' '\')
    fi
}

# ---------- text helpers ----------

# repeat CHAR N times
rep() {
    local ch="$1" n="$2" out=""
    (( n > 0 )) || return 0
    printf -v out '%*s' "$n" ''
    printf '%s' "${out// /$ch}"
}

strip_ansi() { sed -E $'s/\033\\[[0-9;?]*[A-Za-z]//g'; }

# gradient_text "text" ROW_OFFSET  -> colored per character along theme gradient
gradient_text() {
    local text="$1" off="${2:-0}" len i ch t r g b
    local sr sg sb er eg eb
    IFS=" " read -r sr sg sb <<< "$TH_S"
    IFS=" " read -r er eg eb <<< "$TH_E"
    len=${#text}
    if [[ $UI_COLOR -eq 0 ]]; then printf '%s' "$text"; return; fi
    (( len > 0 )) || return 0
    for (( i = 0; i < len; i++ )); do
        ch="${text:i:1}"
        if [[ "$ch" == " " ]]; then printf ' '; continue; fi
        t=$(( (i * 100 / len) + off ))
        (( t > 100 )) && t=100
        r=$(( sr + (er - sr) * t / 100 ))
        g=$(( sg + (eg - sg) * t / 100 ))
        b=$(( sb + (eb - sb) * t / 100 ))
        printf '%s%s' "$(fg_rgb "$r" "$g" "$b")" "$ch"
    done
    printf '%s' "$C_RESET"
}

# ---------- messages ----------

_log_hook() { :; }   # replaced by core.sh once a run directory exists

info()  { printf '%s%s%s %s\n' "$C_CYAN" "$S_INFO" "$C_RESET" "$*"; _log_hook INFO "$*"; }
ok()    { printf '%s%s%s %s\n' "$C_GREEN" "$S_OK" "$C_RESET" "$*"; _log_hook OK "$*"; }
warn()  { printf '%s%s%s %s\n' "$C_YELLOW" "$S_WARN" "$C_RESET" "$*" >&2; _log_hook WARN "$*"; }
error() { printf '%s%s%s %s\n' "$C_RED" "$S_ERR" "$C_RESET" "$*" >&2; _log_hook ERROR "$*"; }
die()   { error "$*"; exit "${DIE_CODE:-1}"; }
step()  { printf '\n%s%s%s %s%s%s\n' "$C_ACCENT" "$S_STEP" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; _log_hook STEP "$*"; }
debug() { (( ${VERBOSE:-0} )) && printf '%s%s debug%s %s\n' "$C_GRAY" "$S_DOT" "$C_RESET" "$*" >&2; return 0; }

hint() { printf '  %s%s%s\n' "$C_GRAY" "$*" "$C_RESET"; }

kv() {
    # kv "Label" "value" [color]
    printf '  %s%-14s%s %s%s%s\n' "$C_GRAY" "$1" "$C_RESET" "${3:-$C_WHITE}" "$2" "$C_RESET"
}

section() {
    local title="$1" width=$(( UI_COLS > 78 ? 78 : UI_COLS - 2 ))
    local left="$S_H$S_H "
    local right_len=$(( width - ${#left} - ${#title} - 2 ))
    printf '\n%s%s%s%s%s%s %s%s\n' \
        "$C_ACCENT" "$left" "$C_BOLD" "$title" "$C_RESET$C_ACCENT" "" \
        "$(rep "$S_H" "$right_len")" "$C_RESET"
}

# box "Title" line1 line2 ...   (plain text lines only)
box() {
    local title="$1"; shift
    local line w=${#title} inner
    for line in "$@"; do (( ${#line} > w )) && w=${#line}; done
    inner=$(( w + 2 ))
    printf '%s%s%s %s%s%s %s%s%s\n' "$C_ACCENT" "$S_TL" "$S_H" "$C_BOLD$C_WHITE" "$title" "$C_RESET$C_ACCENT" \
        "$(rep "$S_H" $(( inner - ${#title} - 2 )))" "$S_TR" "$C_RESET"
    for line in "$@"; do
        printf '%s%s%s %s%-*s %s%s%s\n' "$C_ACCENT" "$S_V" "$C_RESET" "$C_WHITE" "$w" "$line" "$C_ACCENT" "$S_V" "$C_RESET"
    done
    printf '%s%s%s%s%s\n' "$C_ACCENT" "$S_BL" "$(rep "$S_H" "$inner")" "$S_BR" "$C_RESET"
}

severity_color() {
    case "$1" in
        CRITICAL) printf '%s%s' "$C_BG_RED" "$C_BOLD" ;;
        HIGH)     printf '%s%s' "$C_RED" "$C_BOLD" ;;
        MEDIUM)   printf '%s' "$C_ORANGE" ;;
        LOW)      printf '%s' "$C_YELLOW" ;;
        *)        printf '%s' "$C_CYAN" ;;
    esac
}

# ---------- banner ----------

BANNER_ART=(
'██╗  ██╗ █████╗ ███╗   ███╗██╗     ████████╗███████╗ ██████╗██╗  ██╗'
'╚██╗██╔╝██╔══██╗████╗ ████║██║     ╚══██╔══╝██╔════╝██╔════╝██║  ██║'
' ╚███╔╝ ███████║██╔████╔██║██║        ██║   █████╗  ██║     ███████║'
' ██╔██╗ ██╔══██║██║╚██╔╝██║██║        ██║   ██╔══╝  ██║     ██╔══██║'
'██╔╝ ██╗██║  ██║██║ ╚═╝ ██║███████╗   ██║   ███████╗╚██████╗██║  ██║'
'╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝'
)

banner() {
    local i row
    printf '\n'
    if [[ $UI_UTF8 -eq 1 && $UI_COLS -ge 72 ]]; then
        for (( i = 0; i < ${#BANNER_ART[@]}; i++ )); do
            printf '  '
            gradient_text "${BANNER_ART[i]}" $(( i * 4 ))
            printf '\n'
        done
        printf '  '
        gradient_text "N M A P   T O O L K I T   ${S_DOT}   N E T W O R K   I N T E L L I G E N C E" 0
        printf '\n'
    else
        printf '  %s%s XAMLTECH NMAP TOOLKIT %s\n' "$C_BOLD$C_ACCENT" "$S_PTR" "$C_RESET"
    fi
    printf '  %sv%s  %s  discovery %s ports %s services %s NSE %s reports%s\n' \
        "$C_GRAY" "$SCRIPT_VERSION" "$S_DOT" "$S_DOT" "$S_DOT" "$S_DOT" "$S_DOT" "$C_RESET"
    printf '  %sby %s  %s  github.com/%s  %s  %s%s\n\n' \
        "$C_GRAY" "$AUTHOR" "$S_DOT" "$GITHUB_USER" "$S_DOT" "$WEBSITE" "$C_RESET"
}

# ---------- cursor / spinner / progress ----------

cursor_hide() { [[ $UI_TTY -eq 1 ]] && { printf '\033[?25l'; CURSOR_HIDDEN=1; }; return 0; }
cursor_show() { [[ $CURSOR_HIDDEN -eq 1 ]] && { printf '\033[?25h'; CURSOR_HIDDEN=0; }; return 0; }

spin_start() {
    local msg="$1"
    if [[ $UI_TTY -eq 0 ]]; then info "$msg"; return 0; fi
    cursor_hide
    (
        local i=0
        while :; do
            printf '\r%s%s%s %s' "$C_ACCENT" "${SPIN_FRAMES[i % ${#SPIN_FRAMES[@]}]}" "$C_RESET" "$msg"
            i=$(( i + 1 ))
            sleep 0.08
        done
    ) &
    SPIN_PID=$!
    disown "$SPIN_PID" 2>/dev/null || true
}

spin_stop() {
    if [[ -n "$SPIN_PID" ]]; then
        kill "$SPIN_PID" 2>/dev/null || true
        wait "$SPIN_PID" 2>/dev/null || true
        SPIN_PID=""
        printf '\r\033[2K'
    fi
    cursor_show
    return 0
}

# progress_bar PERCENT [WIDTH]
progress_bar() {
    local pct="$1" width="${2:-30}" filled
    (( pct < 0 )) && pct=0
    (( pct > 100 )) && pct=100
    filled=$(( pct * width / 100 ))
    printf '%s%s%s%s%s' "$C_ACCENT" "$(rep "$S_BAR_ON" "$filled")" "$C_GRAY" "$(rep "$S_BAR_OFF" $(( width - filled )))" "$C_RESET"
}

# ---------- prompts ----------

# ask "Label" "default"  -> REPLY
ask() {
    local label="$1" def="${2:-}" prompt
    if [[ -n "$def" ]]; then
        prompt="${C_ACCENT}${S_PTR}${C_RESET} ${label} ${C_GRAY}[${def}]${C_RESET}: "
    else
        prompt="${C_ACCENT}${S_PTR}${C_RESET} ${label}: "
    fi
    if [[ -t 0 ]]; then
        read -r -e -p "$prompt" REPLY || REPLY=""
    else
        read -r REPLY || REPLY=""
    fi
    [[ -n "$REPLY" ]] || REPLY="$def"
}

confirm() {
    local prompt="${1:-Continue?}" answer
    (( ${ASSUME_YES:-0} )) && return 0
    read -r -p "${C_YELLOW}?${C_RESET} ${prompt} [y/N]: " answer || return 1
    [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# ui_menu "Title" "key|Label|Description" ...   -> MENU_REPLY (key); returns 1 on cancel
ui_menu() {
    local title="$1"; shift
    local -a keys=() labels=() descs=()
    local item k l d n i sel=0 key rest first=1 total

    for item in "$@"; do
        IFS='|' read -r k l d <<< "$item"
        keys+=("$k"); labels+=("$l"); descs+=("${d:-}")
    done
    total=${#keys[@]}

    printf '\n%s%s%s\n' "$C_BOLD" "$title" "$C_RESET"

    if [[ ! -t 0 || $UI_TTY -eq 0 ]]; then
        for (( i = 0; i < total; i++ )); do
            printf '  %s%2d)%s %-14s %s%s%s\n' "$C_ACCENT" $(( i + 1 )) "$C_RESET" "${labels[i]}" "$C_GRAY" "${descs[i]}" "$C_RESET"
        done
        read -r -p "Select [1-$total]: " n || return 1
        if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= total )); then
            MENU_REPLY="${keys[n-1]}"; return 0
        fi
        for (( i = 0; i < total; i++ )); do
            [[ "$n" == "${keys[i]}" ]] && { MENU_REPLY="${keys[i]}"; return 0; }
        done
        return 1
    fi

    hint "↑/↓ or j/k move ${S_DOT} Enter select ${S_DOT} 1-9 jump ${S_DOT} q cancel"
    cursor_hide
    while :; do
        (( first )) || printf '\033[%dA' "$total"
        first=0
        for (( i = 0; i < total; i++ )); do
            printf '\033[2K'
            if (( i == sel )); then
                printf ' %s%s %-18s%s %s%s%s\n' "$C_ACCENT$C_BOLD" "$S_PTR" "${labels[i]}" "$C_RESET" "$C_WHITE" "${descs[i]}" "$C_RESET"
            else
                printf '   %s%-18s %s%s\n' "$C_GRAY" "${labels[i]}" "${descs[i]}" "$C_RESET"
            fi
        done
        IFS= read -rsn1 key || { cursor_show; return 1; }
        case "$key" in
            $'\033')
                IFS= read -rsn2 -t 0.05 rest || true
                case "$rest" in
                    '[A') sel=$(( (sel + total - 1) % total )) ;;
                    '[B') sel=$(( (sel + 1) % total )) ;;
                esac ;;
            k) sel=$(( (sel + total - 1) % total )) ;;
            j) sel=$(( (sel + 1) % total )) ;;
            ''|$'\n'|$'\r') cursor_show; MENU_REPLY="${keys[sel]}"; return 0 ;;
            q|Q) cursor_show; return 1 ;;
            [1-9]) (( key <= total )) && sel=$(( key - 1 )) ;;
        esac
    done
}
