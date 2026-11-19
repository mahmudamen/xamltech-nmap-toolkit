# shellcheck shell=bash
# XamlTech Nmap Toolkit - NSE (Nmap Scripting Engine) helpers
# Validates script names against the local script.db so profiles keep working
# across Nmap versions, and lets users browse available scripts.

declare -A NSE_AVAIL=()
NSE_LOADED=0
NSE_DB_OK=0
NSE_MISSING=()

nse_load() {
    (( NSE_LOADED )) && return 0
    NSE_LOADED=1
    local dd db f
    dd="$(nmap_datadir 2>/dev/null || true)"
    [[ -n "$dd" ]] || return 0
    db="$dd/scripts/script.db"
    if [[ -r "$db" ]]; then
        while IFS= read -r f; do NSE_AVAIL["$f"]=1; done < <(grep -o 'filename = "[^"]*"' "$db" | sed -E 's/filename = "(.*)\.nse"/\1/')
    else
        while IFS= read -r f; do f="${f##*/}"; NSE_AVAIL["${f%.nse}"]=1; done < <(find "$dd/scripts" -name '*.nse' 2>/dev/null)
    fi
    (( ${#NSE_AVAIL[@]} > 0 )) && NSE_DB_OK=1
    return 0
}

# nse_existing "a,b,c" -> comma list of scripts that exist locally (unchanged if DB unreadable)
nse_existing() {
    local list="$1" s out=()
    nse_load
    if (( ! NSE_DB_OK )); then printf '%s' "$list"; return 0; fi
    local IFS=','
    for s in $list; do
        if [[ -n "${NSE_AVAIL[$s]:-}" || "$s" == */* ]]; then
            out+=("$s")
        else
            NSE_MISSING+=("$s")
        fi
    done
    printf '%s' "${out[*]}"
}

# Categories and descriptions for the --list-scripts view
nse_list() {
    local filter="${1:-}" dd db
    dd="$(nmap_datadir 2>/dev/null || true)"
    [[ -n "$dd" && -r "$dd/scripts/script.db" ]] || die "NSE script database not found. Try: sudo nmap --script-updatedb"
    db="$dd/scripts/script.db"

    section "NSE scripts${filter:+ matching '$filter'}"
    printf '  %s%-34s %s%s\n' "$C_GRAY" "SCRIPT" "CATEGORIES" "$C_RESET"
    local line name cats count=0 color cat_clean
    while IFS= read -r line; do
        name="$(sed -E 's/.*filename = "([^"]*)\.nse".*/\1/' <<< "$line")"
        cats="$(sed -E 's/.*categories = \{ (.*) \}.*/\1/' <<< "$line" | tr -d '", ' | sed 's/\(.\)$/\1/' )"
        cat_clean="${cats//,/ }"
        if [[ -n "$filter" ]]; then
            [[ "$name" == *"$filter"* || " $cat_clean " == *" $filter "* ]] || continue
        fi
        color="$C_WHITE"
        case " $cat_clean " in
            *" vuln "*)      color="$C_ORANGE" ;;
            *" safe "*)      color="$C_GREEN" ;;
            *" intrusive "*) color="$C_YELLOW" ;;
            *" brute "*|*" dos "*|*" exploit "*) color="$C_RED" ;;
        esac
        printf '  %s%-34s%s %s%s%s\n' "$color" "$name" "$C_RESET" "$C_GRAY" "$cat_clean" "$C_RESET"
        count=$(( count + 1 ))
    done < <(grep '^Entry' "$db" | sort)
    printf '\n  %s%d scripts%s   %sgreen=safe  orange=vuln  yellow=intrusive  red=blocked by this toolkit%s\n' \
        "$C_BOLD" "$count" "$C_RESET" "$C_GRAY" "$C_RESET"
}

nse_help() {
    local name="$1"
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || die "Invalid script name."
    "$NMAP_BIN" --script-help "$name"
}
