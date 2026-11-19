# XamlTech Nmap Toolkit - live Nmap output renderer
#
# Reads raw Nmap stdout on stdin and writes a colorized stream:
#   * colors hosts, ports (by state), services, NSE output, warnings, CVEs
#   * turns Nmap's "Timing: About NN% done" stats into one live progress bar
#
# Variables (-v): color=0|1  progress=0|1  accent=ESC-seq  on=█ off=░

function clear_prog() {
    if (prog_on) { printf "\r\033[2K"; prog_on = 0 }
}

function bar(pct,    w, f, i, s) {
    w = 26; f = int(pct * w / 100); s = ""
    for (i = 0; i < w; i++) s = s (i < f ? on : off)
    return s
}

BEGIN {
    if (color) {
        BOLD = "\033[1m"; DIM = "\033[2m"; UL = "\033[4m"
        GREEN = "\033[38;5;84m"; RED = "\033[38;5;203m"; YEL = "\033[38;5;221m"
        BLUE = "\033[38;5;75m"; MAG = "\033[38;5;177m"; CYAN = "\033[38;5;80m"
        ORG = "\033[38;5;214m"; GRAY = "\033[38;5;245m"; WHITE = "\033[38;5;255m"
        BGRED = "\033[48;5;160m\033[38;5;231m"
        if (accent == "") accent = CYAN
    }
    prog_on = 0
}

{
    line = $0

    # ---- progress -------------------------------------------------------
    if (match(line, /About [0-9.]+% done/)) {
        if (progress) {
            seg = substr(line, RSTART, RLENGTH); sub(/About /, "", seg); sub(/% done/, "", seg)
            pct = seg + 0
            phase = line; sub(/ Timing:.*/, "", phase)
            etc = ""; if (match(line, /ETC: [0-9:]+/)) etc = substr(line, RSTART + 5, RLENGTH - 5)
            rem = ""; if (match(line, /\([0-9:]+ remaining\)/)) rem = substr(line, RSTART + 1, RLENGTH - 1)
            printf "\r\033[2K%s%s%s %5.1f%%  %s%s%s", accent, bar(pct), (color ? "\033[0m" : ""), pct, (color ? GRAY : ""), phase, (color ? "\033[0m" : "")
            if (rem != "") printf "  %s%s%s", (color ? DIM : ""), rem, (color ? "\033[0m" : "")
            prog_on = 1
            fflush()
        }
        next
    }
    if (line ~ /^Stats: /) next

    clear_prog()

    # ---- colorize -------------------------------------------------------
    if (!color) { print line; fflush(); next }

    if (line ~ /^Starting Nmap/ || line ~ /^Initiating / || line ~ /^Completed /) {
        print DIM line "\033[0m"
    } else if (line ~ /^Nmap scan report for/) {
        print BOLD accent line "\033[0m"
    } else if (line ~ /^Host is up/) {
        print GREEN line "\033[0m"
    } else if (line ~ /^Discovered open port/) {
        print GREEN "\342\227\217 " line "\033[0m"
    } else if (line ~ /^(Host seems down|Note: Host seems down)/) {
        print RED line "\033[0m"
    } else if (line ~ /^Nmap done/) {
        print BOLD GREEN line "\033[0m"
    } else if (line ~ /^(WARNING|Warning)/) {
        print YEL line "\033[0m"
    } else if (line ~ /^(QUITTING|Failed to|.*requires root)/) {
        print RED line "\033[0m"
    } else if (line ~ /^PORT[ \t]+STATE/ || line ~ /^HOP[ \t]+RTT/) {
        print GRAY BOLD UL line "\033[0m"
    } else if (line ~ /^(Service Info|OS details|Running|OS CPE|MAC Address|Device type|Network Distance|Aggressive OS|TRACEROUTE|Uptime guess|Not shown|Other addresses)/) {
        print BLUE line "\033[0m"
    } else if (line ~ /^\|/ || line ~ /^\|_/) {
        if (line ~ /VULNERABLE|State: VULN/) print BGRED BOLD line "\033[0m"
        else if (line ~ /CVE-[0-9]+-[0-9]+|NOT FOUND|Warning|weak|deprecated|SSLv|TLSv1\.0|TLSv1\.1|anonymous|open relay|writable/) print ORG line "\033[0m"
        else print MAG line "\033[0m"
    } else if (match(line, /^[0-9]+\/(tcp|udp|sctp)/)) {
        port = substr(line, 1, RLENGTH); rest = substr(line, RLENGTH + 1)
        if (match(rest, /^[ \t]+[a-z|]+/)) {
            sp = substr(rest, 1, RLENGTH); rest2 = substr(rest, RLENGTH + 1)
            st = sp; gsub(/[ \t]/, "", st)
            if (st == "open") sc = GREEN BOLD
            else if (st == "closed") sc = RED
            else if (st ~ /filtered/) sc = YEL
            else sc = GRAY
            svc = ""; tail = rest2
            if (match(rest2, /^[ \t]+[^ \t]+/)) { svc = substr(rest2, 1, RLENGTH); tail = substr(rest2, RLENGTH + 1) }
            print WHITE BOLD port "\033[0m" sc sp "\033[0m" CYAN svc "\033[0m" tail
        } else {
            print line
        }
    } else {
        print line
    }
    fflush()
}

END { clear_prog() }
