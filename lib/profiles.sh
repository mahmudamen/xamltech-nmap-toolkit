# shellcheck shell=bash
# XamlTech Nmap Toolkit - scan profile catalog
#
# Table format:  name|category|risk|root|speed|description
#   risk : safe | moderate | intrusive (intrusive asks for explicit confirmation)
#   root : yes  = best with raw sockets; the toolkit adapts when unprivileged
#   speed: fast | medium | slow

PROFILE_TABLE=(
'discovery|Discovery|safe|no|fast|Host discovery only (ping scan) - build an inventory'
'arp|Discovery|safe|yes|fast|ARP sweep of the local subnet - most reliable on a LAN'
'sweep|Discovery|safe|no|fast|Multi-probe sweep: ICMP echo/timestamp + TCP SYN/ACK probes'
'diagnostic|Discovery|safe|yes|fast|Discovery + traceroute + latency diagnostics'
'list|Discovery|safe|no|fast|DNS list scan - resolve targets without touching them'
'broadcast|Discovery|safe|no|medium|Target-less LAN broadcast discovery (DHCP, UPnP, mDNS, NetBIOS)'
'quick|Ports|safe|no|fast|Fast scan of the 100 most common TCP ports'
'standard|Ports|safe|yes|medium|Top-1000 TCP ports + service/version detection'
'deep|Ports|safe|yes|slow|All 65535 TCP ports + service/version detection'
'full|Ports|moderate|yes|slow|Everything: all ports, OS, versions, default scripts, traceroute'
'os|Ports|safe|yes|slow|All TCP ports + service versions + OS fingerprinting'
'udp|Ports|safe|yes|slow|Top-100 UDP ports + light version probing'
'firewall|Ports|safe|yes|medium|ACK scan to map firewall rules (filtered vs unfiltered)'
'polite|Ports|safe|no|slow|Rate-limited scan, gentle on fragile devices and production'
'default|Scripts|safe|no|medium|Service detection + the default NSE script set'
'safe-nse|Scripts|safe|no|medium|All NSE scripts categorised as safe'
'discovery-nse|Scripts|safe|no|medium|NSE discovery scripts (restricted to safe ones)'
'vuln-safe|Scripts|safe|no|slow|Vulnerability checks that are flagged safe (low impact)'
'vuln|Scripts|intrusive|no|slow|Broad vulnerability checks (no brute/DoS/exploit) - may disturb fragile services'
'vulners|Scripts|moderate|no|medium|CVE lookup via vulners.com (sends service versions off-network)'
'web|Services|safe|no|medium|HTTP(S): titles, headers, methods, robots, directory hints'
'tls|Services|safe|no|medium|TLS/SSL: certificates, protocols, ciphers, Heartbleed/POODLE'
'ssh|Services|safe|no|fast|SSH: algorithms, host keys, auth methods, protocol v1'
'smb|Services|safe|no|medium|SMB/NetBIOS: dialects, signing, OS discovery, MS17-010'
'dns|Services|safe|no|fast|DNS: recursion, NSID, service discovery'
'db|Services|safe|no|medium|Databases/caches exposure: MySQL, PostgreSQL, MSSQL, Redis, MongoDB...'
'mail|Services|safe|no|medium|SMTP/IMAP/POP3 capabilities and TLS'
'rdp|Services|safe|no|fast|RDP: encryption level and NTLM info'
'ftp|Services|safe|no|fast|FTP: banner, anonymous access, system type'
'odoo|XamlTech|safe|no|medium|Odoo ERP: version, DB manager/listing exposure, TLS, PostgreSQL exposure'
'pos|XamlTech|safe|no|medium|POS network: ESC/POS printers (9100), CUPS/IPP, Odoo POS, web UIs'
'iot|XamlTech|safe|no|medium|Cameras/IoT/embedded: RTSP, UPnP, web UIs, MQTT ports'
'audit|Audit|safe|yes|slow|Exposure review: top-1000 + versions + TLS/SSH/SMB/DB/HTTP checks'
)

WORKFLOW_TABLE=(
'recon|Smart pipeline: discovery -> fast ports on live hosts -> versions/scripts on open ports only'
'inventory|Recon pipeline + OS detection and traceroute for a full asset inventory'
)

# Profiles that run without any target
profile_needs_target() { [[ "$1" != "broadcast" ]]; }

profile_field() {   # profile_field NAME INDEX(1-6)
    local row
    for row in "${PROFILE_TABLE[@]}"; do
        if [[ "${row%%|*}" == "$1" ]]; then
            IFS='|' read -r -a _f <<< "$row"
            printf '%s' "${_f[$(( $2 - 1 ))]}"
            return 0
        fi
    done
    return 1
}

profile_exists()   { profile_field "$1" 1 >/dev/null 2>&1; }
workflow_exists()  { local w; for w in "${WORKFLOW_TABLE[@]}"; do [[ "${w%%|*}" == "$1" ]] && return 0; done; return 1; }
profile_risk()     { profile_field "$1" 3; }
profile_root()     { profile_field "$1" 4; }
profile_desc()     { profile_field "$1" 6; }
profile_names()    { local r; for r in "${PROFILE_TABLE[@]}"; do printf '%s\n' "${r%%|*}"; done; for r in "${WORKFLOW_TABLE[@]}"; do printf '%s\n' "${r%%|*}"; done; printf 'custom\n'; }

validate_profile() {
    profile_exists "$1" || workflow_exists "$1" || [[ "$1" == custom ]] \
        || die "Unknown profile: $1  (see --list-profiles)"
}

# ---------- listing ----------

risk_badge() {
    case "$1" in
        safe)      printf '%ssafe%s' "$C_GREEN" "$C_RESET" ;;
        moderate)  printf '%smoderate%s' "$C_YELLOW" "$C_RESET" ;;
        intrusive) printf '%sintrusive%s' "$C_ORANGE" "$C_RESET" ;;
    esac
}

list_profiles() {
    local row cat last="" name risk root speed desc w
    section "Scan profiles"
    printf '  %s%-14s %-10s %-5s %-7s %s%s\n' "$C_GRAY" "PROFILE" "RISK" "ROOT" "SPEED" "DESCRIPTION" "$C_RESET"
    for row in "${PROFILE_TABLE[@]}"; do
        IFS='|' read -r name cat risk root speed desc <<< "$row"
        if [[ "$cat" != "$last" ]]; then
            printf '\n  %s%s%s\n' "$C_ACCENT$C_BOLD" "$cat" "$C_RESET"
            last="$cat"
        fi
        printf '  %s%-14s%s %-19s %-5s %-7s %s%s%s\n' "$C_WHITE$C_BOLD" "$name" "$C_RESET" \
            "$(risk_badge "$risk")" "$root" "$speed" "$C_GRAY" "$desc" "$C_RESET"
    done
    printf '\n  %sWorkflows%s\n' "$C_ACCENT$C_BOLD" "$C_RESET"
    for w in "${WORKFLOW_TABLE[@]}"; do
        printf '  %s%-14s%s %s%s%s\n' "$C_WHITE$C_BOLD" "${w%%|*}" "$C_RESET" "$C_GRAY" "${w#*|}" "$C_RESET"
    done
    printf '\n  %scustom%s         %sYour own Nmap arguments via --args (output flags and offensive NSE are blocked)%s\n\n' \
        "$C_WHITE$C_BOLD" "$C_RESET" "$C_GRAY" "$C_RESET"
    hint "root=yes: best with sudo; unprivileged runs automatically fall back to TCP-connect."
}

# ---------- argument construction ----------

NSE_UA="http.useragent=XamlTech-Nmap-Toolkit/${SCRIPT_VERSION:-2} (authorized-scan; +https://xamltech.com)"

# script_args LIST  -> adds --script with only locally-available scripts
_use_scripts() {
    local list
    list="$(nse_existing "$1")"
    [[ -n "$list" ]] && NMAP_ARGS+=(--script "$list")
    return 0
}

build_nmap_args() {
    local profile="$1"
    NMAP_ARGS=()
    NSE_MISSING=()
    local sd="$SCRIPTS_DIR"

    case "$profile" in
        discovery)     NMAP_ARGS=(-sn --reason) ;;
        arp)           NMAP_ARGS=(-sn -PR --reason) ;;
        sweep)         NMAP_ARGS=(-sn -PE -PP -PS21,22,23,25,80,443,3389,8069 -PA80,443 --reason) ;;
        diagnostic)    NMAP_ARGS=(-sn -T4 --reason --traceroute) ;;
        list)          NMAP_ARGS=(-sL) ;;
        broadcast)
            NMAP_ARGS=(--reason)
            _use_scripts "broadcast-dhcp-discover,broadcast-dns-service-discovery,broadcast-upnp-info,broadcast-netbios-master-browser,broadcast-igmp-discovery"
            ;;
        quick)         NMAP_ARGS=(-T4 --top-ports 100 --open --reason) ;;
        standard)      NMAP_ARGS=(-sS -T4 --top-ports 1000 -sV --open --reason) ;;
        deep)          NMAP_ARGS=(-sS -T3 -p- -sV --open --reason) ;;
        full)          NMAP_ARGS=(-sS -T4 -p- -A --open --reason) ;;
        os)            NMAP_ARGS=(-sS -T3 -p- -sV -O --osscan-limit --open --reason) ;;
        udp)           NMAP_ARGS=(-sU -T4 --top-ports 100 -sV --version-intensity 0 --open --reason) ;;
        firewall)      NMAP_ARGS=(-sA -T4 --top-ports 1000 --reason) ;;
        polite)        NMAP_ARGS=(-sS -T2 --max-rate 50 --top-ports 1000 -sV --version-intensity 2 --open --reason) ;;
        default)       NMAP_ARGS=(-sV -sC -T4 --open --reason) ;;
        safe-nse)      NMAP_ARGS=(-sV -T4 --open --reason --script safe) ;;
        discovery-nse) NMAP_ARGS=(-sV -T4 --open --reason --script "discovery and safe") ;;
        vuln-safe)     NMAP_ARGS=(-sV -T4 --open --reason --script "vuln and safe") ;;
        vuln)          NMAP_ARGS=(-sV -T4 --open --reason --script "vuln and not (dos or exploit or brute or fuzzer)") ;;
        vulners)
            NMAP_ARGS=(-sV -T4 --open --reason)
            _use_scripts "vulners"
            (( ${#NSE_MISSING[@]} )) && die "The 'vulners' NSE script is not installed with this Nmap."
            ;;
        web)
            NMAP_ARGS=(-sV -T4 --open --reason -p80,81,443,3000,5000,8000,8008,8080,8081,8443,8888,9000)
            _use_scripts "http-title,http-server-header,http-headers,http-methods,http-robots.txt,http-enum,http-security-headers,http-cookie-flags,http-favicon,http-generator,ssl-cert"
            ;;
        tls)
            NMAP_ARGS=(-sV -T4 --open --reason -p443,465,636,853,993,995,2376,3389,5671,8443,8883,9443)
            _use_scripts "ssl-cert,ssl-enum-ciphers,ssl-date,ssl-known-key,ssl-dh-params,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,tls-alpn,sslv2"
            ;;
        ssh)
            NMAP_ARGS=(-sV -T4 --open --reason -p22,2222)
            _use_scripts "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1"
            ;;
        smb)
            NMAP_ARGS=(-sV -T4 --open --reason -p139,445)
            _use_scripts "smb-os-discovery,smb-protocols,smb-security-mode,smb2-security-mode,smb2-time,smb-vuln-ms17-010,nbstat"
            ;;
        dns)
            NMAP_ARGS=(-sV -T4 --open --reason -p53)
            _use_scripts "dns-nsid,dns-recursion,dns-service-discovery"
            ;;
        db)
            NMAP_ARGS=(-sV -T4 --open --reason -p1433,1521,3306,5432,5984,6379,7474,9042,9200,11211,27017,50000)
            _use_scripts "mysql-info,ms-sql-info,oracle-tns-version,redis-info,mongodb-info,memcached-info,couchdb-stats,http-title"
            ;;
        mail)
            NMAP_ARGS=(-sV -T4 --open --reason -p25,110,143,465,587,993,995)
            _use_scripts "smtp-commands,smtp-ntlm-info,imap-capabilities,pop3-capabilities,ssl-cert"
            ;;
        rdp)
            NMAP_ARGS=(-sV -T4 --open --reason -p3389)
            _use_scripts "rdp-enum-encryption,rdp-ntlm-info"
            ;;
        ftp)
            NMAP_ARGS=(-sV -T4 --open --reason -p21,990)
            _use_scripts "ftp-anon,ftp-syst"
            ;;
        odoo)
            NMAP_ARGS=(-sV -T4 --open --reason -p22,80,443,5432,8069,8071,8072)
            _use_scripts "$sd/odoo-info.nse,http-title,http-server-header,http-headers,http-methods,ssl-cert,ssl-enum-ciphers"
            ;;
        pos)
            NMAP_ARGS=(-sV -T4 --open --reason -p80,443,515,631,8069,8072,9100,9101,9102)
            _use_scripts "$sd/odoo-info.nse,pjl-ready-message,cups-info,http-title,http-server-header"
            ;;
        iot)
            NMAP_ARGS=(-sV -T4 --open --reason -p80,443,554,1883,1900,5683,8000,8080,8554,8883,37777)
            _use_scripts "rtsp-methods,http-title,http-server-header,http-auth-finder,http-headers"
            ;;
        audit)
            NMAP_ARGS=(-sS -T3 --top-ports 1000 -sV --open --reason)
            _use_scripts "$sd/odoo-info.nse,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,ssh-auth-methods,http-title,http-methods,http-server-header,smb-protocols,smb2-security-mode,rdp-enum-encryption,redis-info,mongodb-info,memcached-info,ftp-anon,telnet-encryption,mysql-info,ms-sql-info"
            ;;
        custom)
            [[ ${#CUSTOM_ARGS[@]} -gt 0 ]] || die "Custom profile requires --args."
            guard_custom_args "${CUSTOM_ARGS[@]}"
            NMAP_ARGS=("${CUSTOM_ARGS[@]}")
            ;;
        *) die "Invalid profile: $profile" ;;
    esac

    # HTTP-aware scripts identify the toolkit honestly in the User-Agent.
    local a has_script=0
    for a in "${NMAP_ARGS[@]}"; do [[ "$a" == --script ]] && has_script=1; done
    (( has_script )) && [[ "$profile" != custom ]] && NMAP_ARGS+=(--script-args "$NSE_UA")

    apply_overrides
    adapt_args_for_privileges
    (( NMAP_NEEDS_FLAG )) && NMAP_ARGS+=(--privileged)
    return 0
}

# ---------- user overrides (timing, ports, rate, scripts...) ----------

# strip_args NAME... : remove options matching glob patterns; "--opt:" patterns also drop the value
_strip_args() {
    local -a keep=()
    local a skip=0 pat drop
    for a in "${NMAP_ARGS[@]}"; do
        if (( skip )); then skip=0; continue; fi
        drop=0
        for pat in "$@"; do
            if [[ "$pat" == *: ]]; then
                [[ "$a" == "${pat%:}" ]] && { drop=1; skip=1; }
            else
                # shellcheck disable=SC2053
                [[ "$a" == $pat ]] && drop=1
            fi
        done
        (( drop )) || keep+=("$a")
    done
    NMAP_ARGS=("${keep[@]}")
}

apply_overrides() {
    local a no_ports=0
    for a in "${NMAP_ARGS[@]}"; do [[ "$a" == -sn || "$a" == -sL ]] && no_ports=1; done
    if (( no_ports )) && [[ -n "${PORTS:-}${TOP_PORTS:-}" ]]; then
        warn "Port options are ignored by discovery-only profiles."
        PORTS=""; TOP_PORTS=""
    fi
    if [[ -n "${TIMING:-}" ]]; then
        [[ "$TIMING" =~ ^[0-5]$ || "$TIMING" =~ ^(paranoid|sneaky|polite|normal|aggressive|insane)$ ]] \
            || die "Invalid timing '$TIMING' (use 0-5)."
        _strip_args '-T*'
        NMAP_ARGS+=("-T$TIMING")
    fi
    if [[ -n "${PORTS:-}" ]]; then
        [[ "$PORTS" =~ ^[0-9TUSP:,-]+$ ]] || die "Invalid port specification: $PORTS"
        _strip_args '-p*' '-F' '--top-ports:'
        NMAP_ARGS+=("-p$PORTS")
    fi
    if [[ -n "${TOP_PORTS:-}" ]]; then
        [[ "$TOP_PORTS" =~ ^[0-9]+$ ]] || die "--top-ports needs a number."
        _strip_args '-p*' '-F' '--top-ports:'
        NMAP_ARGS+=(--top-ports "$TOP_PORTS")
    fi
    if [[ -n "${EXTRA_SCRIPTS:-}" ]]; then
        guard_script_spec "$EXTRA_SCRIPTS"
        local present
        present="$(nse_existing "$EXTRA_SCRIPTS")"
        (( ${#NSE_MISSING[@]} )) && warn "Skipping unavailable scripts: ${NSE_MISSING[*]}"
        [[ -n "$present" ]] && NMAP_ARGS+=(--script "$present")
    fi
    if [[ -n "${SCRIPT_ARGS:-}" ]]; then
        NMAP_ARGS+=(--script-args "$SCRIPT_ARGS")
    fi
    [[ -n "${MAX_RATE:-}" ]]     && { [[ "$MAX_RATE" =~ ^[0-9]+$ ]]     || die "--max-rate needs a number.";     _strip_args '--max-rate:';     NMAP_ARGS+=(--max-rate "$MAX_RATE"); }
    [[ -n "${MAX_RETRIES:-}" ]]  && { [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]]  || die "--max-retries needs a number."; _strip_args '--max-retries:'; NMAP_ARGS+=(--max-retries "$MAX_RETRIES"); }
    [[ -n "${HOST_TIMEOUT:-}" ]] && { [[ "$HOST_TIMEOUT" =~ ^[0-9]+[smhd]?$ ]] || die "--host-timeout like 90s, 5m, 1h."; NMAP_ARGS+=(--host-timeout "$HOST_TIMEOUT"); }
    [[ -n "${DNS_SERVERS:-}" ]]  && { [[ "$DNS_SERVERS" =~ ^[0-9a-fA-F.:,]+$ ]] || die "Invalid --dns-servers."; NMAP_ARGS+=(--dns-servers "$DNS_SERVERS"); }
    [[ -n "${IFACE:-}" ]]        && { [[ "$IFACE" =~ ^[A-Za-z0-9._:-]+$ ]]  || die "Invalid interface name."; NMAP_ARGS+=(-e "$IFACE"); }
    [[ -n "${EXCLUDE:-}" ]]      && { validate_target_token "${EXCLUDE%%,*}"; [[ "$EXCLUDE" =~ ^[][A-Za-z0-9._:/*,-]+$ ]] || die "Invalid --exclude."; NMAP_ARGS+=(--exclude "$EXCLUDE"); }
    (( ${NO_PING:-0} ))   && NMAP_ARGS+=(-Pn)
    (( ${NO_DNS:-0} ))    && NMAP_ARGS+=(-n)
    (( ${IPV6:-0} ))      && NMAP_ARGS+=(-6)
    if (( ${EXTRA_VERBOSE:-0} )); then NMAP_ARGS+=(-v); fi
    return 0
}
