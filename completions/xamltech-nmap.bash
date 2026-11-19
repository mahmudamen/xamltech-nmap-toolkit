# bash completion for xamltech-nmap / nmap-toolkit.sh
_xamltech_nmap() {
    local cur prev opts profiles
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="-t --target -L --target-file -p --profile -a --args -o --output -T --timing --ports --top-ports
          --scripts --script-args --max-rate --max-retries --host-timeout --dns-servers -e --interface
          --exclude --scope --formats --theme --config --no-ping -Pn --no-dns -n -6 --ipv6 --no-latency
          --open --notify --no-color --color --no-banner --authorized --dry-run --sudo --online -v --verbose
          -y --yes --list-profiles --list-scripts --script-help --history --diff --open-report --export
          --doctor --check-updates --version -h --help"
    profiles="discovery arp sweep diagnostic list broadcast quick standard deep full os udp firewall polite
              default safe-nse discovery-nse vuln-safe vuln vulners web tls ssh smb dns db mail rdp ftp
              odoo pos iot audit recon inventory custom"
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
