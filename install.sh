#!/usr/bin/env bash
# XamlTech Nmap Toolkit installer (no network access, no package installation).
#   ./install.sh                 system install under /usr/local   (needs write access / sudo)
#   ./install.sh --user          install under ~/.local
#   ./install.sh --prefix DIR    custom prefix
#   ./install.sh --uninstall     remove a previous install (same prefix flags)
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr/local"
ACTION="install"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)      PREFIX="$HOME/.local"; shift ;;
        --prefix)    [[ $# -ge 2 ]] || { echo "--prefix needs a value" >&2; exit 2; }; PREFIX="$2"; shift 2 ;;
        --uninstall) ACTION="uninstall"; shift ;;
        -h|--help)   sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

SHARE="$PREFIX/share/xamltech-nmap-toolkit"
BIN="$PREFIX/bin/xamltech-nmap"
COMP="$PREFIX/share/bash-completion/completions/xamltech-nmap"

if [[ "$ACTION" == uninstall ]]; then
    rm -rf "$SHARE" "$BIN" "$COMP"
    echo "Removed $SHARE, $BIN and completion."
    exit 0
fi

mkdir -p "$SHARE" "$PREFIX/bin" "$(dirname "$COMP")"
rm -rf "${SHARE:?}/lib" "${SHARE:?}/scripts"
cp -r "$SRC/lib" "$SRC/scripts" "$SRC/nmap-toolkit.sh" "$SRC/LICENSE" "$SHARE/"
mkdir -p "$SHARE/config" "$SHARE/docs"
cp "$SRC"/config/* "$SHARE/config/"
cp "$SRC"/docs/*.md "$SHARE/docs/"
chmod +x "$SHARE/nmap-toolkit.sh" "$SHARE/lib/report.py"
ln -sfn "$SHARE/nmap-toolkit.sh" "$BIN"
cp "$SRC/completions/xamltech-nmap.bash" "$COMP"

echo "Installed to $SHARE"
echo "Command:     xamltech-nmap   (symlink: $BIN)"
case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) echo "Note: add $PREFIX/bin to your PATH." ;; esac
echo "Completion:  open a new shell (or: source $COMP)"
echo "Try:         xamltech-nmap --doctor"
