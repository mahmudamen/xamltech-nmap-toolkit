#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/nmap-toolkit.sh"

if ! command -v shellcheck >/dev/null 2>&1; then
    echo "ShellCheck is not installed; skipping."
    exit 0
fi

shellcheck "$SCRIPT"
echo "ShellCheck passed."
