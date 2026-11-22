#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$ROOT/results"
RUN="latest"
PORT="8765"
OPEN=1

usage() {
    printf '%s\n' \
        'Usage: ./start.sh [options]' \
        '' \
        '  -o, --output DIR   Run directory to serve (default: ./results)' \
        '      --run NAME     Run to open first (default: latest)' \
        '  -p, --port PORT    Local port (default: 8765)' \
        '      --no-open      Do not launch a browser' \
        '  -h, --help         Show this help'
}

die() { printf 'start: %s\n' "$*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) [[ $# -ge 2 ]] || die "--output needs a value"; OUTPUT_DIR="$2"; shift 2 ;;
        --run)       [[ $# -ge 2 ]] || die "--run needs a value"; RUN="$2"; shift 2 ;;
        -p|--port)   [[ $# -ge 2 ]] || die "--port needs a value"; PORT="$2"; shift 2 ;;
        --no-open)   OPEN=0; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "unknown option: $1" ;;
    esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "invalid port: $PORT"
[[ "$RUN" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || die "invalid run name: $RUN"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -f "$ROOT/lib/web.py" ]] || die "missing lib/web.py"

URL="http://127.0.0.1:$PORT/activity"
printf 'Serving %s at %s\n' "$OUTPUT_DIR" "$URL"
printf 'Press Ctrl+C to stop.\n'
python3 -I "$ROOT/lib/web.py" --root "$OUTPUT_DIR" --port "$PORT" --run "$RUN" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT INT TERM

if (( OPEN )); then
    for _ in {1..50}; do
        if python3 -c 'import socket,sys;s=socket.socket();s.settimeout(.2);sys.exit(s.connect_ex(("127.0.0.1",int(sys.argv[1]))))' "$PORT" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if command -v xdg-open >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        xdg-open "$URL" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$URL" >/dev/null 2>&1 &
    else
        printf 'Open in a browser: %s\n' "$URL"
    fi
fi

wait "$SERVER_PID"
