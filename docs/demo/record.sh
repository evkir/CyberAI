#!/usr/bin/env bash
# Records the local benchmark suite demo as an asciinema cast + GIF.
# Usage: docs/demo/record.sh   (run from the repository root)
set -euo pipefail

OUT_CAST="${OUT_CAST:-/tmp/cyberai-bench.cast}"
OUT_GIF="${OUT_GIF:-docs/assets/demo-bench.gif}"

type_out() {
    local text="$*" i
    printf '\033[1;32m$\033[0m '
    for (( i = 0; i < ${#text}; i++ )); do
        printf '%s' "${text:i:1}"
        sleep 0.04
    done
    printf '\n'
}

play() {
    type_out "$@"
    sleep 0.8
    "$@" || true
    echo
    sleep 1.2
}

inner() {
    play cyberai --help
    play cyberai bench run --suite local --engine real
}

if [ "${_CYBERAI_DEMO_INNER:-}" = "1" ]; then
    inner
    exit 0
fi

rm -f "$OUT_CAST"
stty rows 26 cols 100 2>/dev/null || true
_CYBERAI_DEMO_INNER=1 asciinema rec \
    --quiet --overwrite \
    --idle-time-limit 2 \
    --title "CyberAI — local benchmark suite (real engine)" \
    --command "$0" \
    "$OUT_CAST"

agg --speed 1.4 --font-size 15 --theme asciinema --idle-time-limit 2 \
    "$OUT_CAST" "$OUT_GIF"

ls -lh "$OUT_GIF"
