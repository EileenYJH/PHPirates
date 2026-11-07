#!/usr/bin/env bash
# Same as kill-a-holder.ps1, for bash.
set -euo pipefail
lock=$(docker compose exec -T redis redis-cli --scan --pattern 'lock:*' | head -n1 | tr -d '\r')
[ -z "$lock" ] && { echo "Nobody is patching right now - try again in a moment."; exit 1; }
holder=$(docker compose exec -T redis redis-cli GET "$lock" | tr -d '\r')
echo "Killing $holder (holds $lock)"
docker kill "${holder%%-*}" >/dev/null
