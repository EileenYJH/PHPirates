#!/usr/bin/env bash
# Same as export-run.ps1, for bash.
set -euo pipefail
stamp=$(date +%Y%m%d-%H%M%S)
mkdir -p runs
docker compose run --rm --no-deps -T -v "$PWD/runs:/out" -e EXPORT_DIR=/out agent-a python - "$stamp" < scripts/export_run.py >/dev/null
cat "runs/$stamp/SUMMARY.md"
