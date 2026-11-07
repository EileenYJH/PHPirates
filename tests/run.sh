#!/usr/bin/env bash
# Same as run.ps1, for bash.
set -euo pipefail
docker run --rm -d --name phpirates-test-redis -p 6399:6379 redis:7-alpine >/dev/null
trap 'docker rm -f phpirates-test-redis >/dev/null' EXIT
REDIS_URL="redis://localhost:6399/0" python3 tests/test_redis_logic.py
