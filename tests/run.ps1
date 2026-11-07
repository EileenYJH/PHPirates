# Prove the Redis coordination logic with a throwaway Redis. No Docker stack,
# no Ollama needed. Starts redis in a container, runs the test, cleans up.
$ErrorActionPreference = "Stop"
docker run --rm -d --name phpirates-test-redis -p 6399:6379 redis:7-alpine | Out-Null
try {
  $env:REDIS_URL = "redis://localhost:6399/0"
  python tests\test_redis_logic.py
  $code = $LASTEXITCODE
} finally {
  docker rm -f phpirates-test-redis | Out-Null
}
exit $code
