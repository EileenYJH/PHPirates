# Build step 5 demo: SIGKILL whichever agent currently holds a lock.
# Its lock stops being renewed, Redis expires it after LOCK_TTL seconds,
# and another agent picks the ticket up. Nothing "detects" the death.
$lock = docker compose exec -T redis redis-cli --scan --pattern 'lock:*' | Select-Object -First 1
if (-not $lock) { Write-Host "Nobody is patching right now - try again in a moment."; exit 1 }
$holder = (docker compose exec -T redis redis-cli GET $lock).Trim()
$ttl = (docker compose exec -T redis redis-cli TTL $lock).Trim()
$container = $holder.Split('-')[0]   # agent id = <container hostname>-<suffix>
Write-Host "Killing $holder (holds $lock, lease ${ttl}s left)"
docker kill $container | Out-Null
Write-Host "Watch the dashboard: the ticket goes 'lease expired', then another agent takes it."
