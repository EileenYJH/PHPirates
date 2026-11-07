# Save a snapshot of the current run to runs\<timestamp>\ for judges/teammates:
# SUMMARY.md, state.json, and original/patched/diff for every vulnerability.
# Read-only: uses a throwaway container, does not touch agents or Redis contents.
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Force -Path runs | Out-Null
$runs = (Resolve-Path runs).Path
Get-Content scripts\export_run.py -Raw |
  docker compose run --rm --no-deps -T -v "${runs}:/out" -e EXPORT_DIR=/out agent-a python - $stamp | Out-Null
if (Test-Path "runs\$stamp\SUMMARY.md") {
  Write-Host "Saved runs\$stamp"
  Get-Content "runs\$stamp\SUMMARY.md"
} else {
  Write-Host "Export failed - is the stack up? (docker compose ps)"
  exit 1
}
