"""Snapshot a swarm run for show-and-tell. Read-only: agents never read this output.

Runs inside a one-off agent container (it has Redis access and the server volumes).
scripts/export-run.ps1 runs it and the result lands in runs/<stamp>/ on the host.

Writes <EXPORT_DIR>/<stamp>/:
  SUMMARY.md                      one table: every vuln, status, who patched it, notes
  state.json                      raw tickets + live agents, exactly as in Redis
  <server>/<vuln>/original.php    the vulnerable file as first seen
  <server>/<vuln>/patched.php     the file as it is now on the server
  <server>/<vuln>/fix.diff        unified diff original -> patched
"""
import difflib
import json
import os
import sys
import time

import redis

stamp = sys.argv[1] if len(sys.argv) > 1 else time.strftime("%Y%m%d-%H%M%S")
servers_dir = os.environ.get("SERVERS_DIR", "/servers")
out = os.path.join(os.environ.get("EXPORT_DIR", "/tmp/export"), stamp)
r = redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)

keys = sorted(r.scan_iter("vuln:*", count=500))
tickets = [json.loads(v) for v in r.mget(keys) if v] if keys else []
akeys = sorted(r.scan_iter("agent:*", count=500))
agents = [json.loads(v) for v in r.mget(akeys) if v] if akeys else []

os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "state.json"), "w", encoding="utf-8") as f:
    json.dump({"exported_at": time.strftime("%Y-%m-%d %H:%M:%S"), "tickets": tickets, "agents": agents}, f, indent=2)

rows = []
for t in tickets:
    sid, vid = t["server"], t["vuln"]
    d = os.path.join(out, sid, vid)
    os.makedirs(d, exist_ok=True)
    original = r.get("orig:%s:%s" % (sid, vid)) or ""
    try:
        with open(os.path.join(servers_dir, sid, t["file"]), encoding="utf-8") as f:
            current = f.read()
    except OSError:
        current = ""
    for name, text in (("original.php", original), ("patched.php", current)):
        with open(os.path.join(d, name), "w", encoding="utf-8", newline="") as f:
            f.write(text)
    diff = "".join(difflib.unified_diff(original.splitlines(True), current.splitlines(True),
                                        "original/" + t["file"], "patched/" + t["file"]))
    with open(os.path.join(d, "fix.diff"), "w", encoding="utf-8", newline="") as f:
        f.write(diff)
    changed = sum(1 for l in diff.splitlines() if l[:1] in "+-" and l[:3] not in ("+++", "---"))
    fails = sum(1 for a in t.get("attempts", []) if a.startswith("FAIL"))
    takeovers = sum(1 for a in t.get("attempts", []) if a.startswith("LEASE"))
    rows.append("| %s | %s | %s | %s | %s | %d | %d | %d | %s |" % (
        sid, vid, t["type"], t["status"].upper(), t.get("patched_by") or t.get("claimed_by") or "-",
        fails, takeovers, changed, (t.get("verified") or "").replace("|", "/")))

green = sum(1 for t in tickets if t["status"] == "green")
summary = [
    "# PHPirates run %s" % stamp,
    "",
    "**%d / %d vulnerabilities patched and verified** by %d live agents. "
    "No coordinator: agents claimed work through Redis locks only." % (green, len(tickets), len(agents)),
    "",
    "| server | vuln | type | status | patched by | failed attempts | lease takeovers | lines changed | verification |",
    "|---|---|---|---|---|---|---|---|---|",
] + rows + [
    "",
    "Each `<server>/<vuln>/` folder has `original.php`, `patched.php` and `fix.diff`. "
    "\"verification\" is the output of that vuln's exploit script after the patch: "
    "the attack is blocked AND normal use still works.",
    "",
]
with open(os.path.join(out, "SUMMARY.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(summary))
print(out)
