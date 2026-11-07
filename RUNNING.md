# Running PHPirates

Stigmergic patching swarm: agents coordinate **only** through Redis keys. There is no
coordinator; the dashboard is a read-only observer. Commands below are PowerShell from
the repo root (bash works the same).

## Layout

```
docker-compose.yml          3 PHP servers, 4 agents, Redis, dashboard
src/target/                 vulnerable toy PHP site (image for s1..s3)
  site/vulns.json           manifest: vuln id, type, file, exploit script
  site/public/*.php         login.php (SQLi), search.php (XSS), upload.php (file upload)
  site/exploits/*.py        ground truth. exit 0 VULNERABLE, 1 PATCHED, 2 BROKEN, 3 UNREACHABLE
src/agent/agent.py          the agent loop (identical code in every replica)
src/agent/test_redis_logic.py  proves the lock/lease guarantees against real Redis
src/agent/llm.py            OpenAI-compatible client + patch prompts (stdlib only)
src/dashboard/              Flask + one HTML page, polls /api/state every 2 s
scripts/check_ollama.py     build step 1
scripts/kill-a-holder.ps1   build step 5 demo (also .sh)
scripts/export-run.ps1      save a run snapshot to runs/ (also .sh)
```

The exploit scripts also check that normal use still works (valid login, plain search,
PNG upload), so "delete the feature" never counts as a fix — that comes back BROKEN.

## Prove the coordination logic (no Docker, no Ollama)

The whole "no coordinator" claim rests on the Redis lock/lease primitives. `tests/` drives
the *real* ones from `agent.py` against a throwaway Redis and asserts all 8 guarantees
(atomic claim, fenced renew, lease expiry, takeover, fenced write, fenced release, live
renewal). ~15s, deterministic:

```
.\tests\run.ps1
```
Needs only Docker (it starts a short-lived redis). Expect `8 passed, 0 failed`. This is the
quickest thing to show a judge or hand a teammate as a regression gate.

## Build steps

**1. Ollama returns a patched file** (host, no Docker):
```
ollama pull qwen2.5:7b
python scripts/check_ollama.py
python scripts/check_ollama.py --file src/target/site/public/upload.php --type fileupload
```

**2. One vulnerable container + exploit script**
```
docker compose build
docker compose up -d s1
docker compose run --rm --no-deps agent-a python /servers/s1/exploits/sqli.py http://s1
```
Expect `{"result": "VULNERABLE", ...}`.

**3. One agent patches one bug, no Redis**
```
docker compose run --rm --no-deps agent-a python agent.py --solo s1 sqli-login
```
Expect `PATCHED: verified: ...`. Run it again: it verifies first and skips the model.

**Prove the Redis coordination logic** (no model, no servers, ~10s) — exercises the
real Lua scripts and the real `Lease` class from `agent.py`:
```
docker compose up -d redis
docker compose run --rm --no-deps agent-a python test_redis_logic.py
```
Expect `15/15 guarantees held`: mutual exclusion, fenced writes, owner-only
release/renewal, lease expiry on death, and live takeover.

**4–6. Whole swarm**
```
docker compose up -d
docker compose logs -f agent-a agent-b agent-c agent-d
```
Dashboard: http://localhost:5000

**5. Kill an agent mid-patch** (the key demo). Use a short lease and a visible work
window so the takeover happens quickly on stage:
```
$env:LOCK_TTL=20; $env:WORK_DELAY=30; docker compose up -d --force-recreate
.\scripts\kill-a-holder.ps1
```
The ticket turns "lease expired" on the dashboard once the lock key's TTL runs out, then
another agent claims it and logs `TAKEOVER from dead <id>`.

**Save a run for judges / teammates** (before you reset):
```
.\scripts\export-run.ps1
```
Writes `runs\<timestamp>\` with `SUMMARY.md` (every bug, who fixed it, failures,
takeovers, verification result), `state.json` (raw Redis tickets) and, per bug,
`original.php`, `patched.php` and `fix.diff`. Agents never read it.

**Reset everything** (fresh vulnerable files + empty Redis):
```
docker compose down -v
```
Site files live in named volumes seeded from the image on first start, so after editing
anything under `src/target/site/` you need `down -v` and `build` for it to show up.

## Dashboard metrics

The dashboard (`localhost:5000`) shows two live figures, derived only from Redis so they
read the same whenever you open the page:

- **patches/min** — verified fixes divided by the window the swarm was actually working
  (first activity → last fix). It does not decay after the run finishes.
- **effectiveness** — verified fixes / patch attempts, where an attempt is each fix plus
  each failed patch (a patch that did not pass its exploit check). Human rejections excluded.

Every ticket also has a **view diff** expander, so you can see exactly what the model changed.

## Optional: human-in-the-loop approvals (n8n track)

Off by default — the core demo is unchanged. Turn it on and every verified patch waits for
a human before it goes live:

```
$env:REQUIRE_APPROVAL=1; docker compose up -d --build
```

Flow (still stigmergic — the approver only flips one field in shared state, it never assigns
work): an agent patches a bug, verifies it with the exploit script, **stages** the patch and
**reverts the live file to vulnerable**, parking the ticket at `review`. Nothing is live yet.
On the dashboard the ticket shows "awaiting approval" with its diff and Approve / Reject buttons.

Approve it any of these ways — all write the same shared state:

- **On the dashboard (`localhost:5000`):** click Approve/Reject on the ticket. (The buttons call
  the approvals API below; the dashboard never writes Redis itself.)
- **Approvals API / page (`localhost:5001`):** the same buttons on a dedicated page, or
  `curl -X POST http://localhost:5001/api/approve -H "Content-Type: application/json" -d "{\"key\":\"vuln:s1:sqli-login\"}"`
- **n8n:** `docker compose --profile n8n up -d`, open http://localhost:5678, import
  `n8n/approval-workflow.json`, activate it. It polls `/api/reviews` and drives the same API.

On **approve** an agent applies the staged patch, re-runs the exploit, and goes green. On
**reject** the ticket returns to red with the reason and gets re-patched.

### Proving the approval ran through n8n

Each approval is stamped with **who did it**: the dashboard buttons record `approved_by:"dashboard"`,
the n8n workflow records `approved_by:"n8n"`. So an approved ticket on the dashboard literally
shows "approved by n8n". Combined with n8n's own **Executions** tab (every approval appears there
with a timestamp), that is on-screen evidence the approval flowed through n8n, not the fallback.

The approvals service is read-mostly and non-critical: if it dies, tickets simply wait in `review`.

## Config (env, see docker-compose.yml)## Config (env, see docker-compose.yml)

| var | default | meaning |
|---|---|---|
| `LLM_BASE_URL` | `http://host.docker.internal:11434/v1` | Ollama's OpenAI endpoint |
| `LLM_MODEL` | `qwen2.5:7b` | normal model |
| `LLM_MODEL_STRONG` | same as `LLM_MODEL` | used after 2 failed attempts |
| `LOCK_TTL` | `90` | lease seconds; renewed every TTL/3 |
| `WORK_DELAY` | `0` | extra seconds holding the lease (demo only) |
| `REQUIRE_APPROVAL` | off | `1` = require human approval before a patch goes live (n8n track) |

## How coordination works

| key | written by | meaning |
|---|---|---|
| `vuln:{server}:{vuln}` | lock holder only (fenced Lua write) | JSON ticket |
| `lock:{server}:{vuln}` | `SET NX EX` by the claimer | the lease; expiry = release |
| `orig:{server}:{vuln}` | first agent to see it (`SET NX`) | pristine file, used to repair a site a dead agent broke |
| `agent:{id}` | each agent, TTL 10 s | heartbeat for the dashboard only |
| `patch:{server}:{vuln}` | proposer (approval mode) | staged patch, applied verbatim on approval |

- **Seeding:** every agent publishes tickets for the manifests it can see with `SET NX`; nobody owns this.
- **Claim:** `SET lock NX EX ttl` — exactly one agent wins.
- **Renewal:** a thread extends the TTL only if the lock still holds this agent's id.
- **Death:** renewal stops, Redis expires the key, the ticket is claimable again. No detector.
- **Zombies:** an agent that froze and wakes up after losing its lease sees the lock is no
  longer its own and drops the work; ticket writes are compare-and-set on the lock, so it
  can't overwrite the new holder.
- **Verify first:** a new holder runs the exploit before calling the model, so a good patch
  written by an agent that died before marking green is recognised immediately.
- **Failure:** the file is reverted (site keeps working), a `FAIL` note is appended, the
  ticket goes back to red. After 2 `FAIL` notes the next attempt uses the strong prompt
  (previous failures included) and `LLM_MODEL_STRONG`.

## Network note

`swarm` is an `internal` network: servers and Redis have no route out. Agents and the
dashboard are also on `hostlink`, a normal bridge, because agents must reach Ollama on
the host and the dashboard must publish port 5000. That bridge does have outbound
access; if you need agents fully air-gapped, run Ollama as a Compose service on `swarm`
instead (mount your host's models directory into it).
