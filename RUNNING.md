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
src/agent/llm.py            OpenAI-compatible client + patch prompts (stdlib only)
src/dashboard/              Flask + one HTML page, polls /api/state every 2 s
scripts/check_ollama.py     build step 1
scripts/kill-a-holder.ps1   build step 5 demo (also .sh)
```

The exploit scripts also check that normal use still works (valid login, plain search,
PNG upload), so "delete the feature" never counts as a fix — that comes back BROKEN.

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

**Reset everything** (fresh vulnerable files + empty Redis):
```
docker compose down -v
```
Site files live in named volumes seeded from the image on first start, so after editing
anything under `src/target/site/` you need `down -v` and `build` for it to show up.

## Config (env, see docker-compose.yml)

| var | default | meaning |
|---|---|---|
| `LLM_BASE_URL` | `http://host.docker.internal:11434/v1` | Ollama's OpenAI endpoint |
| `LLM_MODEL` | `qwen2.5:7b` | normal model |
| `LLM_MODEL_STRONG` | same as `LLM_MODEL` | used after 2 failed attempts |
| `LOCK_TTL` | `90` | lease seconds; renewed every TTL/3 |
| `WORK_DELAY` | `0` | extra seconds holding the lease (demo only) |

## How coordination works

| key | written by | meaning |
|---|---|---|
| `vuln:{server}:{vuln}` | lock holder only (fenced Lua write) | JSON ticket |
| `lock:{server}:{vuln}` | `SET NX EX` by the claimer | the lease; expiry = release |
| `orig:{server}:{vuln}` | first agent to see it (`SET NX`) | pristine file, used to repair a site a dead agent broke |
| `agent:{id}` | each agent, TTL 10 s | heartbeat for the dashboard only |

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
