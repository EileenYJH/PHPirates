# PHPatch

**Team PHPirates — Neptune North @ GreatUniHack 2026**

A self-coordinating PHP patch swarm. A fleet of identical agents watches a set of
vulnerable web servers and races to patch them — writing a fix, *verifying it with
a real exploit*, and publishing the result for the others. There is no coordinator
and no master: the agents only ever read and write one shared board (Redis), so the
fleet keeps healing even when agents die, the network splits, or the board itself
goes down.

## The idea

Most distributed systems are built to stay consistent: when something breaks, they
stop. PHPatch is built to keep working. Each agent decides for itself what to patch,
tells the truth about what it verified, and never needs permission from a hub. Kill
any agent — or several — and the work it was holding is simply picked up by another.

This answers the Neptune North brief directly: independent actors working toward a
common goal, making decisions on their own, and continuing to make progress even when
they cannot communicate.

The coordination model is **stigmergic** — like ants leaving trails. Agents never talk
to each other. They leave marks on a shared blackboard (Redis keys) and react to the
marks they find. The *absence* of a mark (an expired lock) is itself the signal that
an agent has died; there is no failure detector anywhere in the system.

## How it works

Each vulnerability on each server is one **ticket** on the board, and moves through
three states:

| State | Meaning |
|-------|---------|
| 🔴 **red** | vulnerability confirmed present; ticket is open for any agent to claim |
| 🟠 **amber** | an agent holds a live lease and is patching it right now |
| 🟢 **green** | an agent wrote a fix and a real exploit script confirmed it's gone — this is now the trusted state |

The agent loop (identical code in every replica, `src/agent/agent.py`):

1. **Seed** — every agent publishes a ticket for each vuln it can see with `SET NX`.
   Whoever gets there first creates it; nobody owns seeding.
2. **Claim** — `SET lock NX EX ttl`. Exactly one agent wins the lease on a ticket.
3. **Verify first** — run the ticket's exploit script *before* calling the model. A
   good patch left by an agent that died before marking it green is recognised instantly.
4. **Patch** — ask the local LLM (Ollama) for the complete fixed file, write it
   atomically, then run the exploit again. The exploit is the **ground truth**:
   `0 = VULNERABLE, 1 = PATCHED, 2 = BROKEN, 3 = UNREACHABLE`. The scripts also check
   that *normal* use still works, so "delete the feature" never counts as a fix.
5. **Publish or revert** — on PATCHED, mark the ticket green (fenced compare-and-set
   write, so only the lease holder can change it). On failure, revert the file so the
   site keeps working and append a `FAIL` note. After 2 failures the next attempt uses
   a stronger model and is shown the previous failures.
6. **Renew / die** — a background thread renews the lease every `TTL/3`. If the agent
   dies, renewal stops, Redis expires the lock, and the ticket becomes claimable again.
   The next agent to pick it up logs `TAKEOVER from dead <id>`.

Why it's resilient:

- **No single point of failure** — no coordinator to kill. The dashboard is a *read-only*
  observer; patching continues if it dies.
- **Lease takeover** — a dead agent's work is reclaimed automatically when its lock TTL expires.
- **Zombie-safe** — an agent that froze and wakes after losing its lease sees the lock is
  no longer its own and drops the work; ticket writes are compare-and-set on the lock.
- **Self-repairing site** — the first agent to see a file caches a pristine copy, used to
  restore a site that a dead agent left half-broken.
- **Redis-tolerant** — if the board is briefly unreachable, agents hold their assumption for
  one lease period rather than thrashing.

## See it running

There are two ways to watch it, depending on whether you want the full stack or just the story.
A pre-recorded 1-minute walkthrough of the console is in [`demo/phpatch-demo.mp4`](demo/phpatch-demo.mp4).

### 1. The real swarm (Docker + Ollama)

Three vulnerable PHP servers, four agents, Redis, and a live dashboard — all in Docker.
Patches are written by a local LLM through Ollama, so nothing leaves the machine.

```bash
# host: an OpenAI-compatible local model
ollama pull qwen2.5:7b

# bring up the whole fleet
docker compose up -d
docker compose logs -f agent-a agent-b agent-c agent-d
```

Open the dashboard at **http://localhost:5000** (`src/dashboard/`) — it polls Redis every
two seconds and shows every ticket's state, who holds each lease and for how long, and
which agents are alive. The headline demo is killing an agent mid-patch and watching its
lease expire and get taken over:

```bash
$env:LOCK_TTL=20; $env:WORK_DELAY=30; docker compose up -d --force-recreate
.\scripts\kill-a-holder.ps1
```

Full step-by-step build, config, and troubleshooting notes live in **[RUNNING.md](RUNNING.md)**.

### 2. The demo console (no infra required)

`ui/fleet-patch-console.html` is a self-contained ops-room dashboard — just open the file
in a browser, no Docker, Ollama, or internet needed (fits an air-gapped lab). It mirrors
the real `lock:` / `vuln:` keys in a browser simulation and adds a live architecture map,
a ticket blackboard, a fleet chart, and the swarm log, plus **guided demos** and chaos controls:

- **Lease takeover** — kill the agent holding a ticket and watch another claim it
- **Network partition** / **Kill Redis → gossip fallback** — prove the swarm survives a split board
- **Re-scan catch** — a regression is re-detected and re-patched
- **Cached patch** — a known fix is reused without calling the model
- Sliders for lease TTL, agent count, and speed; kill or isolate any agent by clicking it

## Repo layout

```
docker-compose.yml          3 PHP servers, 4 agents, Redis, dashboard
RUNNING.md                  full run / build / demo instructions
src/target/                 deliberately-vulnerable toy PHP site (image for s1..s3)
  site/vulns.json           manifest: vuln id, type, file, exploit script
  site/public/*.php         login.php (SQLi), search.php (XSS), upload.php (file upload)
  site/exploits/*.py        ground truth: exit 0 VULNERABLE, 1 PATCHED, 2 BROKEN, 3 UNREACHABLE
src/agent/agent.py          the agent loop (identical code in every replica)
src/agent/llm.py            OpenAI-compatible client + patch prompts (stdlib only)
src/dashboard/              Flask + one HTML page, read-only, polls /api/state every 2 s
ui/fleet-patch-console.html self-contained browser demo (no backend)
scripts/                    check_ollama.py (build step 1), kill-a-holder.{ps1,sh} (takeover demo)
```

## Safety & scope

Everything runs in an **air-gapped lab** on our own deliberately-vulnerable servers. The
agents are scoped remediation workers that only ever touch the authorised fleet — never
the open internet. We built this to study whether automated remediation can outrun a
threat, and to show why real-world "vigilante patching" is as dangerous as it is tempting:
no consent, and an unpredictable blast radius.
