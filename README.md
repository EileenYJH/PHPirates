# PHPatch

**Team PHPirates — Neptune North @ GreatUniHack 2026**

A self-healing patch swarm. When a worm exploits a PHP vulnerability, a fleet of
autonomous agents patches every server and verifies the fix — spreading immunity
the way a worm spreads infection, with **no central controller to take down**.

## The idea

Most distributed systems are built to stay consistent: when the network splits,
they stop. PHPatch is built to keep working. The agents never talk to each other
— they coordinate **only through a shared board** (stigmergy, like ants leaving
trails). Each agent decides for itself, tells the truth about what it has done,
and the fleet heals the moment communications return.

This answers the Neptune North brief directly: identical actors working toward a
common goal, deciding independently, and still making progress when they cannot
communicate — with no hub whose failure stops everything.

## Architecture

```
            ┌──────────────┐        ┌───────────┐
   Ollama ──┤   Agents ×N  ├── reads ┤ Dashboard │  (read-only observer)
  (writes   │  (identical) │        └───────────┘
   patches) └──────┬───────┘
                   │ claim lease · write ticket (the ONLY coordination)
            ┌──────┴───────┐
            │ Redis — the  │   vuln:   ticket (red / amber / green)
            │ shared board │   lock:   the lease (SET NX EX); its TTL = the claim
            └──────┬───────┘   orig:   pristine copy of the file
                   │ run exploit · write patched file
            ┌──────┴───────┐
            │  s1 · s2 · s3 │  deliberately-vulnerable PHP sites
            └───────────────┘
```

- **No coordinator.** Agents communicate only by reading and writing Redis keys.
- **Identical code.** Every agent runs the same loop; they differ only by which
  vulnerability types they specialise in, so each bug is covered by several agents.
- **Ground truth.** Exploit scripts decide the outcome (`VULNERABLE / PATCHED /
  BROKEN / UNREACHABLE`) and also check that normal use still works — so "delete
  the feature" never counts as a fix.

## The agent loop

1. **Seed** — publish a ticket for every vulnerability it can see (`SET NX`; whoever
   is first wins, nobody owns seeding).
2. **Claim** — take an unclaimed ticket in its specialism with `SET lock NX EX`;
   exactly one agent wins, and the lock's TTL is the lease.
3. **Verify first** — run the exploit; if a dead predecessor already fixed it, mark
   it green without calling the model.
4. **Patch** — ask the local LLM (Ollama) for a fixed file, write it atomically.
5. **Re-verify** — run the exploit again. Green on success; on failure, **revert**
   the file and record a FAIL. After two fails it escalates to a stronger model.
6. **Release** the lease.

## Resilience (the point)

| State on the board | Meaning |
|---|---|
| 🔴 **red** | vulnerable, unclaimed |
| 🟠 **amber** | an agent holds a live lease and is patching |
| ⚪ **orphaned** | the holder's lease expired — reclaimable |
| 🟢 **green** | exploit now fails and normal use still works |

- **Agent death needs no detector.** A dead agent stops renewing its lock; Redis
  expires it; the ticket becomes claimable again. The *absence of the lock* is the
  "it died" signal. Another agent logs `TAKEOVER` and finishes the work.
- **Zombie-safe.** A frozen agent that wakes up finds the lock is no longer its own
  and drops the work; ticket writes are fenced (compare-and-set on the lock).
- **Honest state.** An agent that cannot verify a fix never claims "clean."

## Demo dashboard

`ui/fleet-patch-console.html` is a self-contained ops-room console (no internet
required — fits the air-gapped lab). It shows:

- a **live architecture map** — dots travel the links as agents coordinate on the
  shared board, call Ollama, and verify against targets;
- the **shared board** — one ticket per bug, with live lease bars and takeover;
- **agents** with their state (working / idle / isolated / down);
- a **fleet-state chart** and a **swarm log**.

**Guided demos** (each resets, gets the swarm busy, then triggers one feature):
lease takeover, Redis-down → gossip fallback, network partition, re-scan catch,
cached patch. Plus manual chaos controls (kill an agent, kill Redis, isolate) and
a **Scale** toggle (24 servers · 72 tickets · 12 agents).

It runs a built-in simulation out of the box; wire real telemetry into the
`pollServers()` / `applyState()` hooks near the bottom of the file to go live
against the actual Redis state.

See **[RUNNING.md](RUNNING.md)** to build and run the real swarm with Docker.

## Safety & scope

Everything runs in an **air-gapped lab** on our own deliberately-vulnerable
servers. The agents only ever touch the authorised fleet — never the open
internet. We built this to study whether automated remediation can outrun a
threat, and to show why real-world "vigilante patching" is as dangerous as it is
tempting (no consent, unpredictable blast radius). We spread immunity, not
malware.
