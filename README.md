# PHPatch

**Team PHPirates — Neptune North @ GreatUniHack 2026**

A self-coordinating PHP patch fleet. When a worm exploits a PHP backdoor, every
server runs an agent that patches itself, verifies the fix, and passes it to its
neighbours — so immunity spreads across the fleet faster than the worm spreads
infection, and no single point of failure can stop it.

## The idea

Most distributed systems are built to stay consistent: when the network splits,
they stop. PHPatch is built to keep working. Each server decides for itself,
shares the cure with whoever it can reach, tells the truth about its own state,
and heals the moment communications return.

This answers the Neptune North brief directly — actors that work toward a common
goal, make decisions independently, and keep making progress even when they
cannot communicate.

## How it works

Each server moves through three states:

| State | Meaning |
|-------|---------|
| 🔴 **Red** | PHP backdoor present, website vulnerable |
| 🟠 **Amber** | worm is in, PHP runtime patched, agent now cleaning the site |
| 🟢 **Green** | agent has verified the site is vulnerability-free — now a patch source |

- The **worm** travels the Docker bridge and carries the patch kit with it.
- A **dispatcher** helps bootstrap the first fixes, but it is a *helper, not a hub*.
- Cleaning an amber server needs a **patch source**: the dispatcher, or a **green
  neighbour** handing over its cached fixes (peer kit).
- Kill the dispatcher and the cure still spreads server-to-server. Only a fully
  isolated server with no fix yet will stall — and it reports that honestly
  rather than falsely declaring itself clean.

## Demo dashboard

`ui/fleet-patch-console.html` is a self-contained ops-room dashboard (no internet
required — fits the air-gapped lab). It shows the live network graph, a dispatcher
online/offline indicator, a fleet-state chart, an agent/worm log, and chaos
controls:

- **Release worm** — or click any node to seed it there
- **Kill dispatcher** — watch the cure keep spreading peer-to-peer
- **Kill a server** / **Cut links** — prove resilience to node loss and partitions

It runs a built-in simulation out of the box. To go live, wire real server
telemetry into the `pollServers()` / `applyFleet()` hooks near the bottom of the
file.

## Safety & scope

Everything runs in an **air-gapped lab** on our own deliberately-vulnerable
servers. The "worm" is a scoped remediation agent that only ever touches the
authorised fleet — never the open internet. We built this to study whether
automated remediation can outrun a threat, and to show why real-world "vigilante
patching" is as dangerous as it is tempting (no consent, unpredictable blast
radius).
