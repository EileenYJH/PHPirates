# FleetGuard

*GreatUniHack 2026 · Neptune North Challenge — "Actors work better together"*

A fleet of PHP web servers that **patches itself against PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) **without a central controller** — and without taking the site down.

## The problem
PHP2Shell is a critical, actively exploited unauthenticated RCE in PHP core (PHP-FPM, Apache mod_php, LiteSpeed). Fixes shipped 21 Oct 2026; the advice is to patch immediately or take systems offline. Real fleets can't rely on a central console during an incident: it may be overloaded, compromised, or unreachable.

## The idea
Every server runs a small defensive agent. Agents share one goal — **patch the whole fleet while keeping ≥ X% capacity online** — and coordinate peer-to-peer:

- **Independent decisions:** each agent checks its own PHP version/SAPI against the fixed versions and decides when it is safe to drain → patch → rejoin.
- **Safe rolling patches:** at most `k` of `N` servers down at once; during a network split, a partition that sees `m` servers may only take down `floor(k·m/N)`.
- **Resilience when comms fail:** patch status and patched packages spread peer-to-peer; an isolated agent falls back to a safe local policy (protective rule / self-quarantine).
- **Reconnect:** state merges; the fleet converges to 100 % patched.

## Scope & safety
Strictly defensive. Version checks and **simulated** attack signals only — no exploit code.

## Demo
~6 simulated servers + live dashboard: alert → waves of patching → kill the console → split the network → reconnect → 100 % patched, site never went down.

## Team
- Eileen
- Saif
- Zak
- John
