#!/usr/bin/env python3
"""PHPirates stigmergic patching agent.

Every replica runs this file independently. There is no coordinator: agents
never talk to each other, they only read and write shared Redis state.

  vuln:{server}:{vuln}  JSON ticket: status red|amber|green, type, claimed_by,
                        attempts[], lease_expires, ...
  lock:{server}:{vuln}  the claim. Value = agent id, Redis TTL = lease.
                        If the holder dies it stops renewing, the key expires,
                        and the ticket is free again. Absence of the lock IS the
                        "agent died" signal; there is no detection logic.
  orig:{server}:{vuln}  pristine copy of the vulnerable file (first write wins)
  agent:{id}            heartbeat with a short TTL, only for the dashboard

Usage:
  python agent.py                       # swarm mode (needs Redis)
  python agent.py --solo s1 sqli-login  # build step 3: patch one bug, no Redis
"""
import argparse
import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
import uuid

import llm

SERVERS_DIR = os.environ.get("SERVERS_DIR", "/servers")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
SPECIALISMS = [s.strip() for s in os.environ.get("SPECIALISMS", "sqli,xss,fileupload").split(",") if s.strip()]
LOCK_TTL = int(os.environ.get("LOCK_TTL", "90"))
RENEW_EVERY = max(1.0, LOCK_TTL / 3.0)
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "3"))
ESCALATE_AFTER = int(os.environ.get("ESCALATE_AFTER", "2"))
WORK_DELAY = float(os.environ.get("WORK_DELAY", "0"))      # demo: hold the lease longer
FAIL_COOLDOWN = float(os.environ.get("FAIL_COOLDOWN", "20"))  # let other agents try first
EXPLOIT_TIMEOUT = float(os.environ.get("EXPLOIT_TIMEOUT", "60"))
AGENT_ID = os.environ.get("AGENT_ID") or "%s-%s" % (socket.gethostname(), uuid.uuid4().hex[:4])

VULNERABLE, PATCHED, BROKEN, UNREACHABLE = 0, 1, 2, 3

working_on = None  # read by the heartbeat thread, display only


def log(msg):
    print("%s [%s] %s" % (time.strftime("%H:%M:%S"), AGENT_ID, msg), flush=True)


def lock_key(vkey):
    return "lock:" + vkey.split(":", 1)[1]


def orig_key(vkey):
    return "orig:" + vkey.split(":", 1)[1]


# ---------------------------------------------------------------- environment

def load_manifests():
    """{server_id: [vuln, ...]} from /servers/<id>/vulns.json on mounted volumes."""
    out = {}
    if not os.path.isdir(SERVERS_DIR):
        return out
    for sid in sorted(os.listdir(SERVERS_DIR)):
        try:
            with open(os.path.join(SERVERS_DIR, sid, "vulns.json"), encoding="utf-8") as f:
                out[sid] = json.load(f)["vulns"]
        except (OSError, ValueError, KeyError):
            continue
    return out


def server_url(sid):
    # Compose service name == server id, so http://s1 reaches server s1.
    return os.environ.get("URL_" + sid.upper(), "http://" + sid)


def run_exploit(sid, ticket):
    script = os.path.join(SERVERS_DIR, sid, ticket["exploit"])
    try:
        p = subprocess.run([sys.executable, script, server_url(sid)],
                           capture_output=True, text=True, timeout=EXPLOIT_TIMEOUT,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    except subprocess.TimeoutExpired:
        return UNREACHABLE, "exploit script timed out"
    lines = p.stdout.strip().splitlines()
    detail = lines[-1] if lines else p.stderr.strip()[-200:]
    try:
        detail = json.loads(detail).get("detail", detail)
    except (ValueError, AttributeError):
        pass
    code = p.returncode if p.returncode in (0, 1, 2, 3) else UNREACHABLE
    return code, detail


def read_file(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_atomic(path, text):
    """Write via rename so a killed agent never leaves a half-written PHP file."""
    tmp = "%s.%s.tmp" % (path, AGENT_ID)
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def attempt_patch(sid, ticket, lease, pristine):
    """One patch attempt. Returns (outcome, note); outcome is
    patched | failed | skipped | lost."""
    path = os.path.join(SERVERS_DIR, sid, ticket["file"])

    # Verify first: a previous holder may have written a good patch and died
    # before marking the ticket green.
    code, detail = run_exploit(sid, ticket)
    if code == PATCHED:
        return "patched", "already fixed, verified: " + detail
    if code == UNREACHABLE:
        return "skipped", "server unreachable: " + detail
    if code == BROKEN and pristine is not None:
        log("site is broken (left by a dead agent?); restoring the pristine file first")
        write_atomic(path, pristine)

    current = read_file(path)
    failures = [a for a in ticket.get("attempts", []) if a.startswith("FAIL")]
    escalated = len(failures) >= ESCALATE_AFTER
    model = llm.STRONG_MODEL if escalated else llm.MODEL
    log("asking %s for a %s patch of %s:%s%s" % (
        model, ticket["type"], sid, ticket["file"], " (ESCALATED)" if escalated else ""))

    try:
        patched = llm.request_patch(ticket["file"], ticket["type"], current,
                                    failures if escalated else None, model)
    except Exception as e:  # model down / timeout is not the patch's fault
        return "skipped", "model call failed: %s" % e

    deadline = time.time() + WORK_DELAY
    while time.time() < deadline and not lease.lost:
        time.sleep(0.5)

    if not lease.still_mine():
        return "lost", ""
    if not patched:
        return "failed", "model %s returned no usable PHP file" % model

    write_atomic(path, patched)
    code, detail = run_exploit(sid, ticket)
    if code == PATCHED:
        return "patched", "verified: " + detail

    # Revert so the site keeps working and the next agent starts from clean code.
    write_atomic(path, current)
    reason = {VULNERABLE: "exploit still works", BROKEN: "patch broke the site",
              UNREACHABLE: "server unreachable after patch"}.get(code, "unknown result")
    return "failed", "%s (%s) [%s%s]" % (reason, detail, model, ", escalated" if escalated else "")


# ---------------------------------------------------------------- the lease

RENEW_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 0
"""
RELEASE_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"""
# Fenced write: only the current lock holder may change the ticket.
WRITE_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[2], ARGV[2])
  return 1
end
return 0
"""


class Lease:
    """A claim on one ticket. A background thread renews the lock key's TTL;
    if this process dies, renewal stops and Redis expires the lock by itself."""

    def __init__(self, r, vkey):
        import redis  # noqa: F401  (only needed in swarm mode)
        self.r = r
        self.vkey = vkey
        self.lkey = lock_key(vkey)
        self.lost = False
        self._mutex = threading.Lock()
        self._stop = threading.Event()
        self._last_ok = time.time()
        self._renew = r.register_script(RENEW_LUA)
        self._release = r.register_script(RELEASE_LUA)
        self._write = r.register_script(WRITE_LUA)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _run(self):
        import redis
        while not self._stop.wait(RENEW_EVERY):
            try:
                if self._renew(keys=[self.lkey], args=[AGENT_ID, LOCK_TTL]):
                    self._last_ok = time.time()
                    self.modify(lambda t: t.update(lease_expires=time.time() + LOCK_TTL))
                else:
                    self.lost = True
                    log("lease on %s is gone (expired or taken over)" % self.vkey)
                    return
            except redis.RedisError as e:
                if time.time() - self._last_ok > LOCK_TTL:
                    self.lost = True
                    log("cannot reach Redis for a whole lease period; assuming lease lost (%s)" % e)
                    return

    def still_mine(self):
        if self.lost:
            return False
        try:
            return self.r.get(self.lkey) == AGENT_ID
        except Exception:
            return False

    def read(self):
        return json.loads(self.r.get(self.vkey))

    def modify(self, fn):
        """Read-modify-write the ticket, only if we still hold the lock."""
        with self._mutex:
            if self.lost:
                return False
            t = self.read()
            fn(t)
            t["updated_at"] = time.time()
            ok = self._write(keys=[self.lkey, self.vkey], args=[AGENT_ID, json.dumps(t)])
            if not ok:
                self.lost = True
            return bool(ok)

    def release(self):
        self._stop.set()
        try:
            self._release(keys=[self.lkey], args=[AGENT_ID])
        except Exception as e:
            log("could not release %s (it will expire on its own): %s" % (self.lkey, e))


class SoloLease:
    """Stand-in used by --solo (no Redis)."""
    lost = False

    def still_mine(self):
        return True


# ---------------------------------------------------------------- swarm loop

def seed(r, manifests):
    """Idempotently publish tickets for every vuln this agent can see.
    SET NX means whichever agent gets there first creates it; nobody owns seeding."""
    for sid, vulns in manifests.items():
        for v in vulns:
            key = "vuln:%s:%s" % (sid, v["id"])
            ticket = {
                "server": sid, "vuln": v["id"], "type": v["type"],
                "file": v["file"], "exploit": v["exploit"],
                "status": "red", "claimed_by": None, "attempts": [],
                "lease_expires": None, "updated_at": time.time(),
            }
            if r.set(key, json.dumps(ticket), nx=True):
                log("published ticket " + key)
            if not r.exists(orig_key(key)):
                try:
                    r.set(orig_key(key), read_file(os.path.join(SERVERS_DIR, sid, v["file"])), nx=True)
                except OSError:
                    pass


def pick_and_claim(r, cooldown):
    keys = list(r.scan_iter("vuln:*", count=500))
    if not keys:
        return None
    tickets = r.mget(keys)
    locks = r.mget([lock_key(k) for k in keys])
    now = time.time()
    candidates = []
    for key, raw, lock in zip(keys, tickets, locks):
        if raw is None or lock is not None:      # live lock = someone is on it
            continue
        t = json.loads(raw)
        if t.get("status") == "green" or t.get("type") not in SPECIALISMS:
            continue
        if cooldown.get(key, 0) > now:
            continue
        candidates.append(key)
    random.shuffle(candidates)
    for key in candidates:
        # Atomic claim: exactly one agent's SET NX succeeds.
        if r.set(lock_key(key), AGENT_ID, nx=True, ex=LOCK_TTL):
            return key
    return None


def work(r, key, cooldown):
    global working_on
    lease = Lease(r, key).start()
    working_on = key
    try:
        ticket = lease.read()
        if ticket.get("status") == "green":     # finished by someone between scan and claim
            return
        prev = ticket.get("claimed_by")
        takeover = ticket.get("status") == "amber" and prev and prev != AGENT_ID

        def claim(t):
            if takeover:
                t["attempts"].append("LEASE %s went silent; lock expired; taken over by %s" % (prev, AGENT_ID))
            t.update(status="amber", claimed_by=AGENT_ID, lease_expires=time.time() + LOCK_TTL)

        if not lease.modify(claim):
            return
        log("claimed %s (%s)%s" % (key, ticket["type"], " - TAKEOVER from dead " + prev if takeover else ""))

        try:
            outcome, note = attempt_patch(ticket["server"], lease.read(), lease, r.get(orig_key(key)))
        except Exception as e:
            outcome, note = "failed", "agent error: %s" % e

        if outcome == "lost":
            log("lost the lease on %s mid-patch; dropping it" % key)
        elif outcome == "patched":
            lease.modify(lambda t: t.update(status="green", claimed_by=None, patched_by=AGENT_ID,
                                            lease_expires=None, verified=note))
            log("GREEN %s: %s" % (key, note))
        elif outcome == "failed":
            def fail(t):
                t["attempts"].append(("FAIL %s: %s" % (AGENT_ID, note))[:300])
                t.update(status="red", claimed_by=None, lease_expires=None)
            lease.modify(fail)
            cooldown[key] = time.time() + FAIL_COOLDOWN
            log("failed %s: %s" % (key, note))
        else:  # skipped: environment problem, not counted as a failed patch
            lease.modify(lambda t: t.update(status="red", claimed_by=None, lease_expires=None, last_note=note))
            cooldown[key] = time.time() + POLL_INTERVAL * 3
            log("skipped %s: %s" % (key, note))
    finally:
        lease.release()
        working_on = None


def heartbeat(r):
    import redis
    while True:
        try:
            r.set("agent:" + AGENT_ID, json.dumps({
                "id": AGENT_ID, "specialisms": SPECIALISMS,
                "working_on": working_on, "seen": time.time(),
            }), ex=10)
        except redis.RedisError:
            pass
        time.sleep(3)


def swarm():
    import redis
    r = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=10)
    log("up. specialisms=%s model=%s strong=%s lock_ttl=%ss" % (
        ",".join(SPECIALISMS), llm.MODEL, llm.STRONG_MODEL, LOCK_TTL))
    threading.Thread(target=heartbeat, args=(r,), daemon=True).start()
    cooldown = {}
    while True:
        try:
            seed(r, load_manifests())
            key = pick_and_claim(r, cooldown)
            if key is None:
                time.sleep(POLL_INTERVAL + random.random())
                continue
            work(r, key, cooldown)
            time.sleep(random.random())
        except redis.RedisError as e:
            log("Redis unavailable (%s); retrying" % e)
            time.sleep(POLL_INTERVAL)


def solo(sid, vuln_id):
    vulns = load_manifests().get(sid)
    if not vulns:
        sys.exit("no manifest found at %s/%s/vulns.json" % (SERVERS_DIR, sid))
    v = next((x for x in vulns if x["id"] == vuln_id), None)
    if v is None:
        sys.exit("unknown vuln %s; have: %s" % (vuln_id, ", ".join(x["id"] for x in vulns)))
    ticket = dict(v, server=sid, attempts=[])
    pristine = read_file(os.path.join(SERVERS_DIR, sid, v["file"]))
    outcome, note = attempt_patch(sid, ticket, SoloLease(), pristine)
    log("%s: %s" % (outcome.upper(), note))
    sys.exit(0 if outcome == "patched" else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--solo", nargs=2, metavar=("SERVER", "VULN"), help="patch one vuln without Redis")
    args = ap.parse_args()
    if args.solo:
        solo(*args.solo)
    else:
        swarm()
