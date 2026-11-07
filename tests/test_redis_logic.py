#!/usr/bin/env python3
"""Proof that the swarm's Redis coordination is correct — no Docker, no Ollama.

It drives the REAL primitives from src/agent/agent.py (the same Lua scripts and
SET NX claim the agents use) against a real Redis, and asserts each guarantee the
"no coordinator" design depends on:

  1. atomic claim      two agents race; exactly one wins
  2. fenced renew      only the lock holder can extend the lease
  3. lease expiry      a holder that stops renewing loses the lock after TTL
  4. takeover          once the lock expires, another agent can claim it
  5. fenced write      an agent that lost its lease cannot overwrite the ticket
  6. fenced release    an agent cannot release a lock it does not hold
  7. live renewal      the Lease thread keeps a lock alive past its TTL, then
                       lets it expire once stopped (long patches don't lose it)

Run:
    REDIS_URL=redis://localhost:6379/0 python tests/test_redis_logic.py
A throwaway Redis is enough:
    docker run --rm -d -p 6379:6379 redis:7-alpine
"""
import os
import sys
import threading
import time
import uuid

# Short lease so the timing tests are quick; must be set before importing agent.
os.environ.setdefault("LOCK_TTL", "2")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, "src", "agent"))
sys.dont_write_bytecode = True

import agent  # noqa: E402  (imports the real scripts, Lease, key helpers)
import redis  # noqa: E402

URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(URL, decode_responses=True)
PREFIX = "test-%s" % uuid.uuid4().hex[:8]          # isolate from any real keys
VKEY = "vuln:%s:bug" % PREFIX
LKEY = agent.lock_key(VKEY)

passed = []
failed = []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print("  %s  %s%s" % ("PASS" if cond else "FAIL", name, (" - " + detail) if detail else ""))


def cleanup():
    for k in r.scan_iter("*%s*" % PREFIX):
        r.delete(k)


# Scripts, registered the same way the agent registers them.
renew = r.register_script(agent.RENEW_LUA)
release = r.register_script(agent.RELEASE_LUA)
write = r.register_script(agent.WRITE_LUA)


def test_atomic_claim():
    cleanup()
    winners = []
    barrier = threading.Barrier(8)

    def race(agent_id):
        barrier.wait()  # all threads fire SET NX at once
        if r.set(LKEY, agent_id, nx=True, ex=agent.LOCK_TTL):
            winners.append(agent_id)

    threads = [threading.Thread(target=race, args=("agent-%d" % i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("atomic claim: exactly one of 8 racers wins", len(winners) == 1,
          "winners=%r" % winners)


def test_fenced_renew():
    cleanup()
    r.set(LKEY, "A", ex=agent.LOCK_TTL)
    ok_a = renew(keys=[LKEY], args=["A", agent.LOCK_TTL])
    ok_b = renew(keys=[LKEY], args=["B", agent.LOCK_TTL])
    check("fenced renew: holder A renews, stranger B cannot", ok_a == 1 and ok_b == 0,
          "A=%s B=%s" % (ok_a, ok_b))


def test_expiry_and_takeover():
    cleanup()
    r.set(LKEY, "A", ex=1)                 # A holds, then "dies" (never renews)
    time.sleep(1.4)
    gone = not r.exists(LKEY)
    b_claims = bool(r.set(LKEY, "B", nx=True, ex=agent.LOCK_TTL))
    holder = r.get(LKEY)
    check("lease expiry: lock disappears when holder stops renewing", gone)
    check("takeover: another agent claims the expired lock", b_claims and holder == "B",
          "holder=%s" % holder)


def test_fenced_write():
    cleanup()
    r.set(LKEY, "A", ex=agent.LOCK_TTL)
    r.set(VKEY, '{"status": "amber", "claimed_by": "A"}')
    ok_a = write(keys=[LKEY, VKEY], args=["A", '{"status": "green", "claimed_by": "A"}'])
    # B lost the race / its lease; its stale write must be rejected.
    ok_b = write(keys=[LKEY, VKEY], args=["B", '{"status": "red", "claimed_by": "B"}'])
    final = r.get(VKEY)
    check("fenced write: only the lock holder can change the ticket",
          ok_a == 1 and ok_b == 0 and '"green"' in final, "ticket=%s" % final)


def test_fenced_release():
    cleanup()
    r.set(LKEY, "A", ex=agent.LOCK_TTL)
    b_release = release(keys=[LKEY], args=["B"])      # not the holder
    still = r.get(LKEY)
    a_release = release(keys=[LKEY], args=["A"])      # the holder
    gone = not r.exists(LKEY)
    check("fenced release: stranger cannot release, holder can",
          b_release == 0 and still == "A" and a_release == 1 and gone)


def test_live_renewal_thread():
    cleanup()
    # Seed a valid ticket (the renewal thread updates lease_expires on it).
    r.set(VKEY, '{"status": "amber", "claimed_by": "%s", "attempts": []}' % agent.AGENT_ID)
    r.set(LKEY, agent.AGENT_ID, ex=agent.LOCK_TTL)
    lease = agent.Lease(r, VKEY).start()
    # Wait well past one TTL: without renewal the lock would be gone by now.
    time.sleep(agent.LOCK_TTL + 1.5)
    alive = r.get(LKEY) == agent.AGENT_ID
    check("live renewal: Lease thread keeps the lock past its TTL", alive)
    lease.release()
    time.sleep(agent.LOCK_TTL + 1.0)
    expired = not r.exists(LKEY)
    check("live renewal: lock expires once the holder is released/dead", expired)


def main():
    try:
        r.ping()
    except redis.RedisError as e:
        sys.exit("cannot reach Redis at %s (%s). Start one: "
                 "docker run --rm -d -p 6379:6379 redis:7-alpine" % (URL, e))
    print("Redis coordination proof — LOCK_TTL=%ss, redis=%s\n" % (agent.LOCK_TTL, URL))
    for fn in (test_atomic_claim, test_fenced_renew, test_expiry_and_takeover,
               test_fenced_write, test_fenced_release, test_live_renewal_thread):
        fn()
    cleanup()
    print("\n%d passed, %d failed" % (len(passed), len(failed)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
