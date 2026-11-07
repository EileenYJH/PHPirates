#!/usr/bin/env python3
"""Proof that the swarm's coordination guarantees hold, using the REAL scripts
and claim code imported from agent.py (not a reimplementation).

Run locally:   REDIS_URL=redis://127.0.0.1:6390/0 python src/agent/test_redis_logic.py
In the stack:  docker compose run --rm --no-deps agent-a python test_redis_logic.py

Exit 0 = every guarantee held.
"""
import os
import sys
import time

import redis

import agent  # the real module under test

R = redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
VK = "vuln:s1:demo"
LK = agent.lock_key(VK)
passed = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    passed.append(bool(cond))


def reset():
    R.delete(VK, LK)


print("1. Mutual exclusion: two agents race to claim the same bug (SET NX)")
reset()
a_wins = R.set(LK, "agentA", nx=True, ex=30)
b_wins = R.set(LK, "agentB", nx=True, ex=30)
check("exactly one agent wins the claim", bool(a_wins) and not b_wins)
check("the winner owns the lock", R.get(LK) == "agentA")

print("2. Fenced writes: only the lock holder can change the ticket (WRITE_LUA)")
reset()
R.set(LK, "agentA", ex=30)
write = R.register_script(agent.WRITE_LUA)
ok_a = write(keys=[LK, VK], args=["agentA", '{"status":"amber","by":"A"}'])
ok_b = write(keys=[LK, VK], args=["agentB", '{"status":"green","by":"B"}'])
check("holder's write is accepted", ok_a == 1)
check("non-holder's write is rejected", ok_b == 0)
check("ticket still shows the holder's value", '"by":"A"' in (R.get(VK) or ""))

print("3. Owner-only release: you cannot release someone else's lock (RELEASE_LUA)")
reset()
R.set(LK, "agentA", ex=30)
release = R.register_script(agent.RELEASE_LUA)
check("a stranger cannot delete the lock", release(keys=[LK], args=["agentB"]) == 0 and R.exists(LK))
check("the owner can release it", release(keys=[LK], args=["agentA"]) == 1 and not R.exists(LK))

print("4. Owner-only renewal: only the holder extends the lease (RENEW_LUA)")
reset()
R.set(LK, "agentA", ex=5)
renew = R.register_script(agent.RENEW_LUA)
check("holder extends the TTL", renew(keys=[LK], args=["agentA", 100]) == 1 and R.ttl(LK) > 50)
check("non-holder cannot extend it", renew(keys=[LK], args=["agentB", 100]) == 0)

print("5. Death without a detector: no renewal -> lock expires -> free to reclaim")
reset()
R.set(LK, "agentA", ex=2)          # a holder that will stop renewing
check("lock is held right after claim", R.get(LK) == "agentA")
time.sleep(2.5)                      # simulate the agent dying (no renew thread)
check("lock is gone after the lease lapses", not R.exists(LK))
check("another agent can now claim it", bool(R.set(LK, "agentB", nx=True, ex=30)))

print("6. The real Lease class: renewal keeps it alive, then takeover on death")
reset()
agent.LOCK_TTL, agent.RENEW_EVERY = 3, 1      # speed the clock up for the test
agent.AGENT_ID = "agentA"
R.set(LK, "agentA", ex=3)
R.set(VK, '{"server":"s1","vuln":"demo","type":"sqli","status":"amber","claimed_by":"agentA","attempts":[]}')
lease = agent.Lease(R, VK).start()
time.sleep(5)                                  # longer than one TTL: survives only if renewed
check("lease survives past its TTL while the agent renews", R.get(LK) == "agentA")
lease._stop.set()                              # kill the renew thread WITHOUT releasing = a crash
time.sleep(4)                                  # > LOCK_TTL with nobody renewing
check("after the crash the lock expires on its own", not R.exists(LK))
agent.AGENT_ID = "agentB"                       # a surviving agent
check("the survivor takes over the freed bug", bool(R.set(LK, "agentB", nx=True, ex=30)))
reset()

print()
print("%d/%d guarantees held" % (sum(passed), len(passed)))
sys.exit(0 if all(passed) else 1)
