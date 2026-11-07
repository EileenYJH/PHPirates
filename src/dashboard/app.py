"""Read-only dashboard. It only ever reads Redis; if it dies, patching carries on."""
import json
import os
import time

import redis
from flask import Flask, jsonify, send_from_directory

r = redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"),
                   decode_responses=True, socket_timeout=2)
app = Flask(__name__)
HERE = os.path.dirname(os.path.abspath(__file__))


@app.get("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.get("/api/state")
def state():
    try:
        keys = sorted(r.scan_iter("vuln:*", count=500))
        tickets = []
        if keys:
            raws = r.mget(keys)
            pipe = r.pipeline()
            for k in keys:
                lk = "lock:" + k.split(":", 1)[1]
                pipe.get(lk)
                pipe.ttl(lk)
            res = pipe.execute()
            for i, (k, raw) in enumerate(zip(keys, raws)):
                if raw is None:
                    continue
                t = json.loads(raw)
                holder, ttl = res[2 * i], res[2 * i + 1]
                status = t.get("status")
                if status == "green":
                    view = "green"
                elif status == "review":
                    view = "review"            # patch staged, waiting on a human
                elif status == "approved" and not holder:
                    view = "approved"          # human said yes, an agent will apply it
                elif holder:
                    view = "amber"
                elif status == "amber":
                    view = "orphaned"          # claimed by an agent whose lock has expired
                else:
                    view = "red"
                t.update(key=k, holder=holder, lease_left=ttl if holder else None, view=view)
                tickets.append(t)
        agents = []
        akeys = list(r.scan_iter("agent:*", count=500))
        if akeys:
            agents = [json.loads(a) for a in r.mget(akeys) if a]
            agents.sort(key=lambda a: a["id"])
        return jsonify(ok=True, now=time.time(), tickets=tickets, agents=agents,
                       metrics=compute_metrics(tickets))
    except redis.RedisError as e:
        return jsonify(ok=False, error=str(e)), 503


def compute_metrics(tickets):
    """Derived only from ticket data, so it reads the same whenever you open the page.

    effectiveness = verified fixes / patch attempts, where an attempt is each green plus
                    each FAIL note (a patch that did not hold). Human rejections excluded.
    patches/min   = fixes / (last fix - first activity), i.e. throughput over the window
                    the swarm was actually working; it does not decay after completion.
    """
    now = time.time()
    greens = [t for t in tickets if t.get("status") == "green"]
    fails = sum(1 for t in tickets for a in t.get("attempts", [])
                if a.startswith("FAIL") and "rejected" not in a)
    attempts = len(greens) + fails
    ups = [t["updated_at"] for t in tickets if t.get("updated_at")]
    run_start = min(ups) if ups else now
    green_ups = [t["updated_at"] for t in greens if t.get("updated_at")]
    last = max(green_ups) if green_ups else now
    window = max(last - run_start, 1.0)                 # seconds; floored so no divide-by-0
    return {
        "total": len(tickets),
        "green": len(greens),
        "attempts": attempts,
        "failed_attempts": fails,
        "effectiveness": (len(greens) / attempts) if attempts else None,   # 0..1
        "patches_per_min": len(greens) / (window / 60.0),
        "elapsed_sec": int(now - run_start),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
