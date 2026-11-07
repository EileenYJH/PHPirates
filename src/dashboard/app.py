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
                if t.get("status") == "green":
                    view = "green"
                elif holder:
                    view = "amber"
                elif t.get("status") == "amber":
                    view = "orphaned"   # claimed by an agent whose lock has expired
                else:
                    view = "red"
                t.update(key=k, holder=holder, lease_left=ttl if holder else None, view=view)
                tickets.append(t)
        agents = []
        akeys = list(r.scan_iter("agent:*", count=500))
        if akeys:
            agents = [json.loads(a) for a in r.mget(akeys) if a]
            agents.sort(key=lambda a: a["id"])
        return jsonify(ok=True, now=time.time(), tickets=tickets, agents=agents)
    except redis.RedisError as e:
        return jsonify(ok=False, error=str(e)), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
