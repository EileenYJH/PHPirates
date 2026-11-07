"""Approval gate for the optional n8n / human-in-the-loop track.

This is NOT a coordinator. It never tells an agent what to patch or who patches it.
It only lets a human accept or reject a patch an agent has already written and verified,
by flipping one field in shared state:

    review  --approve-->  approved   (an agent then applies the staged patch, re-verifies)
    review  --reject -->  red        (an agent re-patches from scratch)

If this service is down, patching with REQUIRE_APPROVAL still runs — tickets simply wait
in `review` until it (or anyone) approves them. With REQUIRE_APPROVAL off it is unused.

Endpoints (for n8n, curl, or the built-in page at /):
    GET  /api/reviews          tickets awaiting approval, with their diff
    POST /api/approve  {key}   review -> approved
    POST /api/reject   {key}   review -> red (+ reason)
"""
import json
import os
import time

import redis
from flask import Flask, jsonify, redirect, request, send_from_directory

r = redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"),
                   decode_responses=True, socket_timeout=2)
app = Flask(__name__)
HERE = os.path.dirname(os.path.abspath(__file__))


def body():
    """Accept a JSON body or a form body; never raise if the content-type is off."""
    return request.get_json(silent=True) or request.form


@app.after_request
def allow_cross_origin(resp):
    # The merged dashboard (:5000) posts approve/reject here (:5001) from the browser.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return ("", 204)


def reviews():
    out = []
    for k in sorted(r.scan_iter("vuln:*", count=500)):
        raw = r.get(k)
        if not raw:
            continue
        t = json.loads(raw)
        if t.get("status") == "review":
            out.append({"key": k, "server": t["server"], "vuln": t["vuln"], "type": t["type"],
                        "proposed_by": t.get("proposed_by"), "verified": t.get("verified"),
                        "diff": t.get("proposed_diff", "")})
    return out


def transition(key, want_from, mutate):
    """Compare-and-set on the ticket's status, so two reviewers can't collide."""
    with r.pipeline() as pipe:
        for _ in range(5):
            try:
                pipe.watch(key)
                raw = pipe.get(key)
                if not raw:
                    pipe.unwatch()
                    return False, "no such ticket"
                t = json.loads(raw)
                if t.get("status") != want_from:
                    pipe.unwatch()
                    return False, "ticket is '%s', not '%s'" % (t.get("status"), want_from)
                mutate(t)
                t["updated_at"] = time.time()
                pipe.multi()
                pipe.set(key, json.dumps(t))
                pipe.execute()
                return True, t["status"]
            except redis.WatchError:
                continue
    return False, "contended, try again"


@app.get("/api/reviews")
def api_reviews():
    try:
        return jsonify(ok=True, reviews=reviews())
    except redis.RedisError as e:
        return jsonify(ok=False, error=str(e)), 503


@app.post("/api/approve")
def api_approve():
    b = body()
    key = b.get("key")
    who = b.get("reviewer", "reviewer")
    ok, detail = transition(key, "review", lambda t: t.update(
        status="approved", approved_by=who))
    return jsonify(ok=ok, detail=detail), (200 if ok else 409)


@app.post("/api/reject")
def api_reject():
    b = body()
    key, who = b.get("key"), b.get("reviewer", "reviewer")
    reason = b.get("reason", "no reason given")

    def mutate(t):
        t.setdefault("attempts", []).append(("FAIL rejected by %s: %s" % (who, reason))[:300])
        t.update(status="red", claimed_by=None, lease_expires=None, proposed_diff="")
    ok, detail = transition(key, "review", mutate)
    if ok:
        r.delete("patch:" + key.split(":", 1)[1])
    return jsonify(ok=ok, detail=detail), (200 if ok else 409)


# --- tiny built-in review page (fallback when n8n isn't wired up) -------------
@app.get("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.post("/ui/<action>")
def ui(action):
    key = request.form.get("key")
    if action == "approve":
        transition(key, "review", lambda t: t.update(status="approved", approved_by="web-ui"))
    elif action == "reject":
        def mutate(t):
            t.setdefault("attempts", []).append("FAIL rejected by web-ui")
            t.update(status="red", claimed_by=None, lease_expires=None, proposed_diff="")
        if transition(key, "review", mutate)[0]:
            r.delete("patch:" + key.split(":", 1)[1])
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5001")))
