"""Routing fingerprint (ADR-0008 #3): for every registered route, build a sample URL and record which route (first match, in registration
order) would actually serve it. Comparing the fingerprint before/after a refactor proves no endpoint became shadowed or re-routed.
usage (inside centinela-backend): python scripts/route_fingerprint.py out.json"""
import json, re, sys
sys.path.insert(0, "/app")
import main
from starlette.routing import Route, WebSocketRoute

def sample(path):
    # {x} -> "x", {x:path} -> "a/b"
    return re.sub(r"\{[^}:]+:path\}", "a/b", re.sub(r"\{([^}:]+)\}", "x", path))

routes = [r for r in main.app.routes if isinstance(r, (Route, WebSocketRoute))]
out = {}
for r in routes:
    methods = sorted(getattr(r, "methods", None) or ["WS"])
    for m in methods:
        if m == "HEAD":
            continue
        url = sample(r.path)
        for cand in routes:
            cm = sorted(getattr(cand, "methods", None) or ["WS"])
            if m in cm and cand.path_regex.match(url):
                out[f"{m} {url}"] = f"{cand.path} -> {getattr(cand.endpoint, '__name__', '?')}"
                break
json.dump(out, open(sys.argv[1], "w"), indent=1, sort_keys=True)
print(len(out), "entries")
