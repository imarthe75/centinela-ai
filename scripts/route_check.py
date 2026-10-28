"""Routing regression check (ADR-0008 #3). Reads a fingerprint {"METHOD /sample/url": "template -> endpoint_name"} and verifies, using the
app's own ASGI matching (works with FastAPI's lazily included routers), that every sample URL is still served by the same endpoint function.
usage (inside centinela-backend): python scripts/route_check.py fp_before.json"""
import json, sys
sys.path.insert(0, "/app")
import main
from starlette.routing import Route, WebSocketRoute

def flat_routes():
    out = []
    for r in main.app.routes:
        if type(r).__name__ == "_IncludedRouter":      # FastAPI >= 0.14x wraps included routers lazily; expand in include order
            out.extend(r.original_router.routes)
        else:
            out.append(r)
    return [r for r in out if isinstance(r, (Route, WebSocketRoute))]

expected = json.load(open(sys.argv[1]))
routes = flat_routes()
bad = []
for key, val in expected.items():
    method, url = key.split(" ", 1)
    want = val.split("-> ")[-1]
    got = None
    for r in routes:
        rm = sorted(getattr(r, "methods", None) or ["WS"])
        if method in rm and r.path_regex.match(url):
            got = getattr(r.endpoint, "__name__", None)
            break
    if got != want:
        bad.append((key, want, got))
print(f"{len(expected) - len(bad)}/{len(expected)} rutas atendidas por el mismo endpoint (de {len(routes)} registradas)")
for b in bad[:15]:
    print("DIFERENCIA:", b)
sys.exit(1 if bad else 0)
