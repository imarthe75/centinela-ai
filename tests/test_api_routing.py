"""ADR-0008 #3: the API is split into routers (api/routers/*.py). Guard against the classic risk of splitting a monolith:
a parametrised route registered before a static one silently swallows it."""
import re

from starlette.routing import Route, WebSocketRoute

import main


def _flat_routes():
    out = []
    for r in main.app.routes:
        if type(r).__name__ == "_IncludedRouter":
            out.extend(r.original_router.routes)
        else:
            out.append(r)
    return [r for r in out if isinstance(r, (Route, WebSocketRoute))]


def test_no_static_route_is_shadowed_by_an_earlier_route():
    routes = _flat_routes()
    shadowed = []
    for i, r in enumerate(routes):
        if "{" in r.path:
            continue
        for m in sorted(getattr(r, "methods", None) or ["WS"]):
            if m == "HEAD":
                continue
            for earlier in routes[:i]:
                if m in (getattr(earlier, "methods", None) or ["WS"]) and earlier.path_regex.match(r.path):
                    shadowed.append((m, r.path, earlier.path))
    assert not shadowed, f"static routes shadowed by an earlier route: {shadowed}"


def test_every_route_has_a_unique_method_and_path():
    seen = {}
    for r in _flat_routes():
        for m in sorted(getattr(r, "methods", None) or ["WS"]):
            if m == "HEAD":
                continue
            key = (m, r.path)
            assert key not in seen, f"duplicate route {key}: {seen[key]} and {r.endpoint.__name__}"
            seen[key] = r.endpoint.__name__


def test_main_still_reexports_helpers_other_code_imports():
    assert callable(main.extract_clean_code)
    assert callable(main._gitlab_instance_from_payload)
