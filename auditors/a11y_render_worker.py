"""Runs INSIDE the Dockerfile.a11y container. Renders each URL in headless Chromium, runs axe-core and prints ONE JSON document to stdout.

    a11y_render_worker.py <url> [<url> ...]  ->  {"results":[{"url":..,"ok":true,"violations":[...],"passes":N,"incomplete":N} | {"url":..,"ok":false,"error":..}]}

Read-only: navigation + DOM inspection only, no form submission, no clicks. Every error is reported per URL, never swallowed."""
import json
import sys

from playwright.sync_api import sync_playwright


def audit(page, url: str) -> dict:
    from axe_playwright_python.sync_playwright import Axe
    page.goto(url, wait_until="networkidle", timeout=45000)
    res = Axe().run(page, options={"runOnly": {"type": "tag", "values": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]}}).response
    viol = []
    for v in res.get("violations", []):
        viol.append({"rule": v["id"], "impact": v.get("impact"), "help": v.get("help"), "helpUrl": v.get("helpUrl"), "tags": v.get("tags", []),
                     "nodes": [{"target": n.get("target"), "html": (n.get("html") or "")[:200], "summary": (n.get("failureSummary") or "")[:300]}
                               for n in v.get("nodes", [])[:25]], "node_count": len(v.get("nodes", []))})
    stats = page.evaluate("() => ({elements: document.querySelectorAll('*').length, text: (document.body ? document.body.innerText : '').trim().length})")
    return {"url": url, "ok": True, "elements": stats["elements"], "text_len": stats["text"], "final_url": page.url, "title": page.title(), "violations": viol,
            "passes": len(res.get("passes", [])), "incomplete": len(res.get("incomplete", []))}


def main(urls):
    out = []
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1366, "height": 900})
        for u in urls:
            page = ctx.new_page()
            try:
                out.append(audit(page, u))
            except Exception as e:      # reported per URL; the caller decides what a failure means
                out.append({"url": u, "ok": False, "error": f"{type(e).__name__}: {e}"[:500]})
            finally:
                page.close()
        browser.close()
    print(json.dumps({"results": out}))


if __name__ == "__main__":
    main(sys.argv[1:])
