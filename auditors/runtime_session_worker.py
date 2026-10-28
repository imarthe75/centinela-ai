"""Runs INSIDE the Dockerfile.a11y container (headless Chromium, Playwright). Logs in as ONE profile with test credentials and browses the given
routes like a user would, recording what a developer-tools panel would show: console messages, HTTP statuses, and sensitive-looking values in
JSON responses. Nothing is clicked except the login submit; nothing is posted besides the login form.

stdin  : one JSON document {"login_url", "username", "password", "routes": [...], "user_selector", "pass_selector", "submit_selector", "wait_ms"}
stdout : ONE JSON document; sensitive values are MASKED here (first 6 characters + '***') so neither real tokens nor real personal data
         ever leave the browser container.
"""
import json
import re
import sys

from playwright.sync_api import sync_playwright

JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
CURP = re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b")
RFC = re.compile(r"\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}", re.IGNORECASE)


def mask(v: str) -> str:
    return (v[:6] + "***") if v else ""


def main():
    cfg = json.load(sys.stdin)
    out = {"login_ok": False, "login_url": cfg["login_url"], "console": [], "responses": [], "pii": [], "storage": [], "errors": []}
    console, responses, pii = [], [], {}
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1366, "height": 900})
        page = ctx.new_page()
        page.on("console", lambda m: console.append({"type": m.type, "text": m.text[:600], "url": page.url}))
        page.on("pageerror", lambda e: out["errors"].append(str(e)[:300]))

        def on_response(r):
            try:
                ct = r.headers.get("content-type", "")
                entry = {"url": r.url.split("?")[0][:300], "status": r.status, "method": r.request.method}
                responses.append(entry)
                if r.status < 400 and "json" in ct:
                    body = r.text()[:300000]
                    for kind, rx in (("CURP", CURP), ("RFC", RFC), ("EMAIL", EMAIL)):
                        found = rx.findall(body)
                        if found:
                            e = pii.setdefault((entry["url"], kind), {"url": entry["url"], "kind": kind, "count": 0, "sample": mask(found[0])})
                            e["count"] += len(found)
            except Exception:
                pass          # a response whose body cannot be read is simply not analysed
        page.on("response", on_response)

        try:
            page.goto(cfg["login_url"], wait_until="networkidle", timeout=45000)
            us = cfg.get("user_selector") or "input[type=email], input[name*=user i], input[name*=correo i], input[name*=login i], input[type=text]"
            ps = cfg.get("pass_selector") or "input[type=password]"
            page.locator(us).first.fill(cfg["username"], timeout=15000)
            page.locator(ps).first.fill(cfg["password"], timeout=15000)
            sub = cfg.get("submit_selector") or "button[type=submit], button:has-text('Iniciar'), button:has-text('Entrar'), button:has-text('Login'), input[type=submit]"
            page.locator(sub).first.click(timeout=15000)
            page.wait_for_load_state("networkidle", timeout=30000)
            page.wait_for_timeout(int(cfg.get("wait_ms", 1500)))
            out["login_ok"] = page.locator("input[type=password]").count() == 0
            out["after_login_url"] = page.url
        except Exception as e:
            out["errors"].append(f"login: {type(e).__name__}: {str(e)[:200]}")
        if out["login_ok"]:
            for route in cfg.get("routes", [])[:25]:
                try:
                    page.goto(route, wait_until="networkidle", timeout=30000)
                    page.wait_for_timeout(int(cfg.get("wait_ms", 1500)))
                except Exception as e:
                    out["errors"].append(f"route {route}: {type(e).__name__}: {str(e)[:150]}")
            try:
                for area in ("localStorage", "sessionStorage"):
                    keys = page.evaluate(f"() => Object.keys({area})")
                    for k in keys:
                        val = page.evaluate(f"(k) => {area}.getItem(k)", k) or ""
                        if JWT.search(val):
                            out["storage"].append({"area": area, "key": k})
            except Exception as e:
                out["errors"].append(f"storage: {type(e).__name__}")
        browser.close()
    for c in console:
        t = c["text"]
        j, b = JWT.search(t), BEARER.search(t)
        c["secret"] = mask((j or b).group(0)) if (j or b) else None
        c["text"] = JWT.sub(lambda m: mask(m.group(0)), BEARER.sub("Bearer ***", t))[:300]
    out["console"] = [c for c in console if c["type"] in ("error", "warning") or c["secret"]][:200]
    out["console_total"] = len(console)
    out["responses"] = responses[:2000]
    out["pii"] = list(pii.values())
    print(json.dumps(out))


if __name__ == "__main__":
    main()
