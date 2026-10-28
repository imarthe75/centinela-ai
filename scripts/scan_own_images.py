"""Scan Centinela's own container images with Trivy and persist HIGH/CRITICAL findings on the 'Centinela-AI (Self-Audit)' asset.

Run inside centinela-ai (trivy + docker.sock available):  docker exec centinela-ai python3 scripts/scan_own_images.py [image ...]
Findings are keyed by image:package so one CVE in two images / two packages stays distinct; vulnerabilities a fresh scan no longer
reproduces are reconciled to RESOLVED. A failed trivy run persists nothing and never reconciles (no false "clean")."""
import subprocess
import sys

sys.path.insert(0, "/app")
from auditors.auditor_ext import parse_trivy_image_json            # noqa: E402
from core import db_manager, deduplication_engine as de             # noqa: E402

SELF_ASSET = "Centinela-AI (Self-Audit)"
DEFAULT_IMAGES = ["centinela-ai-centinela-ai:latest", "centinela-ai-centinela-backend:latest",
                  "centinela-ai-centinela-sentinel:latest", "centinela-ai-centinela-frontend:latest"]
ENGINE = "trivy-image"


def scan(image: str, asset_id) -> int:
    proc = subprocess.run(["trivy", "image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", image],
                          capture_output=True, text=True, errors="replace", timeout=900)
    if proc.returncode != 0:
        print(f"❌ trivy failed on {image}: {proc.stderr[-300:]}")
        return -1
    vulns = parse_trivy_image_json(proc.stdout)
    seen = set()
    with db_manager.get_db_cursor() as cur:
        for v in vulns:
            loc = f"{image}/{v['package']}@{v['installed']}"
            fix = f"Actualizar a {v['fixed']}." if v["fixed"] else "Sin versión corregida publicada."
            desc = f"[{image}] {v['package']} {v['installed']} - {fix} {v['title']}".strip()
            sev = (v["severity"] or "HIGH").upper()
            cve = v["id"]
            de.log_finding_deduplicated(cur, asset_id, cve, sev, desc, ENGINE, url_path=loc, open_status="NEW", preserve_status=True)
            seen.add(de.calculate_fingerprint(asset_id, cve, loc))
        de.reconcile_resolved_findings(cur, asset_id, ENGINE, seen, url_origin=image)
    print(f"✅ {image}: {len(vulns)} HIGH/CRITICAL findings persisted")
    return len(vulns)


if __name__ == "__main__":
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT id FROM public.infra_inventory WHERE asset_name = %s", (SELF_ASSET,))
        row = cur.fetchone()
    if not row:
        sys.exit(f"asset '{SELF_ASSET}' not found")
    for img in (sys.argv[1:] or DEFAULT_IMAGES):
        scan(img, row[0])
