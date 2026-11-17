"""Scan Centinela's own container images with Trivy and persist HIGH/CRITICAL findings on the 'Centinela-AI (Self-Audit)' asset.

Run inside centinela-ai (trivy + docker.sock available):  docker exec centinela-ai python3 scripts/scan_own_images.py [image ...]
Findings are keyed by image:package so one CVE in two images / two packages stays distinct; vulnerabilities a fresh scan no longer
reproduces are reconciled to RESOLVED. A failed trivy run persists nothing and never reconciles (no false "clean")."""
import subprocess
import sys

sys.path.insert(0, "/app")
from auditors.auditor_ext import parse_trivy_image_json            # noqa: E402
from auditors import trivy_crypto                                   # noqa: E402
from core import db_manager, deduplication_engine as de             # noqa: E402

SELF_ASSET = "Centinela-AI (Self-Audit)"
DEFAULT_IMAGES = ["centinela-ai-centinela-ai:latest", "centinela-ai-centinela-backend:latest",
                  "centinela-ai-centinela-sentinel:latest", "centinela-ai-centinela-frontend:latest"]
ENGINE = "trivy-image"
CRYPTO_ENGINE = "trivy-image-crypto"   # own engine: the vuln pass reconciles everything of ENGINE under "<image>"


def scan_crypto(image: str, asset_id) -> int:
    """Certificates baked into the image (Trivy CBOM); see auditors/trivy_crypto.py. Persists only expired/weak own certs."""
    proc = subprocess.run(["trivy", "image", "--quiet", "--timeout", "15m", "--scanners", "crypto", "--format", "cyclonedx", image],
                          capture_output=True, text=True, errors="replace", timeout=1200)
    if proc.returncode != 0:
        print(f"❌ trivy crypto failed on {image}: {proc.stderr[-300:]}")
        return -1
    try:
        cbom = trivy_crypto.parse(proc.stdout)
    except ValueError as e:
        print(f"❌ trivy crypto on {image}: {e}")
        return -1
    found = trivy_crypto.findings_from_cbom(cbom, image)
    seen = set()
    with db_manager.get_db_cursor() as cur:
        for f in found:
            de.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], CRYPTO_ENGINE,
                                        url_path=f["url_path"], open_status="NEW", preserve_status=True)
            seen.add(de.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
        resolved = de.reconcile_resolved_findings(cur, asset_id, CRYPTO_ENGINE, seen, url_origin=image)
    s = trivy_crypto.summarize(cbom)
    print(f"✅ {image}: {s['crypto_assets']} crypto assets, {s['own_certificates']} own certificate(s), {len(found)} finding(s)"
          + (f", {resolved} resolved" if resolved else ""))
    return len(found)


def scan(image: str, asset_id) -> int:
    proc = subprocess.run(["trivy", "image", "--quiet", "--timeout", "15m", "--format", "json", "--severity", "HIGH,CRITICAL", image],
                          capture_output=True, text=True, errors="replace", timeout=1200)
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
        scan_crypto(img, row[0])
