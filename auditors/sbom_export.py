"""
Software Bill of Materials per scanned asset (ADR-0022 §6). Idea from OWASP Dependency-Track: keep a standard inventory
of every component a project ships, so the question "which projects use package X version Y?" -- asked the day a new
vulnerability appears -- is answered from files, without re-scanning the fleet.

* Generated with `trivy fs --format cyclonedx` (CycloneDX 1.x, the OWASP standard), already in the centinela-ai image.
  Without `--scanners` trivy only inventories components: ~1 s per repository, no vulnerability DB needed.
* Stored under `data/sboms/` (internal, never under a public frontend path -- CLAUDE.md rule 9) and served by the backend
  through an authenticated, project-scoped endpoint (`GET /api/sbom`).
* Best effort: a failure is logged with its traceback and the scan goes on; there is simply no SBOM for that asset.
"""
import hashlib
import json
import os
import re
import subprocess
import traceback
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBOM_DIR = os.getenv("SBOM_DIR", os.path.join(ROOT, "data", "sboms"))
TIMEOUT_S = int(os.getenv("SBOM_TIMEOUT_S", "300"))


def sbom_path(asset_name: str) -> str:
    """Stable file name for an asset: readable prefix + hash (asset names contain '/', '@' and spaces)."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", asset_name or "asset").strip("_")[:80]
    digest = hashlib.sha256((asset_name or "").encode("utf-8")).hexdigest()[:12]
    return os.path.join(SBOM_DIR, f"{slug}__{digest}.cdx.json")


def generate_sbom(repo_dir: str, asset_name: str) -> Optional[str]:
    """Writes the CycloneDX SBOM of `repo_dir` for `asset_name`; returns its path, or None when it could not be produced."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return None
    os.makedirs(SBOM_DIR, exist_ok=True)
    final = sbom_path(asset_name)
    tmp = final + ".tmp"
    try:
        res = subprocess.run(["trivy", "fs", "--quiet", "--format", "cyclonedx", "--output", tmp, repo_dir],
                             capture_output=True, text=True, timeout=TIMEOUT_S)
        if res.returncode != 0:
            print(f"⚠️ [SBOM] trivy failed for {asset_name} (rc={res.returncode}): {res.stderr[-400:]}")
            return None
        with open(tmp, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if doc.get("bomFormat") != "CycloneDX":
            print(f"⚠️ [SBOM] unexpected output for {asset_name}: not a CycloneDX document")
            return None
        doc.setdefault("metadata", {}).setdefault("properties", []).append({"name": "centinela:asset", "value": asset_name})
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, final)
        return final
    except (OSError, ValueError, subprocess.SubprocessError):
        print(f"❌ [SBOM] could not generate SBOM for {asset_name}:")
        traceback.print_exc()
        return None
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError as exc:
                print(f"⚠️ [SBOM] could not remove temporary file {tmp}: {exc}")


def summarize(path: str) -> Dict[str, Any]:
    """{"components": n, "spec_version": "1.x", "generated_at": "..."} of a stored SBOM."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    return {"components": len(doc.get("components") or []), "spec_version": doc.get("specVersion"),
            "generated_at": (doc.get("metadata") or {}).get("timestamp")}


def find_component(name: str, version: Optional[str] = None, sbom_dir: Optional[str] = None) -> List[Dict[str, str]]:
    """Which stored SBOMs contain component `name` (optionally an exact version): [{"asset", "name", "version", "purl"}]."""
    wanted = (name or "").strip().lower()
    hits: List[Dict[str, str]] = []
    d = sbom_dir or SBOM_DIR
    if not wanted or not os.path.isdir(d):
        return hits
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".cdx.json"):
            continue
        try:
            with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            traceback.print_exc()
            continue
        asset = next((p.get("value") for p in (doc.get("metadata") or {}).get("properties") or []
                      if p.get("name") == "centinela:asset"), fn)
        for c in doc.get("components") or []:
            cname = str(c.get("name") or "")
            full = f"{c.get('group')}/{cname}" if c.get("group") else cname
            if wanted in (cname.lower(), full.lower()) and (version is None or str(c.get("version")) == version):
                hits.append({"asset": asset, "name": full, "version": str(c.get("version") or ""), "purl": str(c.get("purl") or "")})
    return hits
