"""Run Centinela's own versioned Nuclei templates (templates/nuclei/*.yaml) against one URL.

Community templates are already used by auditor_ext; this adds institution-specific checks without writing a new Python auditor.
Read-only GET requests only. A template file is reviewed code: never load templates from a user-supplied path."""
import json
import logging
import os
import subprocess
from typing import Dict, List

logger = logging.getLogger(__name__)

TEMPLATE_DIR = os.getenv("CENTINELA_NUCLEI_TEMPLATES", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "nuclei"))


def run_custom_templates(url: str, timeout: int = 120) -> List[Dict]:
    """Return [{'template_id','severity','description','matched_at'}] for every custom template that matched `url`.
    Raises on a missing template dir or nuclei failure to start; a non-zero exit with parseable output is still honoured."""
    if not os.path.isdir(TEMPLATE_DIR):
        raise FileNotFoundError(f"custom nuclei template dir not found: {TEMPLATE_DIR}")
    cmd = ["nuclei", "-u", url, "-t", TEMPLATE_DIR, "-silent", "-jsonl", "-duc", "-disable-update-check", "-no-color"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    hits: List[Dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue                    # banner/log noise, never a finding (CLAUDE.md gotcha #6)
        info = rec.get("info") or {}
        hits.append({"template_id": rec.get("template-id"), "severity": (info.get("severity") or "info"),
                     "description": (info.get("description") or info.get("name") or "").strip(), "matched_at": rec.get("matched-at") or url})
    if proc.returncode != 0 and not hits:
        logger.error("custom nuclei run exited %s: %s", proc.returncode, (proc.stderr or "")[-400:])
    return hits
