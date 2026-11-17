"""
Repository facts for the AI analyses (ADR-0021 §5).

A scanner and a language model only see the code; the team knows things the code does not show at the flagged line:
"every /api/admin route is behind the gateway's role check", "Math.random() in /demo is test data", "this module is
dead and scheduled for removal". Without those facts the AI either over-reports or, worse, guesses them. The idea
comes from Crysk's REVIEW.md; Centinela's version adds two sources and two guards:

Sources, all optional, concatenated in this order (most general first):
  1. `config/repo_facts/<group>.md` files for every parent group of the project (facts a whole group shares),
  2. `config/repo_facts/<project>.md` (facts written by the security team, without touching the client repository),
  3. `.centinela/hechos.md`, `.centinela/review.md` or `REVIEW.md` inside the scanned clone (facts the team commits).
  File names replace "/" with "__" in the asset name without its "@branch": `GitLab__ventas__backend.md`,
  `GitLab__ventas.md` for the whole `ventas` group.

Guards:
  * Facts are untrusted data: they are wrapped in nonce blocks by the caller and the prompts say a fact is never proof
    on its own (it only tells the model where to look).
  * Text with instructions aimed at the model (core.prompt_guard) is dropped entirely and reported, never sent.
"""
import os
from typing import Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACTS_DIR = os.getenv("REPO_FACTS_DIR", os.path.join(ROOT, "config", "repo_facts"))
MAX_FACT_CHARS = int(os.getenv("REPO_FACTS_MAX_CHARS", "3000"))
IN_REPO_FILES = (".centinela/hechos.md", ".centinela/review.md", "REVIEW.md")


def _read(path: str) -> str:
    try:
        if os.path.isfile(path) and os.path.getsize(path) <= 200_000:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()
    except OSError:
        pass
    return ""


def config_candidates(asset_name: str) -> List[str]:
    """`config/repo_facts` file names that apply to an asset, most general first."""
    base = str(asset_name or "").split("@", 1)[0].strip().strip("/")
    if not base:
        return []
    parts = base.split("/")
    return ["__".join(parts[:i]) + ".md" for i in range(2, len(parts) + 1)]


def load_repo_facts(asset_name: str, repo_dir: Optional[str] = None, facts_dir: Optional[str] = None) -> Dict[str, object]:
    """{"text": str (capped), "sources": [...], "dropped_injection": [...]} -- empty text when there are no facts."""
    from core import prompt_guard
    facts_dir = facts_dir or FACTS_DIR
    chunks: List[str] = []
    sources: List[str] = []
    dropped: List[str] = []

    def add(label: str, text: str):
        if not text:
            return
        hits = prompt_guard.scan_for_injection(text)
        if hits:
            dropped.append(f"{label} ({', '.join(hits)})")
            return
        chunks.append(text)
        sources.append(label)

    for name in config_candidates(asset_name):
        add(f"config/repo_facts/{name}", _read(os.path.join(facts_dir, name)))
    if repo_dir and os.path.isdir(repo_dir):
        root = os.path.realpath(repo_dir)
        for rel in IN_REPO_FILES:
            full = os.path.realpath(os.path.join(root, rel))
            if full.startswith(root + os.sep):
                txt = _read(full)
                if txt:
                    add(rel, txt)
                    break   # one in-repo file is enough; they are alternatives, not layers
    text = "\n\n".join(chunks)
    if len(text) > MAX_FACT_CHARS:
        text = text[:MAX_FACT_CHARS] + "\n[... hechos truncados por tamaño ...]"
    return {"text": text, "sources": sources, "dropped_injection": dropped}
