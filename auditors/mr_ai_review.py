"""
AI logic review of a Merge Request diff (ADR-0021 §6). OFF by default: `MR_REVIEW_AI=1` turns it on.

What it adds: Centinela's MR review (auditors/mr_review.py) runs pattern detectors (SAST regex, Semgrep, SCA,
secrets). Patterns cannot see LOGIC errors -- an inverted condition, a value in milliseconds compared with seconds, an
error that is caught and ignored, a resource not released on the error path. A language model reading the diff can.
The approach comes from the PR reviewer Crysk (Apache-2.0); this is Centinela's own implementation:

  1. ONE call per MR (the free provider quotas are the limit): the added hunks with their new-file line numbers and a
     checklist of language-independent logic weaknesses (organised from the MITRE CWE catalogue), plus the team's
     repository facts (core/repo_facts.py). Untrusted text goes inside nonce blocks.
  2. Deterministic discipline on the answer -- this is where the precision comes from, not from the model:
       * the finding must sit on a line the MR added (±2), in a file the MR changed;
       * every `file:line` it cites must exist in the checked-out MR head (core/ai_verification.verify_evidence_refs);
         a finding with no verifiable citation is dropped;
       * duplicates are merged (same file within a line window and similar wording), and an AI finding on the same
         spot as a deterministic finding is dropped (the deterministic one is already posted and blocks);
       * test-file findings below HIGH are dropped (test hygiene is not worth an MR comment);
       * HIGH findings get an adversarial check (at most `MR_REVIEW_AI_MAX_REFUTE`, default 3): a second call tries to
         disprove the claim, and only a refutation that cites verifiable lines removes it (silence never does).
  3. What survives is posted as ADVISORY: AI observations never change the `centinela/security` status. Only the
     deterministic detectors gate a merge. This keeps the gate reproducible and explainable.

Limits stated up front: the reviewer only sees the diff and what the prompt carries (it cannot browse the repository
like an agent with tools), quality depends on whichever free model answers, and it has NOT been measured on a labelled
corpus yet -- hence off by default.
"""
import os
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core import ai_verification

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|src/test)/|\.(spec|test)\.[cm]?[jt]sx?$|(Test|Tests|IT)\.java$|_test\.(py|go)$|(^|/)test_[^/]+\.py$",
                           re.IGNORECASE)
_SOURCE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".scala", ".rs", ".c", ".cpp",
               ".sql", ".sh", ".html", ".vue")
_SEV = {"ALTA": "HIGH", "ALTO": "HIGH", "HIGH": "HIGH", "CRITICA": "HIGH", "CRÍTICA": "HIGH", "CRITICAL": "HIGH",
        "MEDIA": "MEDIUM", "MEDIO": "MEDIUM", "MEDIUM": "MEDIUM", "BAJA": "LOW", "BAJO": "LOW", "LOW": "LOW"}
_SEV_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
LINE_FUZZ = 2
DETECTOR_OVERLAP = 1   # an AI finding within 1 line of a deterministic one is taken as the same spot
DEDUPE_LINE_WINDOW = 6
DEDUPE_SIMILARITY = 0.4
_STOP = set("el la los las un una de del en y o que se con por para es son no su sus al lo como este esta esto "
            "the a an of to in and or is are be not this that it for with on as at".split())


def enabled() -> bool:
    return os.getenv("MR_REVIEW_AI", "").strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------------------------- the checklist
# Each line is a question whose "no" is a defect. Grouped by the CWE pillars it comes from; the CWE ids are references
# to the public MITRE catalogue, the wording is Centinela's.
CHECKLIST = """
COMPARACIONES
- ¿La comparación usa el operador correcto (==, <, <=, &&, ||) y compara el atributo que de verdad define la igualdad? (CWE-480, CWE-1025)
- ¿Se comparan contenidos y no referencias (Java equals vs ==, objetos/arrays en JS)? (CWE-595)
- ¿Ambos lados son del mismo tipo o se convierten explícitamente? ¿Se evita comparar decimales con igualdad exacta? (CWE-1024, CWE-1077)
- ¿Un valor validado contra un máximo también se valida contra el mínimo (negativos, cero)? (CWE-839)
CÁLCULOS Y UNIDADES
- ¿Las unidades coinciden (ms vs s, fracción 0-1 vs porcentaje, centavos vs pesos, UTC vs hora local)? ¿Se convierte un valor dos veces?
- ¿Hay división entre un valor que puede ser cero? ¿Desbordamiento o truncamiento al cambiar de tipo? (CWE-369, CWE-190, CWE-681)
- ¿Los límites de ciclos, índices y tamaños son exactos (sin "uno de más/uno de menos")? (CWE-193)
- ¿Se usa un tipo con precisión suficiente para dinero o cantidades exactas? (CWE-1339)
FLUJO DE CONTROL
- ¿Cada rama hace lo que su condición dice? ¿Falta un caso por defecto o un break? ¿Hay código inalcanzable? (CWE-670, CWE-478, CWE-484, CWE-561)
- ¿Todo ciclo termina para cualquier entrada y tiene un límite razonable? (CWE-835, CWE-834)
ORDEN DE LOS PASOS
- ¿Se valida ANTES de usar, y se autoriza ANTES de modificar? ¿Se comprueba que un paso previo terminó antes del siguiente? (CWE-696, CWE-841)
ERRORES
- ¿Se revisa el valor de retorno / el error de cada llamada antes de usar su resultado? (CWE-252, CWE-253)
- ¿Un catch atrapa solo lo que sabe manejar, y no deja el error vacío o silenciado? ¿Se continúa como si nada tras un fallo? (CWE-396, CWE-1069, CWE-455)
- ¿Un finally/cleanup no oculta el error original? (CWE-584)
ENTRADAS Y ESTADO
- ¿Tamaños, índices, posiciones y cantidades que vienen de fuera se validan dentro de rango antes de usarse? (CWE-1284, CWE-1285, CWE-129)
- ¿Campos relacionados se validan como conjunto (fecha inicio < fecha fin, total = suma)? (CWE-1288)
- ¿Puede ser null/undefined/vacío un valor que el código usa sin comprobar? (CWE-476)
INICIALIZACIÓN Y RECURSOS
- ¿Toda variable recibe valor en todos los caminos antes de leerse? (CWE-456, CWE-457)
- ¿Conexiones, archivos, streams, suscripciones, timers y candados se liberan en TODOS los caminos, incluidos los de error? ¿Se evita liberar dos veces? (CWE-404, CWE-772, CWE-675)
CONCURRENCIA E IDEMPOTENCIA
- ¿Dos ejecuciones simultáneas pueden leer-modificar-escribir el mismo dato y perder una actualización? (CWE-362, CWE-367)
- ¿Una llave usada para buscar o deduplicar es realmente única? ¿Un reintento puede repetir un efecto (cobro, correo, alta)?
"""


def numbered_diff(diff_text: str, max_lines: int = 400) -> Tuple[str, int]:
    """Renders a unified diff with the NEW-file line number on every added/context line ("L120+ code" / "L121  code").
    Deleted lines are shown without a number. Returns (text, number_of_added_lines). Capped at max_lines lines."""
    out: List[str] = []
    added = 0
    new_ln = None
    for raw in (diff_text or "").splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            new_ln = int(m.group(1))
            out.append(raw)
            continue
        if new_ln is None or raw.startswith(("+++", "---")):
            continue
        if raw.startswith("+"):
            out.append(f"L{new_ln}+ {raw[1:][:300]}")
            new_ln += 1
            added += 1
        elif raw.startswith("-"):
            out.append(f"      - {raw[1:][:300]}")
        elif raw.startswith("\\"):
            continue
        else:
            out.append(f"L{new_ln}  {raw[1:][:300]}")
            new_ln += 1
        if len(out) >= max_lines:
            out.append("[... diff de este archivo truncado ...]")
            break
    return "\n".join(out), added


def select_changes(changes: List[Dict[str, Any]], max_files: int = 10, max_chars: int = 18000) -> List[Dict[str, Any]]:
    """Source files the MR adds lines to, most added lines first, within a size budget."""
    rows = []
    for ch in changes:
        path = ch.get("new_path") or ""
        if ch.get("deleted_file") or not path.lower().endswith(_SOURCE_EXT):
            continue
        text, added = numbered_diff(ch.get("diff", ""))
        if added:
            rows.append({"path": path, "text": text, "added": added})
    rows.sort(key=lambda r: -r["added"])
    picked, used = [], 0
    for r in rows[:max_files]:
        if used + len(r["text"]) > max_chars and picked:
            break
        picked.append(r)
        used += len(r["text"])
    return picked


def build_hunter_prompt(selected: List[Dict[str, Any]], repo_facts: str = "", mr_title: str = "") -> str:
    nonce = ai_verification.make_nonce(repo_facts, mr_title, *[r["text"] for r in selected])
    parts = [
        "Eres un revisor senior de código. Revisas los cambios de un Merge Request buscando ERRORES DE LÓGICA que "
        "producirían un comportamiento incorrecto: no estilo, no nombres, no formato, no falta de comentarios.",
        "Responde ÚNICAMENTE en español, con un objeto JSON.",
        "",
        ai_verification.untrusted_rules(nonce),
        "",
        "CÓMO TRABAJAR: recorre CADA bloque añadido (líneas `L<n>+`) y aplica TODA la lista de abajo. Encontrar un error "
        "no termina el bloque ni la revisión: un bloque puede tener varios. Reporta un error solo cuando el propio código "
        "lo muestra (nombres, tipos, el resto de la función); no inventes requisitos que el código no expresa.",
        "",
        "LISTA DE REVISIÓN:" + CHECKLIST,
        "SEVERIDAD por consecuencia si es cierto: ALTA = flujo principal roto, pérdida o corrupción de datos, hueco de "
        "seguridad; MEDIA = malfuncionamiento visible para el usuario; BAJA = degradado pero funcional, o latente.",
    ]
    if mr_title:
        parts += ["", "TÍTULO DEL MR:", ai_verification.wrap_untrusted("titulo", mr_title[:300], nonce)]
    if repo_facts:
        parts += ["", "HECHOS DEL REPOSITORIO (contexto del equipo; un comportamiento descrito aquí como deliberado no es un error):",
                  ai_verification.wrap_untrusted("hechos_del_repositorio", repo_facts, nonce)]
    parts += ["", "CAMBIOS (formato: `L<n>+` línea añadida en la línea n del archivo nuevo; `L<n>` contexto; `-` línea eliminada):"]
    for r in selected:
        parts += [f"### {r['path']}", ai_verification.wrap_untrusted("diff", r["text"], nonce)]
    parts += [
        "",
        "FORMATO (JSON estricto; lista vacía si no hay errores, es un resultado válido):",
        '{"hallazgos": [{"archivo": "ruta/del/archivo", "linea": 120, "cwe": "CWE-369", "severidad": "ALTA|MEDIA|BAJA", '
        '"descripcion": "qué hace el código, qué muestra su contexto que se pretendía, y la consecuencia (máx. 80 palabras, '
        'entendible por un gerente)", "evidencia": ["ruta/del/archivo:120", "ruta/del/archivo:98"]}]}',
        "`evidencia` cita archivo:línea del código mostrado (la línea del error y la que muestra la intención). Se comprueba "
        "contra el repositorio: una cita inexistente invalida el hallazgo.",
    ]
    return "\n".join(parts)


def parse_hunter_response(text: Optional[str]) -> List[Dict[str, Any]]:
    import json
    if not text:
        return []
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0), strict=False)
    except ValueError:
        return []
    items = data.get("hallazgos") or data.get("findings") or [] if isinstance(data, dict) else []
    out = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        try:
            line = int(str(it.get("linea") or it.get("line") or "0").strip())
        except ValueError:
            continue
        path = str(it.get("archivo") or it.get("path") or "").strip()
        if path.startswith("./"):
            path = path[2:]
        desc = str(it.get("descripcion") or it.get("claim") or "").strip()
        if not path or line < 1 or not desc:
            continue
        cwe = str(it.get("cwe") or "").strip().upper()
        out.append({"path": path, "line": line, "cwe": cwe if re.fullmatch(r"CWE-\d{1,5}", cwe) else "",
                    "severity": _SEV.get(str(it.get("severidad") or it.get("severity") or "").strip().upper(), "LOW"),
                    "description": desc[:900], "evidence": ai_verification.parse_evidence_refs(it.get("evidencia") or it.get("evidence"))})
    return out


def _tokens(text: str) -> Set[str]:
    return {t for t in re.split(r"[^0-9a-záéíóúñü_]+", text.lower()) if len(t) > 2 and t not in _STOP}


def similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if len(ta) < 5 or len(tb) < 5:
        return 0.0     # too short to compare meaningfully: never merge on it
    return len(ta & tb) / min(len(ta), len(tb))


def postprocess(findings: List[Dict[str, Any]], added_by_file: Dict[str, Set[int]], repo_dir: Optional[str],
                deterministic: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Applies the deterministic discipline. Returns (kept, drop_counts)."""
    drops = {"fuera_del_diff": 0, "evidencia_no_verificable": 0, "duplicado": 0, "ya_reportado_por_detector": 0, "prueba_menor": 0}
    det_spots = [(str(d.get("rel_path")), int(d.get("line") or 0)) for d in deterministic]
    kept: List[Dict[str, Any]] = []
    for f in sorted(findings, key=lambda x: -_SEV_RANK.get(x["severity"], 0)):
        added = added_by_file.get(f["path"])
        if not added or not any(abs(f["line"] - a) <= LINE_FUZZ for a in added):
            drops["fuera_del_diff"] += 1
            continue
        refs = f["evidence"] or [f"{f['path']}:{f['line']}"]
        check = ai_verification.verify_evidence_refs(repo_dir, refs)
        if check["invalid"] or not check["valid"]:
            drops["evidencia_no_verificable"] += 1
            continue
        f = {**f, "evidence_valid": check["valid"]}
        if _TEST_PATH_RE.search(f["path"]) and f["severity"] != "HIGH":
            drops["prueba_menor"] += 1
            continue
        if any(p == f["path"] and abs(ln - f["line"]) <= DETECTOR_OVERLAP for p, ln in det_spots):
            drops["ya_reportado_por_detector"] += 1
            continue
        dup = next((k for k in kept if k["path"] == f["path"] and abs(k["line"] - f["line"]) <= DEDUPE_LINE_WINDOW
                    and (k["cwe"] and k["cwe"] == f["cwe"] or similarity(k["description"], f["description"]) >= DEDUPE_SIMILARITY)), None)
        if dup is not None:
            drops["duplicado"] += 1
            dup.setdefault("merged_lines", []).append(f["line"])
            continue
        kept.append(f)
    return kept, drops


def build_refute_prompt(finding: Dict[str, Any], diff_text: str, repo_facts: str = "") -> str:
    nonce = ai_verification.make_nonce(finding["description"], diff_text, repo_facts)
    parts = [
        "Eres un VERIFICADOR ADVERSARIAL. Otro revisor afirma que este cambio tiene un error. Tu trabajo es intentar "
        "DEMOSTRAR QUE LA AFIRMACIÓN ES FALSA buscando la validación previa, la otra rama que sí maneja el caso, la "
        "restricción de tipo o la garantía del framework que lo impide. Responde ÚNICAMENTE en español, con JSON.",
        ai_verification.untrusted_rules(nonce),
        "",
        f"AFIRMACIÓN ({finding['path']}:{finding['line']}, {finding.get('cwe') or 'sin CWE'}):",
        ai_verification.wrap_untrusted("afirmacion", finding["description"], nonce),
        "",
        "CAMBIOS DEL ARCHIVO:",
        ai_verification.wrap_untrusted("diff", diff_text, nonce),
    ]
    if repo_facts:
        parts += ["HECHOS DEL REPOSITORIO (te dicen dónde mirar; un hecho por sí solo no refuta):",
                  ai_verification.wrap_untrusted("hechos_del_repositorio", repo_facts, nonce)]
    parts += [
        "",
        'VEREDICTOS: "refutado" SOLO si puedes citar las líneas que contradicen la afirmación; "confirmado" si buscaste '
        'y no encontraste nada que la desmienta (no encontrar nada es un resultado, apunta a confirmado); "inconcluso" si '
        "genuinamente depende de código que no ves.",
        '{"veredicto": "confirmado|refutado|inconcluso", "referencias": ["ruta:línea"], "razon": "una frase"}',
    ]
    return "\n".join(parts)


def refute_high(kept: List[Dict[str, Any]], ask: Callable[[str], Optional[str]], repo_dir: Optional[str],
                diffs: Dict[str, str], repo_facts: str = "", max_calls: int = 3) -> Tuple[List[Dict[str, Any]], int]:
    """Adversarial check of HIGH findings. Removes a finding only on a refutation with verifiable citations."""
    import json
    out, removed, calls = [], 0, 0
    for f in kept:
        if f["severity"] != "HIGH" or calls >= max_calls:
            out.append(f)
            continue
        calls += 1
        raw = ask(build_refute_prompt(f, diffs.get(f["path"], ""), repo_facts))
        verdict, refs = "inconcluso", []
        m = re.search(r"\{.*\}", raw or "", re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(0), strict=False)
                verdict = str(data.get("veredicto") or "").strip().lower()
                refs = ai_verification.parse_evidence_refs(data.get("referencias"))
            except ValueError:
                pass
        check = ai_verification.verify_evidence_refs(repo_dir, refs)
        if verdict == "refutado" and check["valid"] and not check["invalid"]:
            removed += 1
            continue
        out.append({**f, "refuter_verdict": verdict if raw else "sin_verificador"})
    return out, removed


def run_ai_review(changes: List[Dict[str, Any]], added_by_file: Dict[str, Set[int]], repo_dir: Optional[str],
                  deterministic: List[Dict[str, Any]], ask: Callable[[str], Optional[str]], repo_facts: str = "",
                  mr_title: str = "") -> Dict[str, Any]:
    """Whole AI pass. Never raises on a provider failure: returns status 'unavailable' and no findings."""
    selected = select_changes(changes)
    if not selected:
        return {"status": "no_source_changes", "findings": [], "drops": {}, "refuted": 0}
    raw = ask(build_hunter_prompt(selected, repo_facts, mr_title))
    if not raw:
        return {"status": "unavailable", "findings": [], "drops": {}, "refuted": 0}
    candidates = parse_hunter_response(raw)
    kept, drops = postprocess(candidates, added_by_file, repo_dir, deterministic)
    kept, refuted = refute_high(kept, ask, repo_dir, {r["path"]: r["text"] for r in selected}, repo_facts,
                                max_calls=int(os.getenv("MR_REVIEW_AI_MAX_REFUTE", "3")))
    kept = kept[: int(os.getenv("MR_REVIEW_AI_MAX_COMMENTS", "8"))]
    return {"status": "reviewed", "candidates": len(candidates), "findings": kept, "drops": drops, "refuted": refuted,
            "files_reviewed": [r["path"] for r in selected]}
