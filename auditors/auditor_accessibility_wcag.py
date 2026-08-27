"""
auditor_accessibility_wcag.py — Centinela-AI v3
Real, static WCAG 2.1 (Level A/AA) accessibility auditor.

Added 2026-08-25 after cross-checking C&A's own methodology manual
(Manual_Metodologia_CA_v2_COMPLETO.docx, section 0B-2 "Estándares de seguridad, accesibilidad y
calidad de código"): accessibility is one of three families of mandatory rules every C&A project
inherits, explicitly described there as "WCAG y las normas de imagen estatal aplicables al sector
público, requisito legal y no una preferencia de diseño" -- a legal requirement for the Estado de
México public-sector projects this platform already audits (SIAT/SIDECO), not a nice-to-have.
Before this file, Centinela had zero dedicated coverage of this dimension: the only accessibility
signal anywhere in the platform was SonarQube's own incidental CODE_SMELL hits (e.g.
"Web:InputWithoutLabelCheck" on the SIDECO frontend), filed as generic code-quality debt, never
tracked as its own compliance area.

Scope, deliberately narrow and honest: this is single-file, regex-based static analysis, the same
rigor level as every other native auditor in this codebase (auditor_master_vulnerabilities.py,
auditor_compliance_standards.py) -- it is NOT a rendering engine and cannot evaluate anything that
requires a computed layout or a color-contrast ratio (WCAG 1.4.3), ARIA live-region behavior, or
real keyboard-focus order. Every rule below checks for a structural pattern that is unambiguous
from source text alone: an <img> with no alt attribute at all IS a real 1.1.1 violation regardless
of what a human reviewer might additionally find; it does not need rendering to be true. Rules that
would need rendering are not attempted here rather than approximated -- an honest gap, not a guess.
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager
from core import deduplication_engine
from core.deduplication_engine import log_finding_deduplicated

# --- 1.1.1 Non-text Content: <img> with no alt attribute at all. alt="" is a legitimate,
# intentional way to mark a purely decorative image as accessible (screen readers correctly skip
# it) -- only the absence of the attribute itself is a real violation, never an empty value.
_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_ALT_ATTR_RE = re.compile(r"\balt\s*=", re.IGNORECASE)

# --- 1.3.1 / 4.1.2 Labels: collect every <label for="X"> id in the file, then check form
# controls against that set. Also accepts aria-label/aria-labelledby as a valid alternative (a
# real, WCAG-compliant way to label a control without a visible <label> element).
_LABEL_FOR_RE = re.compile(r'<label\b[^>]*\bfor\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_CONTROL_RE = re.compile(
    r'<(input|select|textarea)\b([^>]*)>', re.IGNORECASE
)
_SKIP_INPUT_TYPES = {"hidden", "submit", "button", "reset", "image"}

# --- 2.4.4 Link Purpose / 4.1.2 Name, Role, Value: an <a>/<button> with no text content and no
# accessible-name alternative is unusable via a screen reader. Deliberately conservative: skips
# any tag containing an <img>/<svg>/<i> child (icon-only buttons/links are extremely common and
# often DO carry an aria-label the outer regex below already checks for; flagging every icon
# button would be mostly noise) -- only flags a tag that is empty of BOTH text and any child
# markup, the unambiguous case.
_EMPTY_LINK_RE = re.compile(r'<a\b([^>]*)>\s*</a>', re.IGNORECASE)
_EMPTY_BUTTON_RE = re.compile(r'<button\b([^>]*)>\s*</button>', re.IGNORECASE)
# Real false positive found and fixed 2026-08-25, live against the SIDECO frontend: PrimeNG's
# `pButton` directive (301 real occurrences in this one repo alone, confirmed via grep) renders
# its `label="..."` attribute AS the button's visible/accessible text at runtime -- the tag's own
# HTML content is correctly empty by design, that's how the component works, not a violation.
# `label=` isn't a standard WCAG accessible-name attribute on its own, but given how dominant this
# real pattern is here (and the same convention exists in Angular Material/ng-bootstrap), treating
# it as an accepted accessible-name source avoids drowning real violations in framework noise.
#
# Second, same-class false positive found and fixed the same day, live against the SIDECO
# backend's Thymeleaf email templates: `th:text="${expr}"`/`th:utext="${expr}"` is Thymeleaf's
# standard, well-documented way to REPLACE a tag's body with server-evaluated text at render
# time -- `<a th:text="${llsolicitud}"></a>` looks empty in the static .html source (which is all
# this scanner ever sees) but renders with real text content every time. Confirmed real: 3/4 of
# this repo's initial WCAG-2.4.4 hits were exactly this pattern (email-procedente.html,
# solicitud-template.html, email-noprocedente.html), not actual empty links.
_ACCESSIBLE_NAME_ATTR_RE = re.compile(r'\b(aria-label|aria-labelledby|title|label|th:text|th:utext)\s*=', re.IGNORECASE)

# --- 3.1.1 Language of Page: root HTML documents must declare a language.
_HTML_TAG_RE = re.compile(r"<html\b([^>]*)>", re.IGNORECASE)
_LANG_ATTR_RE = re.compile(r"\blang\s*=", re.IGNORECASE)

# --- 2.4.3 Focus Order: a positive tabindex reorders keyboard focus outside the document's
# natural order -- a well-documented anti-pattern (WebAIM, MDN). tabindex="0" (join natural
# order) and tabindex="-1" (programmatic focus only) are correct, common, and NOT flagged.
_POSITIVE_TABINDEX_RE = re.compile(r'\btabindex\s*=\s*["\']?\s*([1-9]\d*)\s*["\']?', re.IGNORECASE)

# --- 4.1.2 Name, Role, Value: a <div>/<span> made clickable without a real interactive role or
# keyboard handler is invisible to keyboard-only and screen-reader users. Only flags a click
# handler with neither `role=` nor `tabIndex`/`tabindex` present on the same tag -- a div/span
# that already carries both is a deliberate, correctly-built custom control, not a violation.
_CLICKABLE_DIV_RE = re.compile(
    r'<(div|span)\b(?![^>]*\b(role|tabindex|tabIndex)\s*=)[^>]*\bon[Cc]lick\s*=', re.IGNORECASE
)


def audit_wcag_accessibility(file_path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    # --- 1.1.1: images without alt
    for idx, line in enumerate(lines, 1):
        for m in _IMG_TAG_RE.finditer(line):
            tag = m.group(0)
            if not _ALT_ATTR_RE.search(tag):
                findings.append({
                    "cve_id": "WCAG-1.1.1-IMG-MISSING-ALT",
                    "severity": "MEDIUM",
                    "file": file_path, "line": idx,
                    "description": f"WCAG 2.1 1.1.1 (Non-text Content): imagen sin atributo alt -- inaccesible para lectores de pantalla. Línea {idx}: {tag.strip()[:150]}"
                })

    # --- 1.3.1/4.1.2: form controls without a label
    label_ids = {m.group(1) for m in _LABEL_FOR_RE.finditer(content)}
    for idx, line in enumerate(lines, 1):
        for m in _FORM_CONTROL_RE.finditer(line):
            tag_name, attrs = m.group(1), m.group(2)
            type_m = re.search(r'\btype\s*=\s*["\']?(\w+)', attrs, re.IGNORECASE)
            input_type = (type_m.group(1).lower() if type_m else "text")
            if tag_name.lower() == "input" and input_type in _SKIP_INPUT_TYPES:
                continue
            if _ACCESSIBLE_NAME_ATTR_RE.search(attrs):
                continue
            id_m = re.search(r'\bid\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if id_m and id_m.group(1) in label_ids:
                continue
            full_tag = m.group(0)
            findings.append({
                "cve_id": "WCAG-1.3.1-FORM-CONTROL-NO-LABEL",
                "severity": "MEDIUM",
                "file": file_path, "line": idx,
                "description": f"WCAG 2.1 1.3.1/4.1.2 (Info and Relationships / Name, Role, Value): control de formulario ({tag_name}) sin <label for> asociado ni aria-label. Línea {idx}: {full_tag.strip()[:150]}"
            })

    # --- 2.4.4/4.1.2: empty links/buttons with no accessible name
    for idx, line in enumerate(lines, 1):
        for pattern, tag_label in ((_EMPTY_LINK_RE, "a"), (_EMPTY_BUTTON_RE, "button")):
            for m in pattern.finditer(line):
                attrs = m.group(1)
                if _ACCESSIBLE_NAME_ATTR_RE.search(attrs):
                    continue
                findings.append({
                    "cve_id": "WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT",
                    "severity": "MEDIUM",
                    "file": file_path, "line": idx,
                    "description": f"WCAG 2.1 2.4.4/4.1.2 (Link Purpose / Name, Role, Value): <{tag_label}> sin texto ni nombre accesible (aria-label/title) -- invisible para lectores de pantalla. Línea {idx}: {m.group(0).strip()[:150]}"
                })

    # --- 3.1.1: <html> without lang
    for idx, line in enumerate(lines, 1):
        for m in _HTML_TAG_RE.finditer(line):
            if not _LANG_ATTR_RE.search(m.group(1)):
                findings.append({
                    "cve_id": "WCAG-3.1.1-HTML-MISSING-LANG",
                    "severity": "LOW",
                    "file": file_path, "line": idx,
                    "description": f"WCAG 2.1 3.1.1 (Language of Page): la etiqueta <html> no declara idioma (lang=). Línea {idx}: {m.group(0).strip()[:150]}"
                })

    # --- 2.4.3: positive tabindex
    for idx, line in enumerate(lines, 1):
        for m in _POSITIVE_TABINDEX_RE.finditer(line):
            findings.append({
                "cve_id": "WCAG-2.4.3-POSITIVE-TABINDEX",
                "severity": "LOW",
                "file": file_path, "line": idx,
                "description": f"WCAG 2.1 2.4.3 (Focus Order): tabindex=\"{m.group(1)}\" positivo reordena el foco de teclado fuera del orden natural del documento -- antipatrón documentado (WebAIM/MDN). Línea {idx}."
            })

    # --- 4.1.2: clickable div/span without role/tabindex
    for idx, line in enumerate(lines, 1):
        for m in _CLICKABLE_DIV_RE.finditer(line):
            findings.append({
                "cve_id": "WCAG-4.1.2-CLICKABLE-DIV-NO-ROLE",
                "severity": "MEDIUM",
                "file": file_path, "line": idx,
                "description": f"WCAG 2.1 4.1.2 (Name, Role, Value): <{m.group(1)}> con manejador de clic pero sin role= ni tabindex -- inalcanzable por teclado y sin rol semántico para lectores de pantalla. Línea {idx}: {m.group(0).strip()[:150]}"
            })

    return findings


def run_wcag_accessibility_audit(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Scans target directory for real, static WCAG 2.1 A/AA violations."""
    all_findings: List[Dict[str, Any]] = []
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [
            ".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests",
            "data/remediation", "data/sonar_scans", ".mvn", "dist", "build",
        ]):
            continue
        for file in files:
            if file.endswith((".html", ".htm", ".xhtml", ".jsx", ".tsx", ".vue")):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    all_findings.extend(audit_wcag_accessibility(full_path, content))
                except Exception:
                    continue

    try:
        active_fingerprints = set()
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir)
                location = f"{rel_path}:{item['line']}"
                active_fingerprints.add(deduplication_engine.calculate_fingerprint(asset_id, item["cve_id"], location))
                log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"],
                    f"{location} - {item['description']}",
                    "accessibility-wcag", url_path=location, preserve_status=True
                )
            # Reconciles stale findings the same way auditor_compliance_standards.py does: only
            # meaningful with a real asset_id (a bare/default call has no well-defined "everything
            # else" set to reconcile against, same reasoning documented in CLAUDE.md item 14).
            if asset_id is not None:
                resolved_count = deduplication_engine.reconcile_resolved_findings(
                    cur, asset_id, "accessibility-wcag", active_fingerprints
                )
                if resolved_count:
                    print(f"✅ [WCAG-Auditor] Reconciled {resolved_count} stale accessibility finding(s) as RESOLVED for asset {asset_id}.")
    except Exception as e:
        print(f"⚠️ [WCAG-Auditor] Error logging to DB: {e}")

    return all_findings


def run(asset_id: int = None, endpoint: str = "") -> List[Dict[str, Any]]:
    """Wrapper for auditor_ext/gitlab_integration compatibility."""
    print(f"♿ [WCAG-Auditor] Running WCAG 2.1 A/AA static accessibility audit on: {endpoint or 'Target Workspace'}")
    return run_wcag_accessibility_audit(asset_id=asset_id)
