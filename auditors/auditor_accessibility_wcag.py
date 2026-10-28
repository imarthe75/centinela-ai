"""
auditor_accessibility_wcag.py — Centinela-AI v3
Real, static WCAG 2.1 (Level A/AA) accessibility auditor.

Added 2026-08-25 after cross-checking the internal methodology manual
(Manual_Metodologia_CA_v2_COMPLETO.docx, section 0B-2 "Estándares de seguridad, accesibilidad y
calidad de código"): accessibility is one of three families of mandatory rules every project
inherits, explicitly described there as "WCAG y las normas de imagen estatal aplicables al sector
público, requisito legal y no una preferencia de diseño" -- a legal requirement for the Estado de
México public-sector projects this platform already audits (proyecto-j/proyecto-k), not a nice-to-have.
Before this file, Centinela had zero dedicated coverage of this dimension: the only accessibility
signal anywhere in the platform was SonarQube's own incidental CODE_SMELL hits (e.g.
"Web:InputWithoutLabelCheck" on the proyecto-k frontend), filed as generic code-quality debt, never
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
from typing import List, Dict, Any, Tuple
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
# Real false positive found and fixed 2026-08-25, live against the proyecto-k frontend: PrimeNG's
# `pButton` directive (301 real occurrences in this one repo alone, confirmed via grep) renders
# its `label="..."` attribute AS the button's visible/accessible text at runtime -- the tag's own
# HTML content is correctly empty by design, that's how the component works, not a violation.
# `label=` isn't a standard WCAG accessible-name attribute on its own, but given how dominant this
# real pattern is here (and the same convention exists in Angular Material/ng-bootstrap), treating
# it as an accepted accessible-name source avoids drowning real violations in framework noise.
#
# Second, same-class false positive found and fixed the same day, live against the proyecto-k
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


# ---------------------------------------------------------------------------------------------------------------
# 2026-10-01 expansion (see core/coverage_matrix.py: the 11 WCAG 2.1 A/AA criteria that ARE statically checkable but had
# no rule). Same honesty contract as above: only unambiguous source-text patterns; anything needing a rendered page
# (contrast, reflow, real focus order) or human judgement stays out and is declared as such in the coverage registry.
# ---------------------------------------------------------------------------------------------------------------
_VIEWPORT_META_RE = re.compile(r'<meta\b[^>]*\bname\s*=\s*["\']viewport["\'][^>]*>', re.IGNORECASE)
_TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_IFRAME_RE = re.compile(r"<iframe\b([^>]*)>", re.IGNORECASE)
_AUTOCOMPLETE_RE = re.compile(r"\bautocomplete\s*=", re.IGNORECASE)
_PERSONAL_FIELD_RE = re.compile(r"(email|correo|password|contrase|passwd|username|usuario|tel[eé]fono|\btel\b|phone)", re.IGNORECASE)
_MARQUEE_RE = re.compile(r"<(marquee|blink)\b", re.IGNORECASE)
_MEDIA_TAG_RE = re.compile(r"<(video|audio)\b([^>]*)>", re.IGNORECASE)
_VIDEO_BLOCK_RE = re.compile(r"<video\b([^>]*)>(.*?)</video>", re.IGNORECASE | re.DOTALL)
_TRACK_CAPTIONS_RE = re.compile(r'<track\b[^>]*\bkind\s*=\s*["\']?(captions|subtitles)', re.IGNORECASE)
_CONDITIONAL_RE = re.compile(r"\*ngIf|\*ngSwitchCase|\*ngSwitchDefault|@if\b|@else\b|@switch\b|@case\b|\[hidden\]|ng-template", re.IGNORECASE)
_STATIC_ID_RE = re.compile(r'(?<![\w\[\(-])\bid\s*=\s*"([A-Za-z][\w:.-]*)"')
_EMPTY_HEADING_RE = re.compile(r"<(h[1-6])\b([^>]*)>\s*</\1>", re.IGNORECASE)
_LABEL_IN_NAME_RE = re.compile(
    r'<(button|a)\b([^>]*)\baria-label\s*=\s*["\']([^"\']+)["\']([^>]*)>([^<>{]+)</\1>', re.IGNORECASE)
_CSS_BLOCK_RE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_OUTLINE_REMOVED_RE = re.compile(r"\boutline\s*:\s*(none|0)\b|\boutline-style\s*:\s*none\b", re.IGNORECASE)
_FOCUS_ALTERNATIVE_RE = re.compile(r"\b(box-shadow|border(-color|-width|-bottom)?|background(-color)?|text-decoration|outline\s*:\s*(?!none|0)[^;]+)\s*:", re.IGNORECASE)
# vendored themes/minified bundles are not the project's own CSS (same reasoning as the SonarQube exclusions)
_VENDORED_CSS_RE = re.compile(r"(\.min\.|/assets/layout/|/assets/theme|/vendor/|/primeng/|/primeicons/|/node_modules/)", re.IGNORECASE)


def _viewport_blocks_zoom(tag: str) -> bool:
    m = re.search(r'content\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
    if not m:
        return False
    content = m.group(1).lower().replace(" ", "")
    if re.search(r"user-scalable=(no|0)", content):
        return True
    ms = re.search(r"maximum-scale=([0-9.]+)", content)
    try:
        return bool(ms) and float(ms.group(1)) < 2.0
    except ValueError:
        return False


def audit_wcag_extended(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Additional static WCAG 2.1 A/AA rules (1.2.2, 1.3.5, 1.4.2, 1.4.4, 2.2.2, 2.4.2, 2.4.6, 2.5.3, 4.1.1, 4.1.2/2.4.1)."""
    out: List[Dict[str, Any]] = []
    lines = content.splitlines()

    def add(rule, sev, idx, sc, text):
        out.append({"cve_id": rule, "severity": sev, "file": file_path, "line": idx,
                    "description": f"WCAG 2.1 {sc}: {text} Línea {idx}."})

    # 1.4.4 Resize text: a viewport that forbids zooming
    for idx, line in enumerate(lines, 1):
        for m in _VIEWPORT_META_RE.finditer(line):
            if _viewport_blocks_zoom(m.group(0)):
                add("WCAG-1.4.4-VIEWPORT-ZOOM-DISABLED", "MEDIUM", idx, "1.4.4 (Resize text)",
                    "la meta viewport impide ampliar el texto (`user-scalable=no` o `maximum-scale` < 2); quien necesita zoom no puede usar la página.")

    # 2.4.2 Page Titled: only for complete documents (a fragment/component template legitimately has no <html>/<head>)
    if re.search(r"<html\b", content, re.IGNORECASE) and re.search(r"<head\b", content, re.IGNORECASE):
        titles = _TITLE_RE.findall(content)
        if not titles or not any(re.sub(r"<[^>]+>|\s", "", t) for t in titles):
            idx = next((i for i, l in enumerate(lines, 1) if re.search(r"<html\b", l, re.IGNORECASE)), 1)
            add("WCAG-2.4.2-MISSING-TITLE", "MEDIUM", idx, "2.4.2 (Page Titled)", "el documento no define un <title> con texto.")

    # 2.4.1 Bypass Blocks: the ROOT template of an SPA (the one hosting <router-outlet>) needs a "skip to content" link.
    # Only app-shell files are checked: a routed page legitimately has none (the shell owns it).
    base = os.path.basename(file_path).lower()
    if base in ("app.component.html", "app.html", "layout.component.html", "app-layout.component.html", "index.html") \
            and re.search(r"<router-outlet\b|<app-root\b", content, re.IGNORECASE):
        has_skip = re.search(r'<a\b[^>]*href\s*=\s*["\']#[^"\']*["\'][^>]*>[^<]*(saltar|skip|ir al contenido|contenido principal|main content)', content, re.IGNORECASE) \
            or re.search(r'(skip-?link|skip-to-content|saltar-al-contenido)', content, re.IGNORECASE)
        if not has_skip:
            idx = next((i for i, l in enumerate(lines, 1) if re.search(r"<router-outlet\b|<app-root\b", l, re.IGNORECASE)), 1)
            add("WCAG-2.4.1-NO-SKIP-LINK", "LOW", idx, "2.4.1 (Bypass Blocks)",
                "la plantilla raíz no ofrece un enlace «saltar al contenido principal»: quien navega con teclado debe recorrer todo el menú en cada página.")

    # 4.1.2 / 2.4.1: <iframe> without an accessible title
    for idx, line in enumerate(lines, 1):
        for m in _IFRAME_RE.finditer(line):
            if not re.search(r"\b(title|aria-label|aria-labelledby)\s*=", m.group(1), re.IGNORECASE) and "[title]" not in m.group(1) and "[attr.title]" not in m.group(1):
                add("WCAG-4.1.2-IFRAME-NO-TITLE", "MEDIUM", idx, "4.1.2/2.4.1 (Name, Role, Value / Bypass Blocks)",
                    "<iframe> sin `title`: el lector de pantalla no puede anunciar qué contiene el marco.")

    # 1.3.5 Identify Input Purpose (AA): personal-data fields with no autocomplete token at all
    for idx, line in enumerate(lines, 1):
        for m in _FORM_CONTROL_RE.finditer(line):
            if m.group(1).lower() != "input":
                continue
            attrs = m.group(2)
            type_m = re.search(r'\btype\s*=\s*["\']?(\w+)', attrs, re.IGNORECASE)
            itype = type_m.group(1).lower() if type_m else "text"
            ident = " ".join(re.findall(r'\b(?:name|id|formControlName|placeholder)\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE))
            if itype in ("hidden", "submit", "button", "reset", "image", "checkbox", "radio", "file", "search"):
                continue
            if _AUTOCOMPLETE_RE.search(attrs) or "[autocomplete]" in attrs:
                continue
            if itype in ("email", "tel", "password") or _PERSONAL_FIELD_RE.search(ident):
                add("WCAG-1.3.5-INPUT-NO-AUTOCOMPLETE", "LOW", idx, "1.3.5 (Identify Input Purpose)",
                    "campo de datos personales sin atributo `autocomplete` (p. ej. `autocomplete=\"email\"`, `\"current-password\"`): se pierde el autollenado y los símbolos de apoyo cognitivo.")

    # 2.2.2 Pause, Stop, Hide: <marquee>/<blink>
    for idx, line in enumerate(lines, 1):
        if _MARQUEE_RE.search(line):
            add("WCAG-2.2.2-MARQUEE-BLINK", "MEDIUM", idx, "2.2.2 (Pause, Stop, Hide)", "contenido en movimiento/parpadeo (<marquee>/<blink>) sin forma de pausarlo.")

    # 1.4.2 Audio Control: media that autoplays WITH sound (video autoplay is fine when muted)
    for idx, line in enumerate(lines, 1):
        for m in _MEDIA_TAG_RE.finditer(line):
            attrs = m.group(2)
            if re.search(r"\bautoplay\b", attrs, re.IGNORECASE) and not re.search(r"\bmuted\b", attrs, re.IGNORECASE):
                add("WCAG-1.4.2-AUTOPLAY-MEDIA", "MEDIUM", idx, "1.4.2 (Audio Control)",
                    f"<{m.group(1).lower()}> con `autoplay` y sin `muted`: reproduce audio automáticamente y estorba al lector de pantalla.")

    # 1.2.2 Captions (Prerecorded): <video> block with sound and no captions/subtitles track
    for m in _VIDEO_BLOCK_RE.finditer(content):
        attrs, inner = m.group(1), m.group(2)
        if re.search(r"\bmuted\b|aria-hidden\s*=\s*[\"']true", attrs, re.IGNORECASE):
            continue
        if not _TRACK_CAPTIONS_RE.search(inner):
            idx = content.count("\n", 0, m.start()) + 1
            add("WCAG-1.2.2-VIDEO-NO-CAPTIONS", "MEDIUM", idx, "1.2.2 (Captions, Prerecorded)", "<video> sin pista `<track kind=\"captions\">`: el audio no es accesible para personas sordas.")

    # 4.1.1 Parsing (removed in WCAG 2.2 but still part of 2.1 AA): literal duplicate ids in one template.
    # LOW: mutually exclusive branches (*ngIf / else) may legitimately reuse an id.
    # Measured live 2026-10-01 over the 26 priority repos: 377 raw hits, many from `*ngIf`/`@if` branches that can be
    # mutually exclusive. Only UNCONDITIONAL duplicates (neither element behind a structural condition) are reported.
    seen: Dict[str, Tuple[int, bool]] = {}
    for idx, line in enumerate(lines, 1):
        conditional = bool(_CONDITIONAL_RE.search(line))
        for m in _STATIC_ID_RE.finditer(line):
            ident = m.group(1)
            if ident in seen:
                first_line, first_conditional = seen[ident]
                if not conditional and not first_conditional:
                    add("WCAG-4.1.1-DUPLICATE-ID", "LOW", idx, "4.1.1 (Parsing)",
                        f"el id `{ident}` ya se usó, sin condición estructural, en la línea {first_line} de esta plantilla; los ids duplicados rompen `label for`, ARIA y anclas.")
            else:
                seen[ident] = (idx, conditional)

    # 2.4.6 Headings and Labels: truly empty heading
    for idx, line in enumerate(lines, 1):
        for m in _EMPTY_HEADING_RE.finditer(line):
            if not re.search(r"\baria-label(ledby)?\s*=", m.group(2), re.IGNORECASE):
                add("WCAG-2.4.6-EMPTY-HEADING", "MEDIUM", idx, "2.4.6 (Headings and Labels)", f"<{m.group(1)}> vacío: crea una entrada sin texto en la navegación por encabezados.")

    # 2.5.3 Label in Name: the accessible name must contain the visible text (voice control says what it sees)
    for idx, line in enumerate(lines, 1):
        for m in _LABEL_IN_NAME_RE.finditer(line):
            visible = re.sub(r"\s+", " ", m.group(5)).strip().lower()
            name = re.sub(r"\s+", " ", m.group(3)).strip().lower()
            if visible and len(visible) > 1 and "{{" not in visible and visible not in name:
                add("WCAG-2.5.3-LABEL-IN-NAME", "LOW", idx, "2.5.3 (Label in Name)",
                    f"el texto visible «{m.group(5).strip()[:40]}» no está contenido en su aria-label «{m.group(3)[:40]}»: el control por voz no puede activarlo por lo que se ve.")
    return out


def audit_wcag_css(file_path: str, content: str) -> List[Dict[str, Any]]:
    """2.4.7 Focus Visible: a `:focus` rule that removes the outline and gives no alternative indicator."""
    if _VENDORED_CSS_RE.search(file_path.replace("\\", "/")):
        return []
    out: List[Dict[str, Any]] = []
    for m in _CSS_BLOCK_RE.finditer(content):
        selector, body = m.group(1), m.group(2)
        if ":focus" not in selector:
            continue
        if _OUTLINE_REMOVED_RE.search(body) and not _FOCUS_ALTERNATIVE_RE.search(body):
            idx = content.count("\n", 0, m.start()) + 1
            out.append({"cve_id": "WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", "severity": "MEDIUM", "file": file_path, "line": idx,
                        "description": (f"WCAG 2.1 2.4.7 (Focus Visible): `{selector.strip()[:80]}` quita el contorno de foco (`outline: none`) y no define "
                                        f"otro indicador (box-shadow, borde, fondo, subrayado): quien navega con teclado pierde la posición. Línea {idx}.")})
    return out


def blank_html_comments(content: str) -> str:
    """Replace every `<!-- ... -->` with spaces, keeping the newlines so reported line numbers do not move. Markup inside an HTML comment is not rendered, so it
    cannot fail any accessibility criterion (until 2026-10-13 commented-out inputs and buttons were reported as findings)."""
    return re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), content, flags=re.S)


def audit_wcag_accessibility(file_path: str, content: str) -> List[Dict[str, Any]]:
    content = blank_html_comments(content)
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

    findings.extend(audit_wcag_extended(file_path, content))
    return findings


def run_wcag_accessibility_audit(target_dir: str = "/app", asset_id: str = None) -> List[Dict[str, Any]]:
    """Scans target directory for real, static WCAG 2.1 A/AA violations."""
    all_findings: List[Dict[str, Any]] = []
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [
            ".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests",
            "data/remediation", "data/sonar_scans", ".mvn", "dist", "build", ".agents",
            "/target/", "\\target\\",
        ]):
            continue
        for file in files:
            if file.endswith((".html", ".htm", ".xhtml", ".jsx", ".tsx", ".vue", ".css", ".scss", ".less")):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if file.endswith((".css", ".scss", ".less")):
                        all_findings.extend(audit_wcag_css(full_path, content))
                    else:
                        all_findings.extend(audit_wcag_accessibility(full_path, content))
                except Exception:
                    import traceback
                    traceback.print_exc()
                    print(f"⚠️ [WCAG-Auditor] Could not analyse {full_path}; continuing with the next file.")
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


def run(asset_id: str = None, endpoint: str = "") -> List[Dict[str, Any]]:
    """Wrapper for auditor_ext/gitlab_integration compatibility."""
    print(f"♿ [WCAG-Auditor] Running WCAG 2.1 A/AA static accessibility audit on: {endpoint or 'Target Workspace'}")
    return run_wcag_accessibility_audit(asset_id=asset_id)
