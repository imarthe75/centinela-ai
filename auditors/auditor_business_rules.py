"""
Business rules of the CORE / Starter catalogue (data/Catalogo_reglas_negocio_CORE_STARTER.xlsx, 165 rules «RN-xx-yyy»,
received 2026-10-28) that can be decided from the text of ONE file. The catalogue itself says most of its rules are functional
(they are verified by running the application -- centinela-smart-tests `business_rules` check), and that its «Inferida»/«Propuesta»
rules are not confirmed requirements. Only the rules below have a static signal; each finding cites the RN it comes from.

  PASSWORD-MIN-LENGTH-BELOW-STANDARD  (RN-01-005, Explícita)  a password validator with a minimum length under 10.
  NUMERIC-CODE-STORED-AS-NUMBER       (RN-06-012/-007/-004)   postal code / municipal or state key typed as a number (leading zeros lost).
  AUDIT-LOG-MUTATION-ENDPOINT         (RN-12-004, RN-13-006)  a bitácora/auditoría controller exposing PUT/PATCH/DELETE, or deleting audit rows.
  SVG-UPLOAD-WITHOUT-SANITIZATION     (RN-15-015)             SVG accepted as an upload type with no SVG sanitizer in the file.
  HTML-TEMPLATE-UNESCAPED-SUBSTITUTION (RN-15-012, RN-14-014) `{{var}}`/`[var]`/`${var}` replaced into an HTML template (e-mail or document) with a raw value.
  SEQUENTIAL-FOLIO-FROM-MAX           (RN-11-011)             next folio computed as MAX(...)+1 / last+1 with no lock or sequence in the file.
  ACCOUNT-ENUMERATION-RESPONSE        (RN-01-004)             password-recovery code that tells the caller the account/e-mail does not exist.

All are heuristics on one file and say so: a lock taken in another class, an escape done by a caller, or a server-side policy
enforced by the identity provider are not visible here. Names avoid the substrings the heuristic engine routes on (PORT, OPEN, ...).
"""
import os
import re
from typing import Any, Dict, List

_STANDARD_MIN_PASSWORD = 10  # RN-01-005


def _add(out, rule, sev, idx, lines, desc):
    snippet = lines[idx - 1].strip()[:140] if 0 < idx <= len(lines) else ""
    out.append({"cve_id": rule, "severity": sev, "line": idx, "description": f"{desc} Line {idx}: {snippet}"})


def _is_test_path(p: str) -> bool:
    p = p.replace("\\", "/")
    return bool(re.search(r"(^|/)(tests?|__tests__|spec|e2e)/|\.(spec|test)\.[jt]sx?$|Test\.java$|Tests\.java$|(^|/)test_\w+\.py$|_test\.py$", p))


def _comment(line: str) -> bool:
    return line.strip().startswith(("//", "*", "/*", "#", "--", "<!--"))


# ------------------------------------------------------------------ RN-01-005
_PWD_NAME = r"(?:password|passwd|contrase(?:n|ñ)i?a\w*|newPassword|nuevaContrase\w*|claveNueva|claveAcceso)"   # bare `clave` is a catalogue key, not a password
_PWD_TS = re.compile(r"(?:\b" + _PWD_NAME + r"\b\W{0,40}Validators\.minLength\(\s*(\d+)\s*\)|"
                     r"get\(\s*['\"]" + _PWD_NAME + r"['\"]\s*\)[^\n]{0,120}Validators\.minLength\(\s*(\d+)\s*\))", re.IGNORECASE)
_PWD_HTML = re.compile(r"<input[^>]*(?:type=\"password\"|(?:formControlName|name|id)=\"" + _PWD_NAME + r"\")[^>]*\bminlength=\"(\d+)\"", re.IGNORECASE)
_SIZE_MIN = re.compile(r"@(?:Size|Length)\s*\([^)]*\bmin\s*=\s*(\d+)")


def _password_min(file_path, content, lines, out):
    fn = os.path.basename(file_path)
    found = []
    if fn.endswith(".ts"):
        for i, line in enumerate(lines, 1):
            if _comment(line):
                continue
            m = _PWD_TS.search(line)
            if m:
                found.append((i, int(m.group(1) or m.group(2))))
    elif fn.endswith(".html"):
        for m in _PWD_HTML.finditer(content):
            found.append((content.count("\n", 0, m.start()) + 1, int(m.group(1))))
    elif fn.endswith((".java", ".kt")):
        for i, line in enumerate(lines, 1):
            if not re.search(r"\b(?:String|var|val)\b[^;=]*\b" + _PWD_NAME + r"\w*\b", line, re.IGNORECASE) or _comment(line):
                continue
            ctx = "\n".join(lines[max(0, i - 5):i])               # annotations sit on the same line (records) or just above
            m = None
            for m in _SIZE_MIN.finditer(ctx):
                pass
            if m:
                found.append((i, int(m.group(1))))
    for ln, n in found:
        if n < _STANDARD_MIN_PASSWORD:
            _add(out, "PASSWORD-MIN-LENGTH-BELOW-STANDARD", "LOW", ln, lines,
                 f"La contraseña se valida con mínimo {n} caracteres; el estándar del CORE/Starter (RN-01-005) pide mínimo "
                 f"{_STANDARD_MIN_PASSWORD}, con al menos una mayúscula, un número y un carácter especial, y la regla debe vivir también en "
                 f"el servidor. Si la contraseña la administra el proveedor de identidad, alinear su política en lugar de esta validación.")


# ------------------------------------------------------------------ RN-06-012 / -007 / -004
_GEO = r"(?:codigo_?postal|cod_?postal|c_?cp|d_?codigo|cp|(?:clave|cve|c_cve)_?(?:municipi\w*|mun|estado|edo|entidad|ent|localidad|loc|asentamiento|asenta|ciudad|colonia))"
_GEO_JAVA = re.compile(r"\b(?:private|protected|public)?\s*(?:Integer|Long|int|long|Short|short|BigInteger|BigDecimal)\s+(" + _GEO + r")\s*[;=]", re.IGNORECASE)
_GEO_TS = re.compile(r"\b(" + _GEO + r")\??\s*:\s*number\b", re.IGNORECASE)
_GEO_SQL = re.compile(r"(?:^|[\s,(])(?:ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?)?\"?(" + _GEO + r")\"?\s+(?:integer|int|int2|int4|int8|bigint|smallint|numeric|decimal)\b",
                      re.IGNORECASE)


def _numeric_codes(file_path, content, lines, out):
    fn = os.path.basename(file_path).lower()
    if _is_test_path(file_path):
        return
    rx = _GEO_JAVA if fn.endswith((".java", ".kt")) else _GEO_TS if fn.endswith(".ts") else _GEO_SQL if fn.endswith(".sql") else None
    if rx is None:
        return
    hits = []
    for i, line in enumerate(lines, 1):
        if _comment(line):
            continue
        if fn.endswith(".sql") and re.search(r"^\s*(?:v_|l_|declare\b)|\bv_\w+\s+integer", line, re.IGNORECASE):
            continue                                            # PL/pgSQL local variables (v_count_cp integer) are not columns
        m = rx.search(line)
        if m:
            hits.append((i, m.group(1)))
    if hits:
        ln, name = hits[0]
        extra = f" ({len(hits)} campos en el archivo)" if len(hits) > 1 else ""
        _add(out, "NUMERIC-CODE-STORED-AS-NUMBER", "LOW", ln, lines,
             f"`{name}` se guarda o tipa como número{extra}: los códigos postales y las claves geográficas son identificadores con ceros "
             "significativos (p. ej. CP 01000) y deben ser texto con su máscara (RN-06-012; CP nacional `^[0-9]{5}$`, RN-06-007; clave "
             "municipal hasta 3 dígitos, RN-06-004). Como número, 01000 se vuelve 1000 y no vuelve a coincidir con el catálogo.")


# ------------------------------------------------------------------ RN-12-004 / RN-13-006
_AUDIT_CLASS = re.compile(r"class\s+\w*(?:Bitacora|Auditoria|Auditor[ií]a|AuditLog|Audit)\w*(?:Controller|Resource|Api)\b")
_AUDIT_PATH = re.compile(r"@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\"[^\"]*(?:bitacora|auditoria|audit-log|audit)[^\"]*\"", re.IGNORECASE)
_MUTATION = re.compile(r"@(?:DeleteMapping|PutMapping|PatchMapping)\b|RequestMethod\.(?:DELETE|PUT|PATCH)\b")
_AUDIT_REPO_DELETE = re.compile(r"\b\w*(?:bitacora|auditoria|auditLog|audit)\w*Repository\s*\.\s*delete\w*\s*\(", re.IGNORECASE)


def _audit_mutation(file_path, content, lines, out):
    if not file_path.endswith((".java", ".kt")) or _is_test_path(file_path):
        return
    if _AUDIT_CLASS.search(content) or _AUDIT_PATH.search(content):
        for i, line in enumerate(lines, 1):
            if not _comment(line) and _MUTATION.search(line):
                _add(out, "AUDIT-LOG-MUTATION-ENDPOINT", "MEDIUM", i, lines,
                     "El controlador de bitácora/auditoría expone una operación que modifica o borra registros. La bitácora y la auditoría "
                     "son de solo consulta (RN-12-004, RN-13-006): quien pueda editar o borrar la evidencia puede ocultar lo que hizo. "
                     "Quitar el endpoint; la depuración por retención, si existe, va en un proceso programado y auditado, no en la API.")
                break
    for i, line in enumerate(lines, 1):
        if not _comment(line) and _AUDIT_REPO_DELETE.search(line):
            _add(out, "AUDIT-LOG-MUTATION-ENDPOINT", "MEDIUM", i, lines,
                 "Se borran registros de bitácora/auditoría desde el código de la aplicación. La evidencia es de solo agregar (RN-12-004, "
                 "RN-13-008): un borrado desde la aplicación permite eliminar rastros. Si hay retención, que la ejecute un proceso de "
                 "mantenimiento con su propio registro.")
            break


# ------------------------------------------------------------------ RN-15-015
_SVG_ALLOWED = re.compile(r"[\"']image/svg\+xml[\"']|[\"']\.?svg[\"']", re.IGNORECASE)
_UPLOAD_CTX = re.compile(r"MultipartFile|@RequestPart|FileUpload|UploadFile|request\.files|multer|getContentType\(\)|ALLOWED_\w*(?:TYPES|MIME|EXT)",
                         re.IGNORECASE)
_SVG_SANITIZER = re.compile(r"DOMPurify|sanitiz|SVGSanitizer|svg-sanitizer|Jsoup\.clean|OWASP|PolicyFactory|HtmlPolicyBuilder|defusedxml|bleach",
                            re.IGNORECASE)


def _svg_upload(file_path, content, lines, out):
    fn = os.path.basename(file_path)
    if not fn.endswith((".java", ".kt", ".py", ".cs")) or _is_test_path(file_path):
        return
    if not _UPLOAD_CTX.search(content) or _SVG_SANITIZER.search(content):
        return
    for i, line in enumerate(lines, 1):
        if not _comment(line) and _SVG_ALLOWED.search(line) and re.search(r"png|jpe?g|gif|webp", _SVG_ALLOWED.sub("", line), re.IGNORECASE):
            _add(out, "SVG-UPLOAD-WITHOUT-SANITIZATION", "MEDIUM", i, lines,
                 "Se acepta SVG en una lista de tipos de carga y el archivo no sanitiza SVG. Un SVG puede llevar `<script>`, manejadores "
                 "`on*` y recursos remotos: servido o incrustado en un correo/página es XSS almacenado (RN-15-015). Validar firma real y "
                 "sanitizar (lista blanca de elementos, sin scripts ni referencias externas) antes de guardar, o convertir a PNG.")
            break


# ------------------------------------------------------------------ RN-15-012 / RN-14-014
_TPL_REPLACE = re.compile(r"\.replace(?:All)?\(\s*(?:\"\{\{\"\s*\+|\"\{\{\s*\w+\s*\}\}\"|\"\[[A-Za-z_][\w ]*\]\"|\"\$\{\w+\}\")[^,]*,\s*(?![\s\"])([^)]+)\)")
_HTML_CTX = re.compile(r"html|plantilla|template|correo|email|mail", re.IGNORECASE)
_ESCAPER = re.compile(r"htmlEscape|escapeHtml\d*|Encode\.forHtml|HtmlEscapers|Jsoup\.clean|StringEscapeUtils|sanitiz", re.IGNORECASE)


def _template_escape(file_path, content, lines, out):
    if not file_path.endswith((".java", ".kt")) or _is_test_path(file_path):
        return
    if not _HTML_CTX.search(os.path.basename(file_path) + "\n" + content[:4000]) or _ESCAPER.search(content):
        return
    for i, line in enumerate(lines, 1):
        if _comment(line):
            continue
        m = _TPL_REPLACE.search(line)
        if m and not re.search(r"subject|asunto", line, re.IGNORECASE):
            _add(out, "HTML-TEMPLATE-UNESCAPED-SUBSTITUTION", "MEDIUM", i, lines,
                 "Una variable de plantilla se sustituye en el HTML (correo o documento) con su valor sin escapar. Un dato capturado por un "
                 "usuario (nombre, folio, dirección) puede inyectar HTML o enlaces en lo que recibe otra persona (RN-15-012). Escapar el valor "
                 "(`HtmlUtils.htmlEscape`) al sustituir, o usar un motor de plantillas con escape automático (Thymeleaf `th:text`).")
            break


# ------------------------------------------------------------------ RN-11-011
_MAX_PLUS_ONE = re.compile(r"(?:COALESCE\s*\(\s*)?MAX\s*\([^)]*\)\s*(?:,\s*0\s*\))?\s*\+\s*1|"
                           r"\b(?:get)?(?:Ultimo|Last|Max)\w*(?:Consecutivo|Folio|Numero|Secuencia)\w*\s*\(\s*\)\s*\+\s*1\b|"
                           r"\b(?:get)?(?:Consecutivo|Folio|Secuencia)\w*\s*\(\s*\)\s*\+\s*1\b", re.IGNORECASE)
_SAFE_SEQ = re.compile(r"PESSIMISTIC_WRITE|@Lock\b|FOR\s+UPDATE|ForUpdate|nextval|@SequenceGenerator|GenerationType\.SEQUENCE|"
                       r"synchronized|AtomicLong|incrementAndGet|SELECT\s+\w+\s+FROM\s+\w+\s+FOR|advisory_lock|UPDATE\s+\w+\s+SET\s+\w+\s*=\s*\w+\s*\+\s*1\s+.*RETURNING",
                       re.IGNORECASE)


def _folio(file_path, content, lines, out):
    if not file_path.endswith((".java", ".kt", ".py", ".sql")) or _is_test_path(file_path) or _SAFE_SEQ.search(content):
        return
    if not re.search(r"folio|consecutiv|secuencia|numerador", content, re.IGNORECASE):
        return
    if file_path.endswith(".sql") and not re.search(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)", content, re.IGNORECASE):
        return                                                  # seed/migration INSERT ... SELECT max(id)+1 runs once, not concurrently
    for i, line in enumerate(lines, 1):
        if _comment(line) or re.search(r"setval|==|!=|<=|>=", line):
            continue                                            # sequence resets and comparisons are not folio emission
        if _MAX_PLUS_ONE.search(line):
            _add(out, "SEQUENTIAL-FOLIO-FROM-MAX", "MEDIUM", i, lines,
                 "El siguiente folio/consecutivo se calcula como «el último + 1» sin bloqueo ni secuencia visible en el archivo. Dos "
                 "solicitudes simultáneas leen el mismo último valor y emiten el mismo folio (RN-11-011). Usar `SELECT ... FOR UPDATE` "
                 "(`@Lock(PESSIMISTIC_WRITE)`), una secuencia de la base o un `UPDATE ... SET n = n + 1 RETURNING n`, más un UNIQUE sobre "
                 "el folio. Si el bloqueo vive en otra clase, este hallazgo es un falso positivo.")
            break


# ------------------------------------------------------------------ RN-01-004
_RECOVERY_FILE = re.compile(r"recuper|reset|forgot|olvid|restablec|recover", re.IGNORECASE)
_NEG = r"(?:no existe|no est[aá] registrad\w*|no registrad\w*|no se encontr\w*|no encontrad\w*|not found|does not exist|not registered|unknown)"
_SUBJ = r"(?:correo|usuario|e-?mail|cuenta|account|user)"
# the negative and the account noun must be adjacent ("No se encontró el usuario", "correo no registrado"), not just in the same sentence
_DISCLOSE = re.compile(r"[\"'][^\"'\n]*(?:" + _NEG + r"[^\"'\n]{0,8}?\b(?:el |la |un |una )?" + _SUBJ + r"|" + _SUBJ + r"\w*[^\"'\n]{0,20}?" + _NEG + r")[^\"'\n]*[\"']?",
                       re.IGNORECASE)


def _enumeration(file_path, content, lines, out):
    fn = os.path.basename(file_path)
    if not fn.endswith((".java", ".kt", ".py", ".cs")) or _is_test_path(file_path) or not _RECOVERY_FILE.search(fn):
        return
    for i, line in enumerate(lines, 1):
        if _comment(line) or re.search(r"\blog(?:ger)?\.\w+\(", line):
            continue                                            # a server log may say it; the client response must not
        m = _DISCLOSE.search(line)
        if m:
            _add(out, "ACCOUNT-ENUMERATION-RESPONSE", "MEDIUM", i, lines,
                 "La recuperación de contraseña responde distinto cuando la cuenta o el correo no existe: permite averiguar qué correos "
                 "están registrados (RN-01-004, WSTG-IDNT-04). Responder siempre el mismo mensaje («si la cuenta existe, recibirás "
                 "instrucciones») y registrar el detalle solo en el log del servidor.")
            break


def scan_business_rules(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Static checks derived from the CORE/Starter business-rule catalogue. One file at a time; returns finding dicts."""
    out: List[Dict[str, Any]] = []
    lines = content.splitlines()
    _password_min(file_path, content, lines, out)
    _numeric_codes(file_path, content, lines, out)
    _audit_mutation(file_path, content, lines, out)
    _svg_upload(file_path, content, lines, out)
    _template_escape(file_path, content, lines, out)
    _folio(file_path, content, lines, out)
    _enumeration(file_path, content, lines, out)
    for f in out:
        f["file"] = file_path
    return out
