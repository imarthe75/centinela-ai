"""
Rules taken from the "Estándar Maestro de Auditoría" (resident-agent-os docs, rewritten for Setag, ADR-0012) that Centinela did not detect yet.
Each is decidable from the text of ONE file, has its own false-positive guard, and is stored as INFORMATIONAL (standards conformance / process,
not an individually exploitable vulnerability -- same call as VALIDATION-REIMPLEMENTED):

  SWALLOWED-ERROR              (std 5.4)  empty catch / `.catch(() => [])` / bare `except: pass`: the symptom disappears, the cause stays.
  DESTRUCTIVE-ACTION-NO-CONFIRM(std 5.10) a delete/revoke call with no confirmation mechanism near it (Angular/TS).
  NATIVE-BROWSER-DIALOG        (std 5.10) native confirm()/alert(): works, but is the shortcut instead of the UI library's dialog.
  SQL-TABLE-WITHOUT-PRIMARY-KEY(std 5.11) CREATE TABLE with no primary key in a .sql migration.
  CICD-GATE-ALLOW-FAILURE      (std 6)    a test/lint/security job that may fail without failing the pipeline (allow_failure / continue-on-error).
  TEST-SKIPPED-WITHOUT-REASON  (std 6)    skipped/disabled/focused test with no stated reason.

Added 2026-10-27 from the shared organisation skills (database standard, Starter conventions):
  SQL-PK-NOT-UUID / SQL-TIMESTAMP-WITHOUT-TIMEZONE / SQL-JSON-NOT-JSONB / SQL-FLOAT-FOR-MONEY / SQL-TABLE-WITHOUT-AUDIT-COLUMNS
                               .sql conformance with the organisation's database and audit standard; aggregated per file. Tables with the legacy
                               fc*/ds*/bo* audit convention are not asked for canonical columns or timestamptz (the standard leaves them alone).
  TRANSACTIONAL-ON-CONTROLLER, FIELD-INJECTION-AUTOWIRED, JPA-OBJECT-ARRAY-RESULT, FRONTEND-HARDCODED-API-URL   code conventions.
  API-ENDPOINT-UNDOCUMENTED    Spring controller endpoints without an OpenAPI @Operation (per file, count of undocumented endpoints).
  SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE (vulnerability)  Hibernate allowed to alter/drop the schema at startup.
  FRONTEND-OIDC-INSECURE-CONFIG     (vulnerability)  OIDC client accepting HTTP / unvalidated discovery outside the local environment.
Heuristics, and they say so in their description.
"""
import os
import re
from typing import Any, Dict, List

try:
    import yaml
except ImportError:                                  # the scanners run where PyYAML exists; without it the CI rule is simply not evaluated
    yaml = None

_TEST_WORDS = re.compile(r"(test|lint|sast|security|scan|audit|quality|check|e2e|unit|spec)", re.IGNORECASE)
_CONFIRM_WORDS = re.compile(r"(ConfirmationService|ConfirmDialog|confirm\w*\s*\(|MatDialog|NgbModal|BsModalService|DialogService|\bswal\b|Swal\.fire|modalService|\bdialog\b)", re.IGNORECASE)
_DESTRUCTIVE_METHOD = re.compile(r"^\s*(?:public\s+|private\s+|protected\s+)?(?:async\s+)?(?P<name>(?:delete|eliminar|borrar|remove|revoke|revocar|cancelar|anular|destroy|baja)\w*)\s*\([^)]*\)\s*(?::\s*[\w<>\[\]| ]+)?\s*\{")
_DESTRUCTIVE_CALL = re.compile(r"\.(delete|remove|eliminar|borrar|revocar|destroy|anular)\w*\s*\(", re.IGNORECASE)
_BENIGN_VAR = re.compile(r"\b(ignored?|expected|_|unused|noop)\b", re.IGNORECASE)


def _add(out, rule, sev, idx, lines, desc):
    out.append({"cve_id": rule, "severity": sev, "line": idx,
                "description": f"{desc} Line {idx}: {lines[idx - 1].strip()[:140] if 0 < idx <= len(lines) else ''}"})


def _is_test_path(p: str) -> bool:
    p = p.replace("\\", "/")
    return bool(re.search(r"(^|/)(tests?|__tests__|spec|e2e)/|\.(spec|test)\.[jt]sx?$|Test\.java$|Tests\.java$|(^|/)test_\w+\.py$|_test\.py$", p))


def _vendored(p: str) -> bool:
    return bool(re.search(r"(\.min\.|\.bundle\.|/assets/plugins/|/vendor/|/node_modules/|/dist/|/build/)", p.replace("\\", "/"), re.IGNORECASE))


def _swallowed(file_path, content, lines, out):
    fn = os.path.basename(file_path)
    if fn.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".java", ".kt", ".cs")):
        for m in re.finditer(r"\bcatch\s*(?:\((?P<v>[^)]*)\))?\s*\{\s*\}", content):
            if m.group("v") and _BENIGN_VAR.search(m.group("v")):
                continue                                                  # `catch (ignored) {}` states the intent
            if fn.endswith(".java") and re.search(r"InterruptedException", m.group("v") or ""):
                continue
            _add(out, "SWALLOWED-ERROR", "MEDIUM", content.count("\n", 0, m.start()) + 1, lines,
                 "`catch` vacío: el error desaparece sin registrarse ni propagarse (el síntoma se oculta, la causa sigue).")
        if fn.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")):
            for m in re.finditer(r"\.catch\(\s*\(?\s*\w*\s*\)?\s*=>\s*(?:\[\]|null|undefined|of\(\s*(?:\[\]|null)\s*\)|EMPTY)\s*\)", content):
                _add(out, "SWALLOWED-ERROR", "MEDIUM", content.count("\n", 0, m.start()) + 1, lines,
                     "`.catch(() => [])`/`null`: un error real se convierte en «sin resultados» sin registrarlo (un endpoint roto parece una lista vacía).")
    elif fn.endswith(".py"):
        for m in re.finditer(r"^[ \t]*except(?P<what>[^\n:]*):[ \t]*(?:\n[ \t]+pass\b|pass\b)", content, re.MULTILINE):
            what = m.group("what").strip()
            broad = what in ("", "Exception", "BaseException") or what.startswith(("Exception as", "BaseException as", "(Exception"))
            if not broad:
                continue                                                  # `except ImportError: pass` etc. are usually deliberate
            _add(out, "SWALLOWED-ERROR", "MEDIUM", content.count("\n", 0, m.start()) + 1, lines,
                 "`except` genérico con `pass`: cualquier error queda silenciado; registra con traza o propaga.")


def _confirm(file_path, lines, out):
    if not file_path.endswith(".ts") or _is_test_path(file_path) or _vendored(file_path):
        return
    text = "\n".join(lines)
    # A confirmation is the UI's job. A data service that merely wraps the HTTP DELETE (@Injectable, no @Component) is not the place to ask.
    is_ui = bool(re.search(r"@Component\s*\(", text))
    conf_idx = [i for i, l in enumerate(lines) if _CONFIRM_WORDS.search(l)]
    # method name -> call lines (excluding its definition)
    for i, line in enumerate(lines if is_ui else []):
        m = _DESTRUCTIVE_METHOD.match(line)
        if not m:
            continue
        name = m.group("name")
        depth, end = 0, min(len(lines), i + 60)
        j = i
        while j < end:
            depth += lines[j].count("{") - lines[j].count("}")
            if depth <= 0 and j > i:
                break
            j += 1
        body = range(i, j + 1)
        calls = [k for k in body if _DESTRUCTIVE_CALL.search(lines[k]) and not re.search(r"^\s*(//|\*)", lines[k])]
        if not calls:
            continue
        in_body = any(i <= c <= j for c in conf_idx)
        invoked_under_confirm = any(re.search(r"\b" + re.escape(name) + r"\s*\(", lines[k]) and k != i and any(0 <= k - c <= 30 for c in conf_idx)
                                    for k in range(len(lines)))
        if not in_body and not invoked_under_confirm:
            _add(out, "DESTRUCTIVE-ACTION-NO-CONFIRM", "LOW", calls[0] + 1, lines,
                 f"`{name}()` borra/revoca sin que se vea un diálogo de confirmación en su cuerpo ni en quien lo invoca (heurística; "
                 "puede confirmarse en la plantilla o en otro componente: requiere validación).")
    for i, line in enumerate(lines):
        mm = re.search(r"(?<![\w.$])(?:window\.)?(?:confirm|alert)\s*\(", line)
        if mm and "<" not in line[:mm.start()] and not re.search(r"\(\s*(?:click|onClick|ngSubmit)\s*\)\s*=", line) \
                and not line.strip().startswith(("//", "*")) \
                and not re.match(r"^\s*(?:public\s+|private\s+|protected\s+)?(?:async\s+)?(?:confirm|alert)\s*\([^)]*\)\s*(?::[^{]+)?\{", line):
            _add(out, "NATIVE-BROWSER-DIALOG", "LOW", i + 1, lines,
                 "`confirm()`/`alert()` nativo del navegador: funciona, pero es el atajo; usa el diálogo estándar de la librería de UI para ser consistente y accesible.")


_SQL_TABLE = re.compile(r"CREATE\s+(?P<mod>(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP(?:ORARY)?\s+|UNLOGGED\s+)?)TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
                        r"(?P<name>(?:\"?\w+\"?\.)?\"?\w+\"?)\s*(?P<rest>\(|AS\b|PARTITION\s+OF\b|\w)", re.IGNORECASE)
_LEGACY_AUDIT = re.compile(r"\b(fccreacion|fcmodificacion|dsusuariocreacion|dsusuariomodifica\w*|boactivo|boborrado)\b", re.IGNORECASE)
_MONEY_COL = re.compile(r"(?:^|[,(\s])\"?(\w*(?:monto|importe|precio|saldo|costo|tarifa|pago|total|subtotal|iva)\w*)\"?\s+"
                        r"(money|real|float[48]?|double\s+precision)\b", re.IGNORECASE)
_COLDEF = r"(?:^|[,(]|ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?|TYPE\s+)\s*"


def _short(name: str) -> str:
    return name.replace('"', "").split(".")[-1].lower()


def _alters_for(clean: str, name: str) -> str:
    """Text of every ALTER TABLE statement on `name` in the same file (columns and keys are often added after an empty CREATE TABLE ();)."""
    short = _short(name)
    out = []
    for m in re.finditer(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?P<n>(?:\"?\w+\"?\.)?\"?\w+\"?)(?P<body>[^;]*)", clean, re.IGNORECASE):
        if _short(m.group("n")) == short:
            out.append(m.group("body"))
    return "\n".join(out)


def _sql(file_path, content, out):
    """Migration rules on .sql files. One finding per table for the missing primary key (existing rule); the conformance rules of the
    organisation database standard (UUID keys, timestamptz, jsonb, numeric money, audit columns) are aggregated per file so a schema dump
    produces one finding per rule, not one per table."""
    if not file_path.lower().endswith(".sql"):
        return
    clean = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), content, flags=re.DOTALL)
    clean = re.sub(r"--[^\n]*", lambda m: " " * len(m.group(0)), clean)
    lines = content.splitlines()
    agg = {"SQL-PK-NOT-UUID": [], "SQL-TIMESTAMP-WITHOUT-TIMEZONE": [], "SQL-JSON-NOT-JSONB": [], "SQL-FLOAT-FOR-MONEY": [],
           "SQL-TABLE-WITHOUT-AUDIT-COLUMNS": []}
    for m in _SQL_TABLE.finditer(clean):
        if m.group("mod").strip() or not m.group("rest").startswith("("):
            continue                                                     # temp tables, CREATE TABLE AS, partitions
        depth, k = 0, m.end() - 1
        while k < len(clean):
            depth += (clean[k] == "(") - (clean[k] == ")")
            if depth == 0:
                break
            k += 1
        body = clean[m.end() - 1:k + 1]
        if re.search(r"\bLIKE\b", body, re.IGNORECASE) or re.match(r"\s*ENGINE\s*=", clean[k + 1:k + 200], re.IGNORECASE):
            continue                                                     # LIKE copies; ClickHouse/MySQL tables (ENGINE = ...) follow other rules
        name = m.group("name").replace('"', "")
        line = content.count("\n", 0, m.start()) + 1
        cols = body + "\n" + _alters_for(clean, name)
        if not re.search(r"PRIMARY\s+KEY", cols, re.IGNORECASE):
            _add(out, "SQL-TABLE-WITHOUT-PRIMARY-KEY", "MEDIUM", line, lines,
                 f"La tabla `{name}` se crea sin llave primaria: sin ella no hay identidad de fila, ni réplica lógica, ni defensa contra duplicados.")
        if re.match(r"(?i)auditoria(_control)?\.", name):
            continue                                                     # the audit standard's own objects (bigint chain id by design)
        legacy = bool(_LEGACY_AUDIT.search(cols))
        if re.search(r"\b(big|small)?serial\b|GENERATED\s+(?:BY\s+DEFAULT|ALWAYS)\s+AS\s+IDENTITY|" + _COLDEF + r"\"?id\"?\s+(?:integer|int[248]?|bigint|smallint)\b",
                     cols, re.IGNORECASE):
            agg["SQL-PK-NOT-UUID"].append((line, name))
        if not legacy:
            if re.search(_COLDEF + r"\"?\w+\"?\s+timestamp(?:\s*\(\d\))?(?!\s*\(?\d?\)?\s*with\s+time\s+zone)(?!tz)\b", cols, re.IGNORECASE | re.MULTILINE):
                agg["SQL-TIMESTAMP-WITHOUT-TIMEZONE"].append((line, name))
            if not re.search(r"\brow_version\b", cols, re.IGNORECASE):
                agg["SQL-TABLE-WITHOUT-AUDIT-COLUMNS"].append((line, name))
        if re.search(_COLDEF + r"\"?\w+\"?\s+json\b(?!b)", cols, re.IGNORECASE | re.MULTILINE):
            agg["SQL-JSON-NOT-JSONB"].append((line, name))
        if _MONEY_COL.search(cols):
            agg["SQL-FLOAT-FOR-MONEY"].append((line, name))
    texts = {
        "SQL-PK-NOT-UUID": ("LOW", "llave primaria entera/serial/IDENTITY en lugar de `uuid DEFAULT uuidv7()` (estándar de base de datos): "
                            "un id secuencial se puede adivinar y enumerar"),
        "SQL-TIMESTAMP-WITHOUT-TIMEZONE": ("LOW", "columnas `timestamp` sin zona horaria; el estándar pide `timestamptz` para eventos auditables"),
        "SQL-JSON-NOT-JSONB": ("LOW", "columnas `json` en lugar de `jsonb` (sin índices GIN ni comparación por contenido)"),
        "SQL-FLOAT-FOR-MONEY": ("MEDIUM", "montos con `money`/`real`/`float`/`double precision`: el redondeo binario altera importes; usa `numeric(p,s)`"),
        "SQL-TABLE-WITHOUT-AUDIT-COLUMNS": ("LOW", "tablas sin las columnas canónicas del estándar de auditoría de base de datos (`ref`, `row_version`, `fecha_*`, "
                                            "`usuario_*`, `activo`, `borrado`): `audit_biu` no puede mantenerlas ni hay concurrencia optimista"),
    }
    for rule, items in agg.items():
        if items:
            sev, what = texts[rule]
            names = ", ".join(f"`{n}`" for _, n in items[:10]) + (f" y {len(items) - 10} más" if len(items) > 10 else "")
            _add(out, rule, sev, items[0][0], lines, f"{len(items)} tabla(s) con {what}: {names}.")


def _config(file_path, content, lines, out):
    fn = os.path.basename(file_path).lower()
    if not re.match(r"(application|bootstrap)[\w.-]*\.(properties|ya?ml)$", fn):
        return
    m = re.search(r"ddl-auto\s*[:=]\s*[\"']?(create-drop|create|update)\b", content, re.IGNORECASE)
    if not m:
        return
    mode = m.group(1).lower()
    dev = bool(re.search(r"[-_](dev|local|test|h2)\b", fn))
    sev = "LOW" if dev else ("HIGH" if mode.startswith("create") else "MEDIUM")
    _add(out, "SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE", sev, content.count("\n", 0, m.start()) + 1, lines,
         f"`spring.jpa.hibernate.ddl-auto={mode}`: Hibernate modifica (o borra y recrea) el esquema al arrancar, fuera del control de las "
         "migraciones Liquibase y sin auditoría del cambio" + (" (perfil de desarrollo)." if dev else "; en un ambiente real puede perder datos. Usa `none` o `validate`."))


def _java(file_path, content, lines, out):
    if not file_path.endswith(".java") or _is_test_path(file_path):
        return
    is_controller = bool(re.search(r"@(Rest)?Controller\b", content))
    if is_controller:
        for i, line in enumerate(lines):
            if re.match(r"\s*@Transactional\b", line):
                _add(out, "TRANSACTIONAL-ON-CONTROLLER", "LOW", i + 1, lines,
                     "`@Transactional` en un controller: la transacción debe vivir en el servicio (frontera de negocio), no en la capa web.")
                break
    if is_controller:
        maps = [i for i, l in enumerate(lines) if re.match(r"\s*@(Get|Post|Put|Patch|Delete|Request)Mapping\b", l)]
        cls = next((i for i, l in enumerate(lines) if re.search(r"\bclass\s+\w+", l) and not l.strip().startswith(("//", "*"))), -1)
        endpoints = [i for i in maps if i > cls]                        # a mapping above the class declaration is the base path
        def _documented(i):
            for j in range(i - 1, max(-1, i - 40), -1):                # walk the annotation block above, stop at the previous member
                t = lines[j].strip()
                if "@Operation" in t:
                    return True
                if t.endswith(("}", ";", "{")) and not t.startswith("@"):
                    break
            return any("@Operation" in l for l in lines[i + 1:i + 4] if l.strip().startswith("@"))
        undocumented = [i for i in endpoints if not _documented(i)]
        if undocumented:
            _add(out, "API-ENDPOINT-UNDOCUMENTED", "LOW", undocumented[0] + 1, lines,
                 f"{len(undocumented)} de {len(endpoints)} endpoint(s) sin `@Operation`/`@ApiResponses`: el contrato OpenAPI no describe qué hacen, "
                 "qué reciben ni qué errores devuelven. Documenta cada endpoint con resumen, respuestas de éxito y de error con ejemplos.")
    field_inj = []
    for i, line in enumerate(lines):
        if re.match(r"\s*@Autowired\b\s*$", line) or re.match(r"\s*@Autowired\s+(private|protected|public)?\s*[\w<>,\s?]+\s+\w+\s*;", line):
            nxt = line if ";" in line else next((l for l in lines[i + 1:i + 4] if l.strip() and not l.strip().startswith("@")), "")
            if re.match(r"\s*(@Autowired\s+)?(private|protected|public)?\s*(final\s+)?[\w<>,.?\s]+\s+\w+\s*(=[^;]*)?;", nxt) and "(" not in nxt:
                field_inj.append(i + 1)
    if field_inj:
        _add(out, "FIELD-INJECTION-AUTOWIRED", "LOW", field_inj[0], lines,
             f"{len(field_inj)} campo(s) con `@Autowired`: usa inyección por constructor con campos `final` (`@RequiredArgsConstructor`); "
             "las dependencias quedan explícitas y la clase se puede probar sin Spring.")
    m = re.search(r"List<\s*Object\s*\[\]\s*>|\bObject\s*\[\]\s+\w+\s*\(", content)
    if m:
        _add(out, "JPA-OBJECT-ARRAY-RESULT", "LOW", content.count("\n", 0, m.start()) + 1, lines,
             "Consulta que devuelve `Object[]`: el acceso por posición se rompe en silencio al cambiar la consulta; usa una interfaz o `record` de proyección.")


def _frontend(file_path, content, lines, out):
    p = file_path.replace("\\", "/")
    fn = os.path.basename(p).lower()
    if not fn.endswith(".ts") or _is_test_path(p):
        return
    flags = [(i + 1, l) for i, l in enumerate(lines) if re.search(r"\b(requireHttps|strictDiscoveryDocumentValidation)\s*:\s*false\b", l)]
    if flags:
        local_env = bool(re.search(r"environment\.(local|dev|development|test)[\w.]*\.ts$", fn))
        base_dev = fn == "environment.ts" and re.search(r"production\s*:\s*false", content)
        if not (local_env or base_dev):
            for ln, line in flags:
                guard = "\n".join(lines[max(0, ln - 16):ln])
                if not fn.startswith("environment") and re.search(r"useLocalMockAuth|isDevMode\(\)|!\s*environment\.production|environment\.local", guard):
                    continue
                _add(out, "FRONTEND-OIDC-INSECURE-CONFIG", "MEDIUM", ln, lines,
                     "Cliente OIDC con `requireHttps`/`strictDiscoveryDocumentValidation` en `false` fuera del ambiente local: acepta un emisor o "
                     "endpoints por HTTP y un discovery que no corresponde al emisor (intercepción o suplantación del proveedor de identidad).")
                break
    if fn.endswith(".service.ts") and not fn.startswith("environment"):
        for i, line in enumerate(lines):
            if line.strip().startswith(("//", "*")):
                continue
            if re.search(r"[\"'`]https?://(?!www\.w3\.org)[^\"'`\s]+", line):
                _add(out, "FRONTEND-HARDCODED-API-URL", "LOW", i + 1, lines,
                     "URL escrita en el servicio: cambia por ambiente y debe venir de `environment` + `API_ENDPOINTS`.")
                break


def _ci(file_path, content, lines, out):
    p = file_path.replace("\\", "/")
    is_gitlab = os.path.basename(p) == ".gitlab-ci.yml"
    is_gha = bool(re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", p))
    if not (is_gitlab or is_gha) or yaml is None:
        return
    try:
        doc = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return
    if not isinstance(doc, dict):
        return

    def line_of(needle):
        for i, l in enumerate(lines, 1):
            if needle in l:
                return i
        return 1
    if is_gitlab:
        for name, job in doc.items():
            if not isinstance(job, dict) or name.startswith(".") or "script" not in job:
                continue
            if job.get("allow_failure") is True and (_TEST_WORDS.search(str(name)) or _TEST_WORDS.search(str(job.get("stage", "")))):
                _add(out, "CICD-GATE-ALLOW-FAILURE", "MEDIUM", line_of("allow_failure"), lines,
                     f"El job `{name}` (pruebas/lint/seguridad) tiene `allow_failure: true`: un fallo real no rompe el pipeline y el gate queda decorativo.")
    else:
        for jname, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if job.get("continue-on-error") is True and _TEST_WORDS.search(str(jname)):
                _add(out, "CICD-GATE-ALLOW-FAILURE", "MEDIUM", line_of("continue-on-error"), lines,
                     f"El job `{jname}` tiene `continue-on-error: true`: un fallo real no rompe el workflow y el gate queda decorativo.")
            for st in job.get("steps") or []:
                if isinstance(st, dict) and st.get("continue-on-error") is True and _TEST_WORDS.search(f"{st.get('name', '')} {st.get('run', '')}"):
                    _add(out, "CICD-GATE-ALLOW-FAILURE", "MEDIUM", line_of("continue-on-error"), lines,
                         f"El paso `{st.get('name') or st.get('run', '')[:40]}` de pruebas/lint/seguridad tiene `continue-on-error: true`: el gate queda decorativo.")


def _skipped(file_path, content, lines, out):
    if not _is_test_path(file_path) or _vendored(file_path):
        return
    fn = os.path.basename(file_path)
    if fn.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")):
        for i, l in enumerate(lines, 1):
            if re.search(r"\b(?:it|test|describe)\.skip\s*\(|\bx(?:it|describe)\s*\(", l) and not re.search(r"(//|/\*).*\S", l.split("skip", 1)[-1] if "skip" in l else ""):
                _add(out, "TEST-SKIPPED-WITHOUT-REASON", "LOW", i, lines, "Prueba desactivada (`skip`/`xit`/`xdescribe`) sin motivo escrito: una prueba omitida «desaparece» el problema.")
            elif re.search(r"\b(?:it|test|describe)\.only\s*\(|\bf(?:it|describe)\s*\(", l):
                _add(out, "TEST-SKIPPED-WITHOUT-REASON", "MEDIUM", i, lines, "Prueba enfocada (`only`/`fit`/`fdescribe`): el resto de la suite deja de ejecutarse sin que nadie lo note.")
    elif fn.endswith(".java"):
        for i, l in enumerate(lines, 1):
            if re.search(r"@(?:Disabled|Ignore)\s*(?:\(\s*(?:value\s*=\s*)?\"\s*\"\s*\))?\s*$", l.strip()):
                _add(out, "TEST-SKIPPED-WITHOUT-REASON", "LOW", i, lines, "`@Disabled`/`@Ignore` sin motivo: documenta por qué se omite y hasta cuándo.")
    elif fn.endswith(".py"):
        for i, l in enumerate(lines, 1):
            if re.search(r"@pytest\.mark\.skip\s*(?:\(\s*\))?\s*$|@unittest\.skip\(\s*(?:\"\"|'')?\s*\)", l.strip()):
                _add(out, "TEST-SKIPPED-WITHOUT-REASON", "LOW", i, lines, "Prueba omitida sin `reason`: documenta por qué se omite y hasta cuándo.")


def scan_standards_rules(file_path: str, content: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if _vendored(file_path):
        return out
    lines = content.splitlines()
    _swallowed(file_path, content, lines, out)
    _confirm(file_path, lines, out)
    _sql(file_path, content, out)
    _config(file_path, content, lines, out)
    _java(file_path, content, lines, out)
    _frontend(file_path, content, lines, out)
    _ci(file_path, content, lines, out)
    _skipped(file_path, content, lines, out)
    for f in out:
        f["file"] = file_path
    return out
