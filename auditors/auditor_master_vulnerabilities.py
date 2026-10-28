"""
Centinela Native Master Vulnerability Auditor (SAST & DevSecOps / IaC)
Inspects codebases, APIs, Dockerfiles, and configurations for security flaws.
"""
import os
import re
import ast
from typing import List, Dict, Any
from core import db_manager


def _is_inside_string_literal(line: str, pos: int) -> bool:
    """
    Naive single-line string-literal detector: True if `pos` falls inside an open quote span on
    this line. Not a full tokenizer (doesn't handle triple-quoted or multi-line strings), but
    correctly handles the real false-positive case found live 2026-08-13: this scanner's own
    rule-definition tuples describe what they detect in a plain string
    (`"Dynamic Code Execution risk via eval()."`), which naive substring matching flagged as a
    fresh CODE-INJECTION-EVAL finding against the scanner's own source on every self-audit run.
    """
    before = re.sub(r"\\['\"]", "", line[:pos])  # drop escaped quotes so they don't skew parity
    return (before.count("'") % 2 == 1) or (before.count('"') % 2 == 1)


def _is_real_dangerous_call(line: str, match: "re.Match") -> bool:
    """
    Used only for the code-execution-risk family (dynamic-eval / exec / os.system / subprocess
    shell=True) -- NOT for HARDCODED-SECRET or the SQLi patterns, where matching inside a string
    literal is the entire point. Real bug fixed 2026-08-13: this scanner's own detector files
    (which necessarily contain comments and description strings *about* those risky calls, to
    define what they catch) were self-flagging on every scan -- confirmed live, 6/6
    CODE-INJECTION-EVAL findings against this codebase's own auditors/*.py were exactly this,
    not a real dynamic-eval call. (Note: this single-line heuristic doesn't track state across a
    multi-line triple-quoted docstring, so a docstring that spells out the flagged pattern
    literally can still self-match, as this one nearly did -- worded around it rather than
    add cross-line tracking for a single, rare self-referential case.)
    """
    if line.lstrip().startswith("#"):
        return False
    return not _is_inside_string_literal(line, match.start())


def _blank_java_comments(text: str) -> str:
    """Replaces // and /* */ comments with spaces, KEEPING every newline so line numbers stay valid. Commented-out code is not code: proyecto-a's
    AuthController.validarAcceso was entirely inside /* ... */ and was reported twice as an unvalidated upload (12-oct-2026)."""
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    text = re.sub(r"/\*.*?\*/", blank, text, flags=re.DOTALL)
    return re.sub(r"(?<![:\"'])//[^\n]*", blank, text)


_SENSITIVE_WORD_RE = re.compile(r"(token|password|passwd|secret|otp|nonce|salt|session|api_?key|clave|contrase|codigo_?verif|reset)", re.IGNORECASE)
_CTRL_ENTITY_BINDING_RE = re.compile(r"@(RequestBody|ModelAttribute)\s+(?:@\w+(?:\([^)]*\))?\s+)*([A-Z]\w*Entity)\b")
# [A-Z]{4}\d{6} (CURP: 4 letters + date) or [A-Z&Ñ]{3,4}\d{6} (RFC: 3-4 letters + date) as written in a regex literal
_VALIDATION_PATTERN_RE = re.compile(r"\[A-Z[^\]]*\]\{(?P<n>4|3,4)\}\s*(?:\\\\?d|\[0-9\])\{6\}")
_LOCAL_HOST_RE = re.compile(r"ws://(localhost|127\.|0\.0\.0\.0|\[::1\])", re.IGNORECASE)


def scan_coverage_rules(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Rules added 2026-10-01 to close OWASP / WSTG gaps that core/coverage_matrix.py showed were statically detectable
    (mass assignment, weak randomness, CBC without authentication, cleartext WebSocket, postMessage origin checks, session
    fixation, GraphQL introspection, SSTI, XPath/LDAP injection, client-side redirect, sensitive browser storage, and supply-chain
    pinning). Each rule is a conservative source-text pattern with its own false-positive guard."""
    out: List[Dict[str, Any]] = []
    filename = os.path.basename(file_path)
    lines = content.splitlines()

    def add(rule, sev, idx, desc):
        out.append({"cve_id": rule, "severity": sev, "file": file_path, "line": idx,
                    "description": f"{desc} Line {idx}: {lines[idx - 1].strip()[:140] if 0 < idx <= len(lines) else ''}"})

    is_java = filename.endswith(".java")
    is_py = filename.endswith(".py")
    # bundles / minified files / bundled third-party plugins are not the project's own code (measured 2026-10-01: the
    # only POSTMESSAGE hits in the fleet were inside `*.bundle.js` of vendored prismjs/datatables)
    _vendored = bool(re.search(r"(\.min\.|\.bundle\.|/assets/plugins/|/vendor/|/resources/js/|/libs?/|/node_modules/)", file_path.replace("\\", "/"), re.IGNORECASE))
    is_front = filename.endswith((".ts", ".js", ".tsx", ".jsx", ".html", ".vue")) and not _vendored

    # --- API3 Broken Object Property Level Authorization / mass assignment: a controller binds the request body straight
    # to a persistence entity, so a client can set any column (id, role, status...). Controllers only; DTOs are the cure.
    if is_java and re.search(r"@(Rest)?Controller\b", content):
        for idx, line in enumerate(lines, 1):
            m = _CTRL_ENTITY_BINDING_RE.search(line)
            if m:
                add("MASS-ASSIGNMENT-ENTITY-BINDING", "MEDIUM", idx,
                    f"El controlador recibe `{m.group(2)}` directamente del cuerpo de la petición (CWE-915): el cliente puede fijar cualquier campo de la entidad (id, rol, estatus...). Usar un DTO con solo los campos permitidos.")

    # --- weak randomness for secrets (CWE-338)
    if is_java or is_py:
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "#", "*")) or "SecureRandom" in line or "secrets." in line:
                continue
            uses_weak = (re.search(r"\bnew\s+Random\s*\(|Math\.random\s*\(", line) if is_java
                         else re.search(r"\brandom\.(random|randint|choice|choices|randrange|getrandbits)\s*\(", line))
            if uses_weak and _SENSITIVE_WORD_RE.search(line):
                add("INSECURE-RANDOM-FOR-SECRET", "MEDIUM", idx,
                    "Generador pseudoaleatorio predecible para un token/contraseña/código (CWE-338). Usar `SecureRandom` (Java) o el módulo `secrets` (Python).")

    # --- CRYP-02/04: AES in CBC with padding and no authentication, bare "AES" (= ECB), and legacy ciphers/digests
    if is_java:
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "*")):
                continue
            if re.search(r'Cipher\.getInstance\s*\(\s*"AES/CBC/PKCS[57]Padding"', line):
                add("CRYPTO-CBC-NO-AUTHENTICATION", "MEDIUM", idx,
                    "AES/CBC con relleno y sin autenticación del cifrado (riesgo de padding oracle, CWE-649). Preferir `AES/GCM/NoPadding`.")
            if re.search(r'Cipher\.getInstance\s*\(\s*"(AES|DES|DESede|RC4|ARCFOUR|Blowfish|RC2)(/ECB[^"]*)?"\s*\)', line):
                add("WEAK-CRYPTOGRAPHY", "HIGH", idx,
                    "Cifrado débil o modo por defecto inseguro (`AES` sin modo equivale a ECB; DES/3DES/RC4/Blowfish están obsoletos) (CWE-327). Usar AES-GCM.")
            if re.search(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"', line):
                add("WEAK-CRYPTOGRAPHY", "MEDIUM", idx,
                    "Función hash obsoleta (MD5/SHA-1) (CWE-328). Para integridad usar SHA-256+; para contraseñas, bcrypt/Argon2/PBKDF2.")

    # --- CLNT-10 WebSockets / CLNT-11 Web Messaging / CLNT-04 redirect / CLNT-12 storage
    if is_front:
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            if re.search(r"""['"`]ws://""", line) and not _LOCAL_HOST_RE.search(line) and not re.search(r"environment\.|isDevMode", line):
                add("INSECURE-WEBSOCKET", "MEDIUM", idx, "WebSocket sin TLS (`ws://` en lugar de `wss://`): el tráfico y los tokens viajan en claro (WSTG-CLNT-10, CWE-319).")
            if re.search(r"""\.postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)""", line):
                add("POSTMESSAGE-WILDCARD-ORIGIN", "MEDIUM", idx, "`postMessage` con origen destino `*`: cualquier página que embeba esta ventana recibe el mensaje (WSTG-CLNT-11, CWE-345).")
            if re.search(r"""addEventListener\s*\(\s*['"]message['"]""", line):
                window_text = "\n".join(lines[idx - 1: idx + 14])
                if not re.search(r"\.origin\b|event\.source|e\.origin|ev\.origin", window_text):
                    add("POSTMESSAGE-NO-ORIGIN-CHECK", "MEDIUM", idx, "El listener de `message` no valida `event.origin` en sus líneas siguientes: acepta mensajes de cualquier origen (WSTG-CLNT-11, CWE-346).")
            if re.search(r"window\.location(\.href)?\s*=\s*[^;]*(queryParams|searchParams|location\.search|params\.get|\$route\.query)", line):
                add("CLIENT-SIDE-REDIRECT", "MEDIUM", idx, "Redirección del lado del cliente hacia un valor tomado de la URL (WSTG-CLNT-04, CWE-601): validar contra una lista de destinos permitidos.")
            if re.search(r"""(localStorage|sessionStorage)\.setItem\s*\(\s*['"](password|passwd|secret|api_?key|clave|contrasena|contraseña)""", line, re.IGNORECASE):
                add("FRONTEND-SENSITIVE-STORAGE", "HIGH", idx, "Se guarda una contraseña/secreto en el almacenamiento del navegador, legible por cualquier script de la página (WSTG-CLNT-12, CWE-922).")

    # --- Session secrets written to the browser console (found by a manual run with a browser extension on 2026-10-15: a STOMP client was
    # configured with `debug: (str) => console.log(...)`; STOMP frames include the CONNECT headers, i.e. the bearer token, and anyone with
    # access to the machine or a malicious extension can copy it). Two conservative rules, tests excluded.
    if is_front and not re.search(r"\.(spec|test)\.[jt]sx?$", filename):
        file_has_credentials = bool(re.search(r"(connectHeaders|Authorization|Bearer\s|accessToken|access_token|\.token\b)", content))
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            if re.search(r"\bdebug\s*:\s*(\(?\s*\w*\s*\)?\s*=>|function\s*\()[^\n]*console\.(log|debug|info)", line) or \
               re.search(r"\.debug\s*=\s*(\(?\s*\w*\s*\)?\s*=>|function\s*\()[^\n]*console\.(log|debug|info)", line):
                add("FRONTEND-STOMP-DEBUG-LOGGING", "HIGH" if file_has_credentials else "MEDIUM", idx,
                    "El cliente de mensajería (STOMP/WebSocket) escribe sus mensajes de depuración en la consola del navegador; esas tramas incluyen las cabeceras de conexión, es decir, el token de sesión "
                    "(CWE-532). Quitar la función `debug` (o dejarla vacía) y no registrar tramas en QA ni producción.")
            m = re.search(r"console\.(log|debug|info|warn|error|trace)\s*\((.*)", line)
            if m:
                args = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", "", m.group(2))                 # drop quoted literals
                args = re.sub(r"`((?:[^`\\]|\\.)*)`", lambda mm: " ".join(re.findall(r"\$\{([^}]*)\}", mm.group(1))), args)   # template: keep only ${...}
                tok = re.search(r"\b(\w*[Tt]oken|\w*[Jj]wt|authorization|bearer|\w*[Pp]assword|passwd|\w*[Ss]ecret|apiKey)\b", args)
                if tok and not re.search(r"(Count|Length|Size|Type|Duration|Time|Expir\w*|Valid\w*|Present|Exists?)$", tok.group(1)) \
                        and not re.match(r"(time|interval|ttl|expir|max|min|has|is)[A-Z_]", tok.group(1)):
                    add("FRONTEND-TOKEN-IN-CONSOLE", "MEDIUM", idx,
                        f"Se escribe `{tok.group(1)}` (un token, contraseña o secreto) en la consola del navegador (CWE-532): cualquiera con acceso al equipo o una extensión maliciosa puede copiarlo y reutilizar la sesión. "
                        "Quitar el registro, o registrar solo un indicador (p. ej. «token presente: sí/no»).")

    # --- SESS-03 session fixation protection switched off (Spring Security)
    if is_java:
        for idx, line in enumerate(lines, 1):
            if re.search(r"sessionFixation\s*\(\s*\)\s*\.\s*none\s*\(|sessionFixation\s*\(\s*\w*\s*->\s*\w+\.none\s*\(", line):
                add("SESSION-FIXATION-DISABLED", "MEDIUM", idx, "La protección contra fijación de sesión está desactivada (`sessionFixation().none()`): un atacante puede imponer un id de sesión conocido (WSTG-SESS-03, CWE-384).")

    # --- APIT-01 GraphQL introspection / GraphiQL exposed through configuration
    if filename.endswith((".properties", ".yml", ".yaml", ".js", ".ts", ".json")):
        for idx, line in enumerate(lines, 1):
            if re.search(r"(graphiql\.enabled|graphql\.introspection(\.enabled)?|introspection)\s*[:=]\s*true\b", line, re.IGNORECASE) \
                    and not line.lstrip().startswith(("#", "//")):
                add("GRAPHQL-INTROSPECTION-ENABLED", "LOW", idx, "GraphQL con introspección/GraphiQL habilitados: revelan todo el esquema a quien pueda consultar el endpoint (WSTG-APIT-01). Desactivar fuera de desarrollo.")

    # --- INPV-18 SSTI (Flask/Jinja `render_template_string` with a non-literal template)
    if is_py:
        for idx, line in enumerate(lines, 1):
            m = re.search(r"render_template_string\s*\(\s*(.)", line)
            if m and m.group(1) not in ("'", '"') and not line.lstrip().startswith("#"):
                add("SSTI-TEMPLATE-FROM-INPUT", "HIGH", idx, "`render_template_string` recibe una plantilla construida en tiempo de ejecución: si incluye entrada del usuario permite ejecución de código (WSTG-INPV-18, CWE-1336).")
            if re.search(r"""render_template_string\s*\(\s*f['"]""", line):
                add("SSTI-TEMPLATE-FROM-INPUT", "HIGH", idx, "`render_template_string` con f-string: la entrada interpolada se evalúa como plantilla (WSTG-INPV-18, CWE-1336).")

    # --- INPV-09 XPath / INPV-06 LDAP injection by string concatenation
    if is_java or is_py:
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "#", "*")):
                continue
            if re.search(r"""(xpath|XPath)[\w.]*\.(evaluate|compile)\s*\(\s*((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\+|f"(?:[^"\\]|\\.)*\{|f'(?:[^'\\]|\\.)*\{)|\.xpath\s*\(\s*f['"][^'"]*\{""", line):
                add("XPATH-INJECTION-CONCAT", "MEDIUM", idx, "Consulta XPath construida por concatenación con datos variables (WSTG-INPV-09, CWE-643). Usar variables XPath/parámetros.")
            if re.search(r"""['"]\(\s*(uid|cn|sAMAccountName|samaccountname|mail|userPrincipalName)\s*=\s*['"]\s*\+|f['"]\(\s*(uid|cn|sAMAccountName|mail)\s*=\s*\{""", line):
                add("LDAP-INJECTION-CONCAT", "HIGH", idx, "Filtro LDAP construido por concatenación con datos variables (WSTG-INPV-06, CWE-90). Escapar con `LdapEncoder.filterEncode` o usar filtros parametrizados.")

    # --- Supply chain pinning (A08/A06): lockfile missing, floating versions
    if filename == "package.json" and "node_modules" not in file_path:
        dirn = os.path.dirname(file_path)
        has_deps = re.search(r'"(dependencies|devDependencies)"\s*:\s*\{\s*"', content)
        if has_deps and dirn and not any(os.path.exists(os.path.join(dirn, lf)) for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb")):
            add("SUPPLY-CHAIN-NO-LOCKFILE", "MEDIUM", 1, "`package.json` sin archivo de bloqueo (package-lock.json/yarn.lock/pnpm-lock.yaml): las instalaciones no son reproducibles y una versión comprometida entra sin aviso.")
        for idx, line in enumerate(lines, 1):
            if re.search(r'"[@\w./-]+"\s*:\s*"(latest|\*|x)"', line):
                add("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", "MEDIUM", idx, "Dependencia con versión flotante (`latest`/`*`): cada instalación puede traer código distinto.")
    if filename == "pom.xml":
        for idx, line in enumerate(lines, 1):
            if re.search(r"<version>\s*(LATEST|RELEASE|[\[(][^<]*,[^<]*[\])])\s*</version>", line):
                add("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", "MEDIUM", idx, "Versión de dependencia Maven por rango o `LATEST/RELEASE`: la compilación no es reproducible.")
            elif re.search(r"<version>[^<$]*-SNAPSHOT</version>", line) and idx > 1 and re.search(r"<artifactId>", "\n".join(lines[max(0, idx - 4): idx])) \
                    and "<parent>" not in "\n".join(lines[max(0, idx - 6): idx]) and "<dependency>" in "\n".join(lines[max(0, idx - 6): idx]):
                add("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", "LOW", idx, "Dependencia `-SNAPSHOT` en el proyecto: el artefacto cambia sin cambiar la versión.")
    if filename.startswith("requirements") and filename.endswith(".txt"):
        for idx, line in enumerate(lines, 1):
            t = line.strip()
            if not t or t.startswith(("#", "-", "http", "git+", ".")):
                continue
            if re.match(r"^[A-Za-z0-9_.\[\]-]+\s*(([<>~!]=|>|<)[^;#]*)?(\s*;.*)?(\s*#.*)?$", t) and "==" not in t:
                add("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", "LOW", idx, "Dependencia Python sin versión exacta (`==`): la instalación no es reproducible.")

    # --- ADR-0012 D10 / methodology 0B-4: institutional validations (RFC, CURP) are defined ONCE (a reusable validator of the Starter)
    # and cited, not re-written per project. A hand-written RFC/CURP pattern is a conformance gap (and a source of divergent rules),
    # not a security vulnerability: INFORMATIONAL. Tests and vendored paths are skipped. If the file IS the catalogue's validator, ignore it.
    if not _vendored and not re.search(r"(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.[jt]sx?$|Test\.java$|test_\w+\.py$", file_path.replace("\\", "/")) \
            and filename.endswith((".java", ".ts", ".tsx", ".js", ".jsx", ".py", ".kt", ".cs", ".php")):
        for idx, line in enumerate(lines, 1):
            m = _VALIDATION_PATTERN_RE.search(line)
            if m:
                kind = "CURP" if m.group("n") == "4" else "RFC"
                add("VALIDATION-REIMPLEMENTED", "LOW", idx, f"Patrón de validación de {kind} escrito a mano en el proyecto. El catálogo institucional de "
                    "validaciones (0B-4) define cada validación una sola vez como validador reutilizable de la base de arranque; "
                    "úsalo en lugar de reescribirlo. Si este archivo es el propio validador del catálogo, ignora este aviso.")
    return out


def scan_sast_code(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Performs AST & Pattern SAST analysis on source code files."""
    findings = []
    lines = content.splitlines()
    filename = os.path.basename(file_path)

    # 1. SQL Injection Detection
    sqli_patterns = [
        (r'execute\s*\(\s*f["\'].*?SELECT.*?\{', "SQL-INJECTION-FSTRING", "HIGH", "SQL Injection via interpolated f-string in query."),
        # Real bug fixed here: the previous `.*?` segments could cross the query string's OWN
        # closing quote into either (a) a LATER, unrelated string literal on the same line, or
        # (b) an inner, different-type quote char nested inside a single SQL string containing
        # a literal '%wildcard%' -- e.g. the safe, correctly-parameterized
        # `cur.execute("... LIKE %s", (f"%{name}%",))` and the fully-static
        # `cur.execute("... LIKE '%None%'")` were both flagged, the regex mistaking a SQL LIKE
        # wildcard for a Python `%` format operator. Confirmed live: 3 genuinely safe queries
        # (2 in centinela.py, 1 in scratch/db_count.py) flagged this way. Fixed with a
        # backreference (`\1`) so the "content" segments can only contain characters that are
        # NOT the SAME quote character that opened the string -- this correctly finds the
        # string's real terminator (crossing over inner different-type quotes, never crossing
        # the matching one) regardless of whether a comma/second argument follows. Real unsafe
        # `"...%s" % value` calls (no parameter tuple at all) are still caught.
        (r'execute\s*\(\s*(["\'])(?:(?!\1).)*?SELECT(?:(?!\1).)*?\1\s*%\s*[^(]', "SQL-INJECTION-PERCENT", "HIGH", "SQL Injection via string percent formatting without parameter tuple."),
        (r'execute\s*\(\s*["\'].*?\+.*?\+', "SQL-INJECTION-CONCAT", "CRITICAL", "SQL Injection via string concatenation.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in sqli_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 2. Command Injection Detection
    cmd_patterns = [
        (r'subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True', "CMD-INJECTION-SHELL-TRUE", "CRITICAL", "Command Injection risk: subprocess executed with shell=True."),
        (r'os\.system\s*\(', "CMD-INJECTION-OS-SYSTEM", "HIGH", "Insecure os.system call. Use subprocess with explicit argument list."),
        # \b is required: without it this matched "eval(" as a substring inside any longer
        # identifier ending in those letters (e.g. onErrorEval(err), retrieval(x)) -- confirmed
        # against real production data where 136 of 140 logged CODE-INJECTION-EVAL findings were
        # exactly this false positive, not an actual eval() call.
        (r'\beval\s*\(', "CODE-INJECTION-EVAL", "CRITICAL", "Dynamic Code Execution risk via eval().")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in cmd_patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m and _is_real_dangerous_call(line, m):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 3. SSRF (Server-Side Request Forgery)
    # Real false positive fixed 2026-08-13: the old pattern flagged ANY f-string URL starting
    # with http(s)://, regardless of whether the interpolated {variable} controls the actual
    # destination HOST (real SSRF risk) or is merely a path/query segment on an otherwise
    # hardcoded, fixed host (not SSRF at all -- e.g. main.py's own
    # `requests.get(f"http://ip-api.com/json/{ip}?...")`, where the request always goes to
    # ip-api.com no matter what `ip` contains). `[^/"\']*\{` requires the first `{` interpolation
    # to appear before the first `/` after the scheme -- i.e. inside the host/authority part of
    # the URL, which is the actual condition for SSRF (attacker-influenced destination).
    ssrf_patterns = [
        (r'requests\.(get|post|put|delete)\s*\(\s*f["\']https?://[^/"\']*\{', "SSRF-UNCHECKED-FETCH", "MEDIUM", "Potential SSRF: the request's destination HOST is dynamically interpolated without private/internal IP validation.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in ssrf_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 4. Hardcoded Secrets & JWT Tokens
    secret_patterns = [
        (r'(jwt_secret|api_key|password|private_key)\s*=\s*["\'][A-Za-z0-9+/=_-]{8,}["\']', "HARDCODED-SECRET", "HIGH", "Hardcoded credential or secret key detected in source code."),
        (r'(ghp_[A-Za-z0-9_]{36}|glpat-[A-Za-z0-9_]{20}|hvs\.[A-Za-z0-9_-]{24}|"type":\s*"service_account")', "EXPANDED-CLOUD-SECRET", "CRITICAL", "Hardcoded cloud token, PAT, or service account credential detected.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 5. Advanced Backend DB, Security & Performance (SpringBoot, Python, Deserialization, XXE, CSRF)
    backend_db_patterns = [
        (r'\.(raw|extra)\s*\(\s*f?["\'].*?\{', "ORM-RAW-QUERY-INJECTION", "HIGH", "Risk of ORM SQL Injection via raw/extra query interpolation."),
        (r'sequelize\.query\s*\(\s*f?["\'].*?\+', "ORM-RAW-QUERY-INJECTION", "HIGH", "Risk of ORM SQL Injection in Node.js Sequelize."),
        (r'(postgres|mysql)://[^\s"\']+@[^\s"\']+', "DB-UNENCRYPTED-CONN-STRING", "MEDIUM", "Database Connection string detected in code without explicit TLS/SSL parameters."),
        (r'@Query\s*\([^)]*nativeQuery\s*=\s*true', "SPRINGBOOT-NATIVE-QUERY-RISK", "MEDIUM", "SpringBoot native SQL query bypasses JPA parameter escaping safety."),
        # Deserialization, Path Traversal, Weak Crypto, CSRF Disabled & XXE (CWE-502, CWE-22, CWE-327, CWE-352, CWE-611)
        (r'\b(pickle\.loads|pickle\.load|marshal\.loads)\s*\(|yaml\.load\s*\([^)]*?(?<!SafeLoader)\)', "INSECURE-DESERIALIZATION", "CRITICAL", "Insecure deserialization risk (CWE-502). Use SafeLoader for YAML or safer serialization formats."),
        (r'open\s*\(\s*(f["\'].*?\{|.*?\+)', "PATH-TRAVERSAL-RISK", "HIGH", "Potential Path Traversal risk when opening file paths constructed dynamically (CWE-22)."),
        (r'hashlib\.(md5|sha1)\s*\(|Cipher\.getInstance\s*\(\s*["\']AES/ECB', "WEAK-CRYPTOGRAPHY", "HIGH", "Use of weak cryptographic algorithm or ECB mode (CWE-327). Use SHA-256/SHA-512 or AES/GCM."),
        (r'\.csrf\s*\(\s*\)\s*\.disable\s*\(|csrf\s*->\s*csrf\.disable\s*\(', "SPRINGBOOT-CSRF-DISABLED", "HIGH", "CSRF protection explicitly disabled in Spring Security configuration (CWE-352)."),
        (r'DocumentBuilderFactory\.newInstance\s*\(\s*\)|xml\.etree\.ElementTree', "XXE-INSECURE-PARSER", "MEDIUM", "XML parser initialization without explicit XXE / DTD protection (CWE-611)."),
        # Module Audit Extracted Findings
        (r'(LocalAuth|TestSandbox|Backdoor)Controller', "BACKDOOR-SANDBOX-CONTROLLER", "CRITICAL", "Backdoor or sandbox/test controller detected in production code (CWE-288 / CWE-798)."),
        (r'TrustAllManager|NullHostnameVerifier|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy|TrustSelfSignedStrategy', "JVM-GLOBAL-SSL-BYPASS", "CRITICAL", "Disabling SSL/TLS certificate or hostname verification JVM-wide (CWE-295)."),
        (r'@RequestParam.*?(jwt|token)|request\.getParameter\s*\(\s*["\']token["\']', "JWT-IN-URL-PARAM", "HIGH", "Passing JWT token in URL query parameter instead of Authorization header."),
        (r'JdkSerializationRedisSerializer', "REDIS-JDK-SERIALIZATION", "HIGH", "Insecure Java JDK serialization used in Redis cache config (CWE-502)."),
        (r'Files\.readAllBytes|byte\[\]\s+\w+\s*=\s*.*?readAllBytes', "OOM-BYTE-ARRAY-STREAMING", "MEDIUM", "Loading entire file into byte[] array risks Heap Out-Of-Memory. Use InputStream/StreamingResponseBody.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in backend_db_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # Multi-line ORM N+1 Query Scan on full content
    if re.search(r'for\s+\w+\s+in\s+.*?\.(all|filter)\(\):?\s*\n\s*.*?\.\w+', content, re.IGNORECASE):
        findings.append({
            "cve_id": "ORM-N-PLUS-ONE-QUERY",
            "severity": "MEDIUM",
            "file": file_path,
            "line": 1,
            "description": "Potential N+1 Query antipattern inside loop detected in file. Use select_related/prefetch_related or join fetch."
        })

    # 5b. 2026-10-01 -- points raised in un colaborador's comparative audit of proyecto-g (un colaborador's pentest
    # vs un colaborador's analyses vs Centinela) that no engine covered. Each rule documents its own
    # false-positive guards; none ever writes the secret VALUE into a finding (it would end up in
    # the DB, PDFs and chat).
    is_cfg = filename.endswith((".properties", ".yml", ".yaml")) and (
        filename.startswith(("application", "bootstrap")))
    if is_cfg:
        _benign_key_tail = re.compile(
            r'(file|path|url|uri|header|expir\w*|ttl|type|name|prefix|enabled|endpoint|param|claim|'
            r'validity|minutes|seconds|ms|length|min|max|pattern|regex|policy|history|required|duration|timeout|interval|lifetime|rotation|days|hours)$', re.IGNORECASE)
        _placeholder = re.compile(r'(true|false|\d+|<.*>|\*+|changeme|change-me|xxx+|your[-_ ].*|none|null|secret|password)$', re.IGNORECASE)
        _dev_profile = bool(re.search(r'-(local|dev|test|example|sample|h2)\.', filename, re.IGNORECASE))
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(("#", "!")):
                continue
            m = re.match(r'\s*([\w.\-]*?(?:secret|password|passwd|pwd|contrase[nñ]a|clave|token|api[-_.]?key|private[-_.]?key|credential)[\w.\-]*)\s*[=:]\s*(.*?)\s*$',
                         line, re.IGNORECASE)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip().strip('"\'')
            if re.search(r'devtools\.remote\.secret', key, re.IGNORECASE):
                continue   # la regla específica SPRING-DEVTOOLS-REMOTE-ENABLED (abajo) es la dueña de esta línea
            if not val or val.startswith(("${", "#{", "{cipher}", "ENC(")) or _placeholder.fullmatch(val) \
                    or _benign_key_tail.search(key):
                continue
            is_jwt = bool(re.search(r'jwt|signing|signature|private[-_.]?key', key, re.IGNORECASE)) and len(val) >= 16
            findings.append({
                "cve_id": "CONFIG-JWT-SECRET-LITERAL" if is_jwt else "CONFIG-SECRET-LITERAL",
                "severity": "MEDIUM" if _dev_profile else ("CRITICAL" if is_jwt else "HIGH"),
                "file": file_path, "line": idx,
                "description": (f"La propiedad `{key}` de `{filename}` tiene un valor literal de {len(val)} caracteres "
                                f"(oculto a propósito) versionado en el repositorio, en lugar de leerse de una variable de "
                                f"entorno / Vault (`${{{key.upper().replace('.', '_').replace('-', '_')}}}`). "
                                f"{'Con el secreto de firma JWT cualquiera con acceso al repo puede forjar tokens válidos. ' if is_jwt else ''}"
                                f"Quien clone el repo o lea su historial obtiene la credencial; rotarla y moverla fuera del código "
                                f"(CWE-798, ASVS V2.10.4)."
                                f"{' Perfil de desarrollo/prueba: severidad reducida, verificar que no se use en producción.' if _dev_profile else ''}"),
            })

        # --- Familia «configuración peligrosa de Spring» (2026-10-19) -----------------------------------------------
        # Añadida tras el reporte de un colaborador sobre CVE-2026-40972 (Spring Boot DevTools: el secreto remoto se compara en
        # tiempo NO constante -> ataque de temporización -> subir clases al endpoint remoto -> RCE). El SCA por versión
        # (OSV) ya detecta la dependencia vulnerable; estas reglas cubren el hueco de CONFIGURACIÓN: la condición que
        # realmente habilita la superficie de ataque. Detección estática sobre application*/bootstrap*.{properties,yml}.
        # Límite declarado: la forma anidada de YAML (clave en su propia línea sin el prefijo con puntos) no siempre se
        # detecta; la forma con puntos (la usada en estos repos) sí. Nunca se escribe el valor del secreto.
        _sensitive_actuator = ("env", "beans", "heapdump", "threaddump", "shutdown", "configprops", "loggers",
                               "mappings", "httptrace", "auditevents", "sessions", "jolokia")
        for idx, line in enumerate(lines, 1):
            st = line.strip()
            if st.startswith(("#", "!")):
                continue
            low = st.lower()
            # 1. DevTools remoto habilitado (CVE-2026-40972). El secreto presente, o remote.enabled=true, habilitan el
            #    canal remoto vulnerable al ataque de temporización. HIGH siempre: no debe existir en un repo/despliegue
            #    alcanzable, ni siquiera en dev (el secreto quedaría versionado y el canal expuesto).
            if re.search(r'devtools\.remote\.secret\s*[=:]\s*\S', low) or re.search(r'devtools\.remote\.enabled\s*[=:]\s*true', low):
                findings.append({
                    "cve_id": "SPRING-DEVTOOLS-REMOTE-ENABLED", "severity": "HIGH", "file": file_path, "line": idx,
                    "description": ("Spring Boot DevTools remoto habilitado (`spring.devtools.remote.*`). La comparación del "
                                    "secreto remoto no es de tiempo constante (CVE-2026-40972, CWE-208): un atacante en red "
                                    "adyacente puede adivinar el secreto midiendo tiempos y luego subir clases al endpoint "
                                    "remoto, logrando ejecución de código. DevTools remoto es solo para desarrollo: quitar "
                                    "`spring.devtools.remote.secret` y poner `spring.devtools.remote.enabled=false`, y excluir "
                                    "spring-boot-devtools del artefacto de producción. (El valor del secreto no se muestra.)"),
                })
                continue
            # 2. Consola H2 habilitada: expone una consola SQL web (lectura/escritura de BD, vector de RCE conocido).
            if re.search(r'h2\.console\.enabled\s*[=:]\s*true', low):
                findings.append({
                    "cve_id": "SPRING-H2-CONSOLE-ENABLED", "severity": "MEDIUM" if _dev_profile else "HIGH",
                    "file": file_path, "line": idx,
                    "description": ("Consola web de H2 habilitada (`spring.h2.console.enabled=true`): expone una consola SQL "
                                    "que permite leer/escribir la base de datos y es un vector de RCE conocido si es "
                                    "alcanzable. Deshabilitarla en cualquier entorno accesible (CWE-16/A05)."
                                    f"{' Perfil de desarrollo/prueba: severidad reducida.' if _dev_profile else ''}"),
                })
                continue
            # 3. Exposición de endpoints sensibles de Actuator (`*` o endpoints que filtran config/credenciales o permiten
            #    apagar la app). Complementa la detección perimetral (/actuator/env) con la raíz en configuración.
            ma = re.search(r'exposure\.include\s*[=:]\s*(.+)$', st, re.IGNORECASE)
            if ma:
                val = ma.group(1).strip().strip('"\'[]')
                items = [x.strip().lower() for x in re.split(r'[,\s]+', val) if x.strip()]
                hit = "*" in items or any(s in items for s in _sensitive_actuator)
                if hit:
                    which = "*" if "*" in items else ", ".join(s for s in items if s in _sensitive_actuator)
                    findings.append({
                        "cve_id": "SPRING-ACTUATOR-SENSITIVE-EXPOSED", "severity": "MEDIUM" if _dev_profile else "HIGH",
                        "file": file_path, "line": idx,
                        "description": (f"Actuator expone endpoints sensibles por web (`management.endpoints.web.exposure.include` "
                                        f"incluye `{which}`). Endpoints como env/configprops/heapdump/threaddump/beans filtran "
                                        f"configuración y credenciales, y `shutdown` permite apagar la app. Exponer solo `health` "
                                        f"(e `info`) y proteger el resto (CWE-200/A05)."
                                        f"{' Perfil de desarrollo/prueba: severidad reducida.' if _dev_profile else ''}"),
                    })

    if filename.endswith(".java"):
        # CWE-208: `token.equals(x)` short-circuits on the first differing byte -> timing oracle.
        # Guard: identifier must END in the sensitive word (tokenType/tokenName are not secrets) and
        # constant-time helpers on the same line are accepted.
        _cmp = re.compile(r'\b\w*(?:token|secret|apikey|api_key|signature|hmac)\s*\.equals(?:IgnoreCase)?\s*\(|'
                          r'\.equals(?:IgnoreCase)?\s*\(\s*\w*(?:token|secret|apikey|api_key|signature|hmac)\s*\)', re.IGNORECASE)
        for idx, line in enumerate(lines, 1):
            st = line.strip()
            if st.startswith(("//", "*", "/*")) or "isEqual(" in line or "constantTime" in line:
                continue
            if _cmp.search(line):
                findings.append({
                    "cve_id": "TIMING-UNSAFE-SECRET-COMPARISON", "severity": "MEDIUM", "file": file_path, "line": idx,
                    "description": ("Comparación de un token/secreto/firma con `String.equals`, que termina en el primer byte "
                                    "distinto y permite adivinarlo midiendo tiempos de respuesta (CWE-208). Usar "
                                    f"`MessageDigest.isEqual(a.getBytes(UTF_8), b.getBytes(UTF_8))`. Line {idx}: {st[:120]}"),
                })

        # Password policy: a create/change/reset DTO with a password field and no @Size/@Pattern.
        if re.search(r'(Crear|Create|Registr|Register|Alta|Cambi|Change|Reset|Actualiz|Update|Nuevo|New)\w*(Request|Dto|DTO)', filename):
            for idx, line in enumerate(lines, 1):
                if re.match(r'\s*private\s+String\s+(password|contrasena|contrasenia|clave|passwd|newPassword|nuevaContrasena)\w*\s*;', line, re.IGNORECASE):
                    ctx = "\n".join(lines[max(0, idx - 6):idx - 1])
                    if not re.search(r'@(Size|Pattern|Length|ValidPassword|StrongPassword|Password)\b', ctx):
                        findings.append({
                            "cve_id": "PASSWORD-POLICY-NOT-ENFORCED", "severity": "MEDIUM", "file": file_path, "line": idx,
                            "description": (f"`{filename}` recibe una contraseña sin `@Size`/`@Pattern` (longitud mínima / "
                                            f"complejidad) en el DTO. Si la política solo vive en el cliente se evita llamando "
                                            f"a la API directamente (ASVS V2.1.1, CWE-521). Line {idx}: {line.strip()}"),
                        })

    if filename.endswith((".ts", ".js", ".tsx", ".jsx")):
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            if re.search(r'[?&](access_?token|token|jwt|id_token)=\s*(\$\{|[\'"]\s*\+|\'\s*\+)', line, re.IGNORECASE):
                findings.append({
                    "cve_id": "FRONTEND-TOKEN-IN-URL", "severity": "MEDIUM", "file": file_path, "line": idx,
                    "description": ("El front-end arma una URL con el token de sesión en el query string (típico de `EventSource`/"
                                    "`window.open`/descargas). La URL queda en logs de nginx, historial del navegador y cabecera "
                                    "Referer (CWE-598). Preferir `fetch` con cabecera `Authorization`, o un ticket de un solo uso "
                                    f"y vida corta. Line {idx}: {line.strip()[:120]}"),
                })
        if re.search(r'(routes?|routing)[\w.\-]*\.ts$', filename, re.IGNORECASE):
            for idx, line in enumerate(lines, 1):
                if re.search(r'\bpath\s*:\s*[\'"][^\'"]*(?<![a-z])(test|prueba|ejemplo|demo|sandbox|debug)[^\'"]*[\'"]', line, re.IGNORECASE):
                    findings.append({
                        "cve_id": "FRONTEND-TEST-ROUTE-EXPOSED", "severity": "MEDIUM", "file": file_path, "line": idx,
                        "description": ("Ruta de prueba/ejemplo/depuración registrada en el router de producción: se empaqueta en el "
                                        "bundle y es accesible por URL aunque no haya enlace. Condicionarla al `environment` o quitarla. "
                                        f"Line {idx}: {line.strip()[:120]}"),
                    })

    # 6. Advanced Frontend Security (React, Angular, SpringBoot & DOM XSS)
    if filename.endswith((".js", ".ts", ".jsx", ".tsx", ".html", ".java")):
        frontend_patterns = [
            (r'(VITE_|NEXT_PUBLIC_|REACT_APP_)(DB_|DATABASE_|POSTGRES_|MYSQL_)', "FRONTEND-EXPOSED-DB-CREDENTIAL", "CRITICAL", "Exposed Database credential or connection URL in Frontend public environment variable."),
            (r'localStorage\.setItem\s*\(\s*["\'](token|jwt|session|auth_token)["\']', "FRONTEND-JWT-LOCALSTORAGE", "MEDIUM", "Storing authentication token in localStorage makes it vulnerable to XSS extraction. Use httpOnly cookies."),
            # React & Angular Specific Security Antipatterns
            (r'dangerouslySetInnerHTML', "REACT-DANGEROUSLY-SET-INNER-HTML", "HIGH", "React dangerouslySetInnerHTML antipattern detected (DOM XSS risk)."),
            # `[innerHTML]="x"` is NOT a sanitization bypass: Angular sanitizes it by default. The bypass is bypassSecurityTrustHtml() (next pattern), which is what
            # this rule reports. (Until 2026-10-13 every [innerHTML] binding was reported as HIGH with a description that was false.)
            (r'bypassSecurityTrust(Html|Script|ResourceUrl|Style)', "ANGULAR-BYPASS-SECURITY-TRUST", "HIGH", "Angular explicit security sanitization bypass (DomSanitizer)."),
            (r'<button(?![^>]*aria-label)[^>]*>(?!\s*<span[^>]*>[^<]+</span>|\s*[^<\s]+)', "ACCESSIBILITY-WCAG-MISSING-LABEL", "LOW", "Interactive button missing accessible label or text content (WCAG 2.1 AA).")
        ]
        _fl = lines
        if filename.endswith(".html"):
            # markup inside <!-- --> is not rendered: it cannot be an accessibility (or DOM) finding
            _fl = re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), "\n".join(lines), flags=re.S).split("\n")
        elif filename.endswith((".ts", ".tsx", ".js", ".jsx", ".java")):
            # commented-out code is not code: a `// this._sanitizer.bypassSecurityTrust...` line is not a finding
            _fl = _blank_java_comments("\n".join(lines)).split("\n")
        for idx, line in enumerate(_fl, 1):
            for pattern, rule_id, severity, desc in frontend_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # ACCESSIBILITY-WCAG-MISSING-LABEL: this older regex only looks at the literal text inside <button>,
                    # so PrimeNG's `label="..."`, `[label]`, aria-label(ledby) and title= -- which DO give the button an
                    # accessible name -- were flagged. Measured 2026-10-01: 461 of 1,504 open findings fleet-wide had
                    # one of those attributes on the very same line (false positives). Icon-only buttons with no name
                    # at all are still reported here and, more precisely, by the dedicated WCAG engine.
                    if (rule_id == "ACCESSIBILITY-WCAG-MISSING-LABEL"
                            and re.search(r'\blabel\s*=|\[label\]|aria-label|aria-labelledby|\btitle\s*=|\[attr\.aria-label\]', line, re.IGNORECASE)):
                        continue
                    # A button whose content (until its closing tag) is an image with a non-empty alt, or has visible text on a following line, DOES have an accessible name.
                    if rule_id == "ACCESSIBILITY-WCAG-MISSING-LABEL":
                        _rest = "\n".join(lines[idx - 1:idx + 7])
                        _inner = re.split(r"</button\s*>", re.sub(r"^.*?<button[^>]*>", "", _rest, count=1, flags=re.S), maxsplit=1, flags=re.I)[0]
                        if re.search(r'<img\b[^>]*\balt\s*=\s*"[^"]+"', _inner, re.I) or re.search(r"\[?alt\]?\s*=\s*\"[^\"]+\"", _inner, re.I) \
                                or re.sub(r"<[^>]*>|\{\{.*?\}\}|\s", "", _inner) or re.search(r"\{\{[^}]+\}\}", _inner):
                            continue
                    # bypassSecurityTrust*() applied to a blob: URL the browser itself just minted with
                    # URL.createObjectURL(...) is Angular's documented pattern for showing a local
                    # PDF/image (the value is not attacker-controlled markup). Reporting it HIGH
                    # contradicted our own AI verdicts (SonarQube S6268 "riesgo real nulo") in the
                    # same report; keep it visible as LOW for review instead of HIGH.
                    if (rule_id == "ANGULAR-BYPASS-SECURITY-TRUST" and "bypassSecurityTrust" in line
                            and re.search(r'createObjectURL\s*\(', "\n".join(lines[max(0, idx - 10):idx]))):
                        findings.append({
                            "cve_id": rule_id, "severity": "LOW", "file": file_path, "line": idx,
                            "description": (f"{desc} Se aplica a un `blob:` URL generado localmente con `URL.createObjectURL` "
                                            f"(patrón recomendado por Angular para mostrar archivos locales), por lo que no "
                                            f"hay HTML/URL controlado por un atacante: severidad reducida a LOW, revisar solo "
                                            f"que el blob no provenga de contenido no confiable. Line {idx}: {line.strip()}"),
                        })
                        continue
                    findings.append({
                        "cve_id": rule_id,
                        "severity": severity,
                        "file": file_path,
                        "line": idx,
                        "description": f"{desc} Line {idx}: {line.strip()}"
                    })

    # 5b. Architectural/concurrency/IDOR risk patterns -- added 2026-09-30 in response to a
    # direct cross-check against an external third-party code audit (proyecto-g's own RBAC/race-
    # condition findings) and a third-party WSTG pentest report (Superset deployment): both
    # surfaced real vulnerability classes this engine had zero coverage for. Each pattern below
    # is a deliberately conservative, single-signal heuristic -- false-positive risk is handled
    # per-rule in its own comment, not assumed away.
    arch_risk_patterns = [
        # CORS wildcard: a real, common misconfiguration independently found both in the
        # Superset WSTG report and this project's own earlier auditor_wstg.py scope -- this adds
        # the SOURCE-CODE-visible equivalent (Spring @CrossOrigin / allowedOrigins / an explicit
        # ACAO header), which only applied previously to a live, registered perimeter asset, not
        # to GitLab-Repo source.
        (r'@CrossOrigin\s*\([^)]*origins\s*=\s*["\']\*["\']', "CORS-WILDCARD-ORIGIN", "HIGH",
         "CORS wildcard origin (@CrossOrigin origins=\"*\") allows any site to call this endpoint with credentials, risking CSRF/data exfiltration."),
        (r'\.allowedOrigins\s*\(\s*["\']\*["\']\s*\)', "CORS-WILDCARD-ORIGIN", "HIGH",
         "CORS wildcard origin (allowedOrigins(\"*\")) allows any site to call this endpoint with credentials, risking CSRF/data exfiltration."),
        (r'(setHeader|addHeader)\s*\(\s*["\']Access-Control-Allow-Origin["\']\s*,\s*["\']\*["\']', "CORS-WILDCARD-ORIGIN", "HIGH",
         "CORS wildcard origin set explicitly via Access-Control-Allow-Origin: *."),
        # Stack trace / raw exception message returned to the client -- confirms whether an
        # internal error (DB schema, file paths, library versions) leaks to an attacker, the
        # same class of "verbose error handling" the external WSTG pentest flagged against
        # Superset. printStackTrace() to a response stream, or e.getMessage()/e.toString()
        # placed directly inside a ResponseEntity/response body, both leak internals.
        (r'\.printStackTrace\s*\(\s*(response|out|writer|resp)', "STACK-TRACE-EXPOSURE", "MEDIUM",
         "Exception stack trace written directly to the HTTP response stream, leaking internal implementation details to the client."),
        (r'ResponseEntity[^;{]*?\.(body|status)\([^)]*\b(e|ex|exception)\.(getMessage|toString)\s*\(\s*\)', "STACK-TRACE-EXPOSURE", "MEDIUM",
         "Raw exception message returned directly in the API response body, leaking internal implementation details to the client."),
        # Blocking Thread.sleep() in production code -- directly confirmed as a real finding
        # class in the external proyecto-g module audit (`.rar` files, "antipatrón Thread.sleep()
        # bloqueante"). Scoped to .java only; test/mock-delay usage is already excluded by the
        # outer dispatch's /test/ exclusion.
        (r'Thread\.sleep\s*\(', "BLOCKING-THREAD-SLEEP", "LOW",
         "Thread.sleep() blocks the calling thread (likely an HTTP request-handling thread in a web container) -- under load this exhausts the thread pool. Use an async/scheduled mechanism instead."),
    ]
    if filename.endswith((".java", ".py", ".js", ".ts")):
        for idx, line in enumerate(lines, 1):
            for pattern, rule_id, severity, desc in arch_risk_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "cve_id": rule_id,
                        "severity": severity,
                        "file": file_path,
                        "line": idx,
                        "description": f"{desc} Line {idx}: {line.strip()}"
                    })

    # 5c. JPA @Entity classes missing @Version (optimistic locking) -- multi-line, per-class
    # check. Directly confirms a real finding class from the external proyecto-g audit (CRIT-03:
    # "Pérdida de concurrencia optimista real en JPA (@Version inexistente)", CRIT-01: folio
    # race condition). A @Entity class with no @Version field anywhere in its body has no
    # protection against the classic lost-update race (two concurrent transactions read the same
    # row, both write, one silently overwrites the other with no conflict detection) -- JPA's
    # own documented mechanism for this is the @Version annotation, and its total absence from
    # an entity is a real, verifiable fact about the file, not a guess about runtime behavior.
    # Conservative: only fires on classes that declare at least one mutable field (so a pure
    # read-only/reference-data entity, where lost updates can't occur, doesn't get flagged) and
    # that aren't already abstract/MappedSuperclass base classes.
    if filename.endswith(".java") and "@Entity" in content:
        class_pattern = re.compile(
            r'@Entity\b.*?\bclass\s+(\w+)\b(.*?)(?=\n@Entity\b|\Z)', re.DOTALL
        )
        for m in class_pattern.finditer(content):
            class_name, body = m.group(1), m.group(2)
            if "@Version" in body or "@MappedSuperclass" in m.group(0) or "abstract class" in m.group(0):
                continue
            if not re.search(r'@Column\b|private\s+\w', body):
                continue
            line_no = content[:m.start()].count("\n") + 1
            findings.append({
                "cve_id": "JPA-ENTITY-MISSING-VERSION",
                "severity": "MEDIUM",
                "file": file_path,
                "line": line_no,
                "description": (
                    f"La entidad JPA '{class_name}' no declara un campo @Version. Sin control de "
                    f"concurrencia optimista, dos transacciones concurrentes que lean y escriban "
                    f"la misma fila pueden producir una actualización perdida (lost update) sin "
                    f"ninguna detección de conflicto. Línea {line_no}."
                )
            })

    # 5c2. A TLS check that accepts everything, by SHAPE and not by name: an X509TrustManager whose checkServerTrusted/checkClientTrusted do nothing, or a
    # HostnameVerifier whose verify() just returns true. (Until 2026-10-12 this rule fired on any mention of "X509TrustManager", including the normal
    # `(X509TrustManager) trustManagers[0]` of a correctly configured client -- a false positive on every OkHttp-generated ApiClient.)
    if filename.endswith(".java"):
        _code = _blank_java_comments(content)
        for _m in re.finditer(r'check(?:Server|Client)Trusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}|boolean\s+verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;\s*\}', _code):
            _line = _code[:_m.start()].count("\n") + 1
            findings.append({
                "cve_id": "JVM-GLOBAL-SSL-BYPASS", "severity": "CRITICAL", "file": file_path, "line": _line,
                "description": f"Implementación que acepta cualquier certificado u host sin verificar (CWE-295). Línea {_line}: {lines[_line - 1].strip()}"
            })

    # 5d. File-upload endpoints with no visible validation -- confirms a real finding class from
    # the external proyecto-g audit (BucketController: arbitrary file upload/download). Heuristic: a
    # method accepting a MultipartFile parameter whose body (next ~25 lines) contains none of the
    # usual validation calls (content-type check, extension check, size check, filename
    # sanitization). Deliberately conservative and labeled for manual review rather than a
    # certain finding, since a validation layer could legitimately live in a separate
    # interceptor/filter this single-file heuristic can't see.
    if filename.endswith(".java") and "MultipartFile" in content and not re.search(r'(?:Upload|File|Archivo)\w*Validator\.java$', filename):
        validation_hints = re.compile(
            r'getContentType|getSize\s*\(\s*\)\s*[<>]|getOriginalFilename.*?(replace|sanitiz|normalize)|'
            r'allowedExtensions|ALLOWED_EXTENSIONS|FileTypeDetector|Tika|isValidFile|'
            r'\b(?:upload|archivo|file)\w*[Vv]alidator\.\w+\s*\(', re.IGNORECASE      # an upload/file validator component called with the file
        )
        code_only = _blank_java_comments(content)       # commented-out code is neither flagged nor accepted as validation
        for m in re.finditer(r'MultipartFile\s+(\w+)', code_only):
            window_start = m.end()
            window = code_only[window_start:window_start + 1500]
            if not validation_hints.search(window):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "cve_id": "FILE-UPLOAD-NO-VALIDATION",
                    "severity": "MEDIUM",
                    "file": file_path,
                    "line": line_no,
                    "description": (
                        f"Parámetro MultipartFile '{m.group(1)}' sin validación visible de "
                        f"content-type/extensión/tamaño/nombre en las ~1500 caracteres "
                        f"siguientes. Requiere revisión manual: la validación podría existir en "
                        f"un interceptor/filtro separado que este análisis estático de un solo "
                        f"archivo no puede ver. Línea {line_no}."
                    )
                })

    # 5e. Direct object reference without a visible ownership check (BOLA/IDOR heuristic) --
    # confirms a real finding class from the external proyecto-g audit (BOLA/IDOR in
    # UsuarioMensajeController). Heuristic, intentionally low-confidence and labeled as such:
    # a @PathVariable id used directly in a repository findById()/getOne() call, with no
    # ownership-check keyword (current authenticated user id/username compared against the
    # loaded entity) anywhere in the following ~800 characters. This is a weak signal on
    # purpose -- a real ownership check can be implemented in many ways a single-file text scan
    # cannot reliably recognize -- so it is reported as a review item, not a confirmed
    # vulnerability, to avoid the fake-precision problem this project's own rules prohibit.
    if filename.endswith(".java") and "@PathVariable" in content:
        ownership_hints = re.compile(
            r'getPrincipal|getAuthentication|SecurityContextHolder|@PreAuthorize|getUsuario\(\)\.getId|'
            r'\.equals\(.*?[Uu]sername\)|current[A-Z]\w*\.getId|AccessDenied|AccessPolicy|exigirAcceso|verificarAcceso|tieneAcceso|puedeVer', re.IGNORECASE
        )
        for m in re.finditer(r'@PathVariable[^)]*?\b(\w*[Ii]d)\b[^)]*\)[^{]*\{', content):
            window_start = m.end()
            window = content[window_start:window_start + 800]
            if re.search(r'\.(findById|getOne|getReferenceById)\s*\(\s*' + re.escape(m.group(1)), window) and not ownership_hints.search(window):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "cve_id": "POTENTIAL-IDOR-NO-OWNERSHIP-CHECK",
                    "severity": "MEDIUM",
                    "file": file_path,
                    "line": line_no,
                    "description": (
                        f"Posible IDOR/BOLA: el identificador de ruta '{m.group(1)}' se usa en "
                        f"una búsqueda directa por id sin ninguna palabra clave de verificación "
                        f"de propiedad visible en los ~800 caracteres siguientes (usuario "
                        f"autenticado, @PreAuthorize, comparación de propietario). "
                        f"HALLAZGO DE BAJA CONFIANZA -- requiere revisión manual obligatoria "
                        f"antes de tratarse como vulnerabilidad confirmada; la verificación de "
                        f"propiedad puede existir en una capa de servicio/aspecto que este "
                        f"análisis de un solo archivo no puede ver. Línea {line_no}."
                    )
                })

    # 5f. Authentication endpoints with no visible rate-limiting -- suggested 2026-09-30 after
    # cross-checking against a real third-party WSTG pentest report (no rate-limit finding there,
    # but it's a well-known OWASP ASVS V2.2.1 control this project had zero coverage for).
    # Heuristic, intentionally low-confidence: a controller method mapped to a login/auth path
    # with no reference to a known rate-limiting mechanism (Bucket4j, Resilience4j, Spring Cloud
    # Gateway RequestRateLimiter, a custom @RateLimiter/@Throttle annotation, or a Redis INCR-based
    # counter) anywhere in the same file. A real rate limiter commonly lives in a separate
    # filter/interceptor/gateway config this single-file heuristic cannot see, so this is reported
    # as a review item, not a confirmed vulnerability.
    if filename.endswith(".java") and re.search(r'@(Post|Request)Mapping\s*\(\s*(value\s*=\s*)?["\'][^"\']*\b(login|signin|sign-in|authenticate)\b', content, re.IGNORECASE):
        rate_limit_hints = re.compile(
            r'Bucket4j|RateLimiter|Resilience4j|RequestRateLimiter|@RateLimiter|@Throttle|'
            r'ratelimit|rate_limit|LoginAttempt|failedAttempts', re.IGNORECASE
        )
        if not rate_limit_hints.search(content):
            m = re.search(r'@(Post|Request)Mapping\s*\([^)]*\b(login|signin|sign-in|authenticate)\b[^)]*\)', content, re.IGNORECASE)
            line_no = content[:m.start()].count("\n") + 1 if m else 1
            findings.append({
                "cve_id": "AUTH-ENDPOINT-NO-RATE-LIMIT",
                "severity": "MEDIUM",
                "file": file_path,
                "line": line_no,
                "description": (
                    "Endpoint de autenticación sin ninguna referencia visible a un mecanismo de "
                    "limitación de intentos (rate limiting / lockout) en este archivo "
                    "(ASVS V2.2.1, OWASP WSTG-ATHN-03). HALLAZGO DE BAJA CONFIANZA -- el control "
                    "podría existir en un filtro/interceptor, API gateway o WAF separado que este "
                    f"análisis de un solo archivo no puede ver; requiere revisión manual. Línea {line_no}."
                )
            })

    # 5g. JPA repository methods with multiple write calls (save/delete/update) and no
    # @Transactional on the method or enclosing class -- suggested 2026-09-30. Without a
    # transaction boundary, a failure between the first and second write leaves the database in a
    # partially-applied state with no rollback (CWE-662-adjacent: missing atomicity). Conservative:
    # requires at least 2 distinct write calls in the same method body to avoid flagging a single
    # trivial save().
    if filename.endswith(".java"):
        method_pattern = re.compile(
            r'\b(public|private|protected)\s+[\w<>\[\],\s]+\s+(\w+)\s*\([^)]*\)\s*\{',
        )
        for m in method_pattern.finditer(content):
            # Look back from the method signature to the end of the previous method/class body
            # (a '}' at column 0 or less-indented) for an @Transactional on THIS method specifically.
            preceding_start = content.rfind("}", 0, m.start())
            preceding = content[preceding_start + 1 if preceding_start != -1 else 0:m.start()]
            if "@Transactional" in preceding:
                continue
            method_name = m.group(2)
            # Find the method body with a simple brace-matching scan.
            body_start = m.end()
            depth = 1
            i = body_start
            while i < len(content) and depth > 0:
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                i += 1
            body = content[body_start:i]
            # only calls on a repository / DAO / EntityManager are database writes; `signature.update(...)` or `digest.update(...)` are not
            write_calls = re.findall(r'\b(?:\w*[Rr]epositor\w*|\w*Repo|\w*Dao|entityManager|em)\.(save|saveAndFlush|delete|deleteById|update)\s*\(', body)
            if len(write_calls) >= 2:
                # Also skip if @Transactional sits on the enclosing class instead of this method.
                if "@Transactional" in content[max(0, m.start() - 2000):m.start()] and re.search(r'\bclass\s+\w+', content[max(0, m.start() - 300):m.start()]):
                    continue
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "cve_id": "JPA-MULTI-WRITE-NO-TRANSACTIONAL",
                    "severity": "MEDIUM",
                    "file": file_path,
                    "line": line_no,
                    "description": (
                        f"El método '{method_name}' realiza {len(write_calls)} escrituras de "
                        f"repositorio ({', '.join(sorted(set(write_calls)))}) sin estar anotado "
                        f"(ni él ni su clase) con @Transactional. Si falla entre la primera y la "
                        f"última escritura, la base de datos queda en un estado parcialmente "
                        f"aplicado sin rollback automático. Línea {line_no}."
                    )
                })

    # 5h. Cookies constructed manually without Secure/HttpOnly -- suggested 2026-09-30 after
    # cross-checking a real third-party WSTG pentest report (its WSTG-CRYP-03/SESS-02 findings
    # were about cookie transport/SameSite on a live perimeter; this is the source-code-visible
    # equivalent for Java/Jakarta Servlet code using `new Cookie(...)` directly, which
    # auditor_wstg.py's perimeter check cannot see on a GitLab-Repo asset with no live endpoint).
    if filename.endswith(".java") and re.search(r'new\s+Cookie\s*\(', content):
        for m in re.finditer(r'new\s+Cookie\s*\(\s*"([^"]+)"', content):
            window = content[m.end():m.end() + 400]
            has_secure = re.search(r'\.setSecure\s*\(\s*true\s*\)', window)
            has_httponly = re.search(r'\.setHttpOnly\s*\(\s*true\s*\)', window)
            if not (has_secure and has_httponly):
                line_no = content[:m.start()].count("\n") + 1
                missing = [n for n, present in (("Secure", has_secure), ("HttpOnly", has_httponly)) if not present]
                findings.append({
                    "cve_id": "INSECURE-COOKIE-FLAGS",
                    "severity": "MEDIUM",
                    "file": file_path,
                    "line": line_no,
                    "description": (
                        f"La cookie '{m.group(1)}' se construye sin establecer explícitamente "
                        f"{' ni '.join(missing)} en las ~400 caracteres siguientes (OWASP "
                        f"WSTG-SESS-02, CWE-614/CWE-1004). Sin Secure, puede transmitirse por "
                        f"HTTP sin cifrar; sin HttpOnly, es accesible a JavaScript y robable vía "
                        f"XSS. Línea {line_no}."
                    )
                })

    # 5. AST Cognitive Complexity Check (Python files)
    if filename.endswith(".py"):
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    complexity = 0
                    for sub in ast.walk(node):
                        if isinstance(sub, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                            complexity += 1
                    if complexity > 15:
                        findings.append({
                            "cve_id": "COGNITIVE-COMPLEXITY-EXCEEDED",
                            "severity": "MEDIUM",
                            "file": file_path,
                            "line": node.lineno,
                            "description": f"Function '{node.name}' has cognitive complexity of {complexity} (max recommended: 15)."
                        })
        except Exception as e:
            print(f"⚠️ [Master-Auditor] Could not parse {file_path} for cognitive complexity: {e}")

    findings.extend(scan_coverage_rules(file_path, content))
    from auditors.auditor_arch_rules import scan_arch_rules   # Spring Boot / Angular architecture & performance rules (DECISIONS/0011)
    findings.extend(scan_arch_rules(file_path, content))
    from auditors.auditor_standards_rules import scan_standards_rules   # standards 5.4 / 5.10 / 5.11 / 6 (ADR-0012)
    findings.extend(scan_standards_rules(file_path, content))
    return findings


def scan_iac_dockerfile(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Dockerfiles against CIS Benchmarks and DevSecOps Hardening rules."""
    findings = []
    lines = content.splitlines()

    has_user_instruction = False
    for idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if clean_line.startswith("USER"):
            has_user_instruction = True
            if "root" in clean_line.lower() or clean_line == "USER 0":
                findings.append({
                    "cve_id": "DOCKER-ROOT-USER",
                    "severity": "HIGH",
                    "file": file_path,
                    "line": idx,
                    "description": "Dockerfile explicitly sets execution user to root."
                })
        if clean_line.startswith("FROM") and ":latest" in clean_line:
            findings.append({
                "cve_id": "DOCKER-UNPINNED-BASE-IMAGE",
                "severity": "LOW",
                "file": file_path,
                "line": idx,
                "description": f"Dockerfile uses unpinned base image ':latest'. Line {idx}: {clean_line}"
            })

    for idx, line in enumerate(lines, 1):
        if re.search(r"^\s*RUN\b.*\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b", line):
            findings.append({"cve_id": "DOCKER-CURL-PIPE-SHELL", "severity": "MEDIUM", "file": file_path, "line": idx,
                             "description": f"El Dockerfile descarga y ejecuta un script remoto sin verificarlo (`curl | sh`) (A08, CWE-494). Line {idx}: {line.strip()[:140]}"})

    if not has_user_instruction:
        findings.append({
            "cve_id": "DOCKER-MISSING-NON-ROOT-USER",
            "severity": "HIGH",
            "file": file_path,
            "line": 1,
            "description": "Dockerfile lacks explicit non-root 'USER appuser' instruction."
        })

    return findings


def run_master_vulnerability_scan(target_dir: str = "/app", asset_id: str = None) -> List[Dict[str, Any]]:
    """Runs SAST and DevSecOps vulnerability scan across target directory."""
    all_findings = []
    
    for root, _, files in os.walk(target_dir):
        # "tests" excluded here too -- several test files in this repo (by design) contain
        # deliberately vulnerable-looking snippets as fixtures to test the detectors
        # themselves (e.g. tests/test_full_coverage_100.py's HARDCODED-SECRET fixture,
        # tests/test_sast_db_patterns.py's SQL injection fixtures) -- these aren't real
        # production vulnerabilities and previously polluted compliance scoring for the
        # asset that owns this source tree.
        # "data/remediation" excluded 2026-08-13: this is Centinela's own GENERATED OUTPUT
        # (the remediation scripts/patches this exact function writes for other findings), not
        # source code -- a script whose entire job is `sed -i 's/eval(/console.log(/g'` was
        # being flagged as a NEW eval() vulnerability, creating a real feedback loop where fixing
        # a finding generated a new "finding" about the fix itself. "data/sonar_scans" excluded
        # same day: cloned THIRD-PARTY repositories from other GitLab projects' SonarQube scans,
        # not Centinela's own code at all -- were being misattributed to Centinela's own
        # self-audit asset (confirmed live: findings under
        # data/sonar_scans/arquitectura-proyecto-m/... on the Centinela-AI (Self-Audit) asset).
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests", "/test/", "\\test\\", "data/remediation", "data/sonar_scans", "everything-claude-code", ".mvn", "/target/", "\\target\\", ".agents"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if file == "Dockerfile" or file.startswith("Dockerfile."):
                    all_findings.extend(scan_iac_dockerfile(full_path, content))
                # Real gap found 2026-08-20 while auditing a pure-Java codebase (proyecto-k/proyecto-j):
                # scan_sast_code() already has Java-aware detectors internally (the frontend
                # antipattern block at its own line ~160 explicitly checks filename.endswith(...,
                # ".java"), and SPRINGBOOT-NATIVE-QUERY-RISK/HARDCODED-SECRET/DB-UNENCRYPTED-CONN-
                # STRING are language-agnostic text patterns genuinely relevant to Java/Spring)
                # but this outer dispatch never actually sent .java files into it -- every Java
                # file in every repo this engine has ever scanned was silently skipped, making
                # "0 SAST findings" indistinguishable from "genuinely clean" for any Java-only
                # codebase. Confirmed safe to add: every pattern inside scan_sast_code() is
                # already internally guarded by its own filename check, so .java files simply
                # exercise the subset of rules that apply to them, same as any other extension.
                elif file.endswith(".sql"):
                    # .sql files only feed the migration-quality rule (the generic text rules were written for application code)
                    from auditors.auditor_standards_rules import scan_standards_rules
                    all_findings.extend(scan_standards_rules(full_path, content))
                elif file.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".java", ".html", ".xml", ".properties", ".json", ".yml", ".yaml")) \
                        or (file.startswith("requirements") and file.endswith(".txt")):
                    all_findings.extend(scan_sast_code(full_path, content))
            except Exception as e:
                print(f"⚠️ [Master-Auditor] Error reading {full_path}: {e}")

    # Persist findings in DB if available. Two real bugs fixed here:
    #
    # 1. item["file"]/item["line"] were captured by every scanner above but never actually
    #    written anywhere -- the INSERT only carried cve_id/severity/description, so no
    #    remediation (human or AI) could ever know which file to fix. Now stored in url_path
    #    as "relative/path.py:LINE" (repurposing the same generic "where this finding lives"
    #    column ZAP already uses for URLs), and prefixed into description for readability.
    #
    # 2. "ON CONFLICT DO NOTHING" with no conflict target only suppresses inserts that violate
    #    an actual unique constraint -- vulnerability_log has none beyond its own id, so this
    #    was a complete no-op and every re-scan re-inserted every finding as brand new (the same
    #    failure mode CLAUDE.md already documents for this table). Replaced with
    #    deduplication_engine.log_finding_deduplicated(), which also merges cross-tool (e.g. the
    #    same real CVE independently flagged by sca-native/Nuclei on this asset collapses into
    #    one ticket instead of creating a second one).
    try:
        from core import deduplication_engine
        active_fingerprints = set()
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir) if item.get("file") else "unknown"
                location = f"{rel_path}:{item.get('line', 0)}"
                description = f"**Archivo:** `{rel_path}` (Línea {item.get('line', 0)})\n{item['description']}"

                active_fingerprints.add(deduplication_engine.calculate_fingerprint(asset_id, item["cve_id"], location))
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], description,
                    "sast-native", url_path=location, open_status="OPEN", preserve_status=True
                )

            # Only reconcile when scoped to a real asset -- a bare/default asset_id=None call
            # (e.g. ad-hoc testing) has no well-defined "everything else for this asset" set to
            # resolve against. See reconcile_resolved_findings()'s own docstring: this closes a
            # real gap where line-anchored findings on actively-edited files (e.g. Centinela's
            # own source) never got marked resolved even long after the flagged code moved or
            # was already fixed, because line-number drift meant a fresh scan's fingerprint
            # would never match the old one again.
            if asset_id is not None:
                resolved_count = deduplication_engine.reconcile_resolved_findings(cur, asset_id, "sast-native", active_fingerprints)
                if resolved_count:
                    print(f"✅ [Master-Auditor] Reconciled {resolved_count} stale sast-native finding(s) as RESOLVED for asset {asset_id}.")
    except Exception as db_err:
        print(f"⚠️ [Master-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
