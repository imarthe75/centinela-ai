"""
Supply-chain rules for dependency manifests (ADR-0022 §3). Ideas from Datadog's GuardDog (Apache-2.0) and the OpenSSF
"Pinned-Dependencies" check; the code is Centinela's own and works offline on the files already in the clone:

  SUPPLY-CHAIN-INSTALL-SCRIPT-RISKY   package.json install hooks (preinstall/install/postinstall/prepare) that download
                                      or decode-and-run code. npm runs them on every developer machine and CI runner
                                      that installs the project, before anyone reviews anything.
  SUPPLY-CHAIN-DEPENDENCY-FROM-URL    a dependency taken from git / a tarball URL / a GitHub shorthand instead of the
                                      registry, without a full commit hash: the code behind the name can change at any
                                      time and no advisory database tracks it.
  SUPPLY-CHAIN-LOCKFILE-INSECURE-SOURCE  a lockfile that resolves packages over plain http:// (tampering in transit).
  SUPPLY-CHAIN-POSSIBLE-TYPOSQUAT     a dependency one edit away from a very popular package (`lodahs`, `reqeusts`)
                                      that is not itself a known package: the classic malware delivery trick. MEDIUM and
                                      worded as "verify", because a legitimate near-name is possible.

Known malicious packages (with an OSV `MAL-*` advisory) are reported by the SCA engine (auditor_sca_dependencies), not
here: this module catches the patterns BEFORE a package is known to be malicious.
"""
import json
import re
from typing import Dict, List, Optional, Tuple

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
_RISKY_CMD = re.compile(
    r"(\b(curl|wget|Invoke-WebRequest|iwr|certutil)\b|base64\s+(-d|--decode)|\bnode\s+-e\b|\beval\b|"
    r"\|\s*(ba|z)?sh\b|\bpowershell\b.*-enc)", re.I)
_FULL_SHA = re.compile(r"#[0-9a-f]{40}$|@[0-9a-f]{40}(?:#|$)", re.I)
_URL_SPEC = re.compile(r"^(git\+|git://|github:|gitlab:|bitbucket:|https?://)", re.I)
_GH_SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?$")

# The most downloaded packages of each registry, kept short on purpose: a typosquat targets names people type often.
POPULAR_NPM = frozenset("""
react react-dom vue angular lodash underscore express axios moment dayjs chalk commander debug request rxjs tslib
typescript webpack babel-core eslint prettier jest mocha chai sinon jquery bootstrap tailwindcss postcss autoprefixer
vite rollup esbuild next nuxt redux mobx uuid dotenv cors body-parser cookie-parser jsonwebtoken bcrypt bcryptjs
mongoose sequelize mysql mysql2 pg sqlite3 redis ioredis socket.io ws yargs minimist glob rimraf mkdirp fs-extra
semver async bluebird classnames prop-types styled-components sass node-sass less nodemon concurrently cross-env
husky lint-staged zod joi yup ajv qs core-js regenerator-runtime colors inquirer ora boxen figlet electron puppeteer
playwright cheerio jsdom marked highlight.js chart.js three d3 leaflet primeng primeicons ngx-toastr keycloak-js
angular-oauth2-oidc date-fns luxon numeral validator xlsx pdfkit nodemailer multer helmet morgan winston pino
tslint preact react-is
""".split())
POPULAR_PYPI = frozenset("""
requests urllib3 numpy pandas scipy matplotlib django flask fastapi uvicorn gunicorn sqlalchemy psycopg2 psycopg2-binary
pymysql redis celery boto3 botocore pyyaml jinja2 click six setuptools wheel pip certifi idna chardet charset-normalizer
cryptography pyopenssl paramiko pillow lxml beautifulsoup4 selenium pytest coverage mock tox black flake8 pylint mypy
pydantic attrs python-dateutil pytz tzdata simplejson ujson orjson httpx aiohttp websockets openpyxl xlrd scikit-learn
tensorflow torch keras tqdm colorama rich typer jsonschema markdown docutils sphinx pyjwt passlib bcrypt itsdangerous
werkzeug marshmallow alembic psutil docker kubernetes ansible hvac pika kafka-python elasticsearch pymongo
psycopg psycopg-binary pymssql pyodbc pydantic-core
""".split())


def _damerau1(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insertion, deletion, substitution or adjacent transposition."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(s) and s[i] == l[i]:
        i += 1
    return s[i:] == l[i + 1:]


def typosquat_target(name: str, ecosystem: str) -> Optional[str]:
    """The popular package `name` imitates, or None. Scoped npm names (@org/x) are never flagged: scopes are owned."""
    n = (name or "").strip().lower()
    if not n or n.startswith("@") or len(n) < 5:
        return None
    popular = POPULAR_NPM if ecosystem == "npm" else POPULAR_PYPI
    if n in popular:
        return None
    if ecosystem == "pypi":
        canon = re.sub(r"[-_.]+", "-", n)
        if canon in popular:
            return None     # same project, different separator spelling (PEP 503)
    for p in popular:
        if len(p) >= 4 and _damerau1(n, p):
            return p
    return None


_URL_CREDENTIALS = re.compile(r"(?<=://)[^/@\s]+@")


def redact_url_credentials(text: str) -> str:
    """`git+http://<user>:<token>@<host>/...` -> `git+http://***@<host>/...`. A credential inside a dependency URL must not
    travel into the finding text (database, reports, AI prompts). The credential itself is already reported by the secret
    engines (measured 2026-11-12: a GitLab token in three package.json files, flagged by five engines), so no rule here."""
    return _URL_CREDENTIALS.sub("***@", text or "")


def _line_of(lines: List[str], needle: str, start: int = 0) -> int:
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return 1


def evaluate_package_json(content: str) -> List[Tuple[str, str, int, str]]:
    """(rule, severity, line, description) for a package.json. Unparseable JSON yields nothing (other rules report it)."""
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    lines = content.splitlines()
    out: List[Tuple[str, str, int, str]] = []

    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for hook in INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and _RISKY_CMD.search(cmd):
            out.append(("SUPPLY-CHAIN-INSTALL-SCRIPT-RISKY", "HIGH", _line_of(lines, f'"{hook}"'),
                        f"El script de instalación `{hook}` descarga o ejecuta código (`{cmd[:120]}`): npm lo corre en cada máquina y "
                        "runner de CI que instala el proyecto, sin revisión. Mueva esa descarga a un paso explícito y verificado "
                        "(versión fija y suma SHA-256) o elimínela."))

    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec_s = str(spec or "").strip()
            line = _line_of(lines, f'"{name}"')
            shown = redact_url_credentials(spec_s)[:120]
            if (_URL_SPEC.match(spec_s) or (_GH_SHORTHAND.match(spec_s) and not spec_s[:1].isdigit())) \
                    and not spec_s.startswith(("file:", "link:", "workspace:", "npm:")) and not _FULL_SHA.search(spec_s):
                out.append(("SUPPLY-CHAIN-DEPENDENCY-FROM-URL", "MEDIUM", line,
                            f"La dependencia `{name}` viene de `{shown}` y no del registro, sin un commit completo (40 "
                            "caracteres) fijado: el código detrás del nombre puede cambiar en cualquier momento y ninguna base de "
                            "avisos lo vigila. Publíquela en el registro interno o fije el commit (`#<sha>`)."))
            target = typosquat_target(name, "npm")
            if target:
                out.append(("SUPPLY-CHAIN-POSSIBLE-TYPOSQUAT", "MEDIUM", line,
                            f"La dependencia `{name}` está a un carácter del paquete muy usado `{target}` y no es un paquete "
                            "conocido de la lista de referencia: verifique que sea la que se quería instalar (los paquetes con "
                            "nombres casi idénticos son la vía más común para distribuir malware)."))
    return out


def evaluate_requirements(content: str) -> List[Tuple[str, str, int, str]]:
    out: List[Tuple[str, str, int, str]] = []
    for idx, raw in enumerate((content or "").splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(-e\s+)?(git\+|https?://)", line) and "--hash" not in line and not _FULL_SHA.search(line.split("#egg=")[0]):
            out.append(("SUPPLY-CHAIN-DEPENDENCY-FROM-URL", "MEDIUM", idx,
                        f"Dependencia instalada desde `{redact_url_credentials(line)[:120]}` sin commit completo ni `--hash`: el contenido puede cambiar "
                        "sin cambiar esta línea y ninguna base de avisos lo vigila."))
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if m and not line.startswith("-"):
            target = typosquat_target(m.group(1), "pypi")
            if target:
                out.append(("SUPPLY-CHAIN-POSSIBLE-TYPOSQUAT", "MEDIUM", idx,
                            f"La dependencia `{m.group(1)}` está a un carácter del paquete muy usado `{target}` y no es un paquete "
                            "conocido de la lista de referencia: verifique que sea la que se quería instalar."))
    return out


def evaluate_lockfile(content: str, filename: str) -> List[Tuple[str, str, int, str]]:
    """package-lock.json / npm-shrinkwrap.json / yarn.lock / pnpm-lock.yaml: packages resolved over plain http://.
    Grouped into one finding per lockfile (a single misconfigured registry shows up on hundreds of entries)."""
    hits: List[int] = []
    rx = re.compile(r'("resolved"\s*:\s*"|resolved\s+"?|tarball:\s*)http://', re.I)
    for idx, line in enumerate((content or "").splitlines(), 1):
        if rx.search(line):
            hits.append(idx)
    if not hits:
        return []
    return [("SUPPLY-CHAIN-LOCKFILE-INSECURE-SOURCE", "MEDIUM", hits[0],
             f"`{filename}` resuelve {len(hits)} paquete(s) por `http://` sin cifrar (primera línea {hits[0]}): un intermediario "
             "puede sustituir el paquete durante la instalación. Configure el registro con `https://` y regenere el lockfile.")]


def scan_file(filename: str, content: str) -> List[Tuple[str, str, int, str]]:
    """Dispatch by manifest name; any other file yields nothing."""
    if filename == "package.json":
        return evaluate_package_json(content)
    if filename.startswith("requirements") and filename.endswith(".txt"):
        return evaluate_requirements(content)
    if filename in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
        return evaluate_lockfile(content, filename)
    return []
