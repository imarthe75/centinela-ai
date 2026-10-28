"""
Centinela-AI — external dependencies declared in a repository's configuration that do not answer (scan_engine: dependency-probe).

Why: in a manual QA cycle two blockers were environment problems (a document-editor server that was down, a backend whose submit call failed), found only by
running the cases. The endpoints are written in the configuration (application-*.yml/properties, Angular environment files, .env.example), so Centinela can
read them and check, from its own network, that each host resolves and accepts a TCP connection.

Read-only and conservative: TCP connect only (no requests with credentials), at most MAX_PER_REPO hosts, short timeout, URL credentials are never printed.
It measures reachability FROM CENTINELA, which may not be the network the application runs in: every finding says so, and the severity is LOW for dev/local profiles.
Skipped on purpose: `${placeholders}`, localhost/loopback, single-label names (container service names that only resolve inside their own compose), documentation hosts.
"""
import logging
import os
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core import db_manager, deduplication_engine as de

logger = logging.getLogger(__name__)
ENGINE = "dependency-probe"
MAX_PER_REPO = 40
TIMEOUT = 3.0
SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "__pycache__", ".gradle", "test", "tests"}
_URL_RE = re.compile(r"\b((?:https?|jdbc:[a-z0-9]+|redis|rediss|amqp|amqps|mongodb|ldap|ldaps|smtp|kafka|tcp)://[^\s'\"`,;)}\]]+)", re.IGNORECASE)
_DEFAULT_PORT = {"http": 80, "https": 443, "redis": 6379, "rediss": 6379, "amqp": 5672, "amqps": 5671, "mongodb": 27017, "ldap": 389, "ldaps": 636,
                 "postgresql": 5432, "mysql": 3306, "sqlserver": 1433, "oracle": 1521, "mariadb": 3306, "smtp": 25, "kafka": 9092}
_IGNORED_HOSTS = re.compile(r"(^|\.)(example|test|invalid|localhost|local)(\.[a-z]+)?$|^(localhost|0\.0\.0\.0|127\.\d+\.\d+\.\d+|::1)$", re.IGNORECASE)
_CONFIG_FILE = re.compile(r"(^|/)(application[\w.-]*\.(ya?ml|properties)|bootstrap[\w.-]*\.(ya?ml|properties)|environment[\w.-]*\.ts|\.env(\.\w+)?|\.env\.example|config\.json)$", re.IGNORECASE)


def _profile(rel: str) -> str:
    m = re.search(r"(?:application|bootstrap|environment)[.-]([a-z0-9]+)\.", rel, re.IGNORECASE)
    return (m.group(1).lower() if m else "base")


def parse_endpoint(raw: str) -> Optional[Tuple[str, int, str]]:
    """a JDBC/HTTP URL -> (host, port, scheme); any user:password part of the URL is discarded. None when it cannot be probed (placeholder, loopback, single label, no host)."""
    if "${" in raw or "{{" in raw or "<" in raw:
        return None
    url = raw.strip().rstrip(".,")
    url = re.sub(r"^jdbc:", "", url, flags=re.IGNORECASE)
    try:
        u = urlparse(url)
        host = u.hostname
        port = u.port
    except ValueError:
        return None
    scheme = (u.scheme or "").lower()
    if not host or _IGNORED_HOSTS.search(host):
        return None
    if "." not in host and not re.fullmatch(r"[0-9a-fA-F:]+", host):
        return None                        # single-label name: a container/service name, only meaningful inside its own network
    port = port or _DEFAULT_PORT.get(scheme)
    if not port:
        return None
    return host, int(port), scheme


def extract_dependencies(root: str) -> List[Dict[str, Any]]:
    """[{host, port, scheme, file, line, profile}] from the configuration files of a repository (credentials in the URL are discarded here)."""
    out, seen = [], set()
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if not _CONFIG_FILE.search(rel):
                continue
            try:
                lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except OSError:
                continue
            for n, line in enumerate(lines, 1):
                if line.lstrip().startswith(("#", "//", "*")):
                    continue
                for m in _URL_RE.finditer(line):
                    ep = parse_endpoint(m.group(1))
                    if ep and (ep[0], ep[1]) not in seen:
                        seen.add((ep[0], ep[1]))
                        out.append({"host": ep[0], "port": ep[1], "scheme": ep[2], "file": rel, "line": n, "profile": _profile(rel)})
    return out[:MAX_PER_REPO]


_cache: Dict[Tuple[str, int], Tuple[float, str]] = {}


def probe(host: str, port: int, timeout: float = TIMEOUT) -> str:
    """'ok' | 'dns' (does not resolve) | 'refused' | 'timeout' | 'error:<kind>'. Cached for 10 minutes (the same host appears in many repositories)."""
    hit = _cache.get((host, port))
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        res = "dns"
    else:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                res = "ok"
        except ConnectionRefusedError:
            res = "refused"
        except (socket.timeout, TimeoutError):
            res = "timeout"
        except OSError as e:
            res = f"error:{e.__class__.__name__}"
    _cache[(host, port)] = (time.time(), res)
    return res


_WHY = {"dns": "el nombre no se resuelve", "refused": "rechaza la conexión (nada escucha en ese puerto)", "timeout": "no responde (tiempo de espera agotado)"}


def check_dependencies(deps: List[Dict[str, Any]], prober=probe) -> List[Dict[str, Any]]:
    findings = []
    for d in deps:
        res = prober(d["host"], d["port"])
        if res == "ok":
            continue
        sev = "LOW" if d["profile"] in ("dev", "local", "test", "desa") else "MEDIUM"
        findings.append({
            "cve_id": "DEPENDENCY-UNREACHABLE", "severity": sev, "url_path": f"{d['file']}:{d['line']}",
            "description": (f"La dependencia `{d['host']}:{d['port']}` ({d['scheme']}) declarada en `{d['file']}` línea {d['line']} (perfil «{d['profile']}») {_WHY.get(res, 'no se pudo contactar (' + res + ')')} "
                            f"desde Centinela. Si el aplicativo la necesita en ese ambiente, fallará en tiempo de ejecución (por ejemplo, un editor de documentos o un servicio de firma caído). "
                            f"_Alcance: alcanzabilidad medida desde la red de Centinela, que puede no ser la del aplicativo._"),
        })
    return findings


def run_dependency_probe(target_dir: str, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
    findings = check_dependencies(extract_dependencies(target_dir))
    if asset_id is not None:
        active = set()
        with db_manager.get_db_cursor() as cur:
            for f in findings:
                active.add(de.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
                de.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], scan_engine=ENGINE, url_path=f["url_path"], preserve_status=True)
            de.reconcile_resolved_findings(cur, asset_id, ENGINE, active)
    return findings
