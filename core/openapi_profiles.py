"""
Profiles (roles / scopes) declared by an application's OpenAPI/Swagger document, for assets that are a URL or an API endpoint with NO source code in the
inventory. Names only; nothing is invented: a spec that declares none returns an empty list.

Read from:  components.securitySchemes.*.flows.*.scopes (OAuth2 scopes) and securityDefinitions.*.scopes (Swagger 2),
            vendor extensions `x-roles`, `x-required-roles`, `x-permissions`, `x-scopes` (any depth),
            enum values of a parameter/property named role / rol / perfil / profile / authority.
"""
import ipaddress
import json
import re
import socket
from typing import Any, Dict, Iterator, List
from urllib.parse import urlparse

import requests

MAX_BYTES = 3_000_000
_EXT_KEYS = ("x-roles", "x-required-roles", "x-permissions", "x-scopes")
_ROLE_PARAM = re.compile(r"^(role|rol|roles|perfil|profile|authority|authorities)$", re.IGNORECASE)


def _walk(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, dict):
            stack.extend(n.values())
        elif isinstance(n, list):
            stack.extend(n)


def parse_profiles(spec: Dict[str, Any]) -> List[Dict[str, str]]:
    found: Dict[str, Dict[str, str]] = {}

    def add(name: Any, where: str):
        if isinstance(name, str) and 2 <= len(name.strip()) <= 80:
            found.setdefault(name.strip().lower(), {"role": name.strip(), "source": "openapi", "file": where})

    comps = (spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
    for scheme_name, scheme in comps.items():
        if not isinstance(scheme, dict):
            continue
        for flow in (scheme.get("flows") or {}).values():
            for scope in (flow.get("scopes") or {}):
                add(scope, f"securitySchemes.{scheme_name}")
        for scope in (scheme.get("scopes") or {}):
            add(scope, f"securityDefinitions.{scheme_name}")
    for n in _walk(spec):
        if isinstance(n, dict):
            for k in _EXT_KEYS:
                v = n.get(k)
                for item in (v if isinstance(v, list) else list((v or {}).keys()) if isinstance(v, dict) else []):
                    add(item, k)
            name, enum = n.get("name"), n.get("enum")
            if isinstance(name, str) and _ROLE_PARAM.match(name) and isinstance(enum, list):
                for e in enum:
                    add(e, f"enum:{name}")
            for pname, prop in (n.get("properties") or {}).items() if isinstance(n.get("properties"), dict) else []:
                if _ROLE_PARAM.match(str(pname)) and isinstance(prop, dict) and isinstance(prop.get("enum"), list):
                    for e in prop["enum"]:
                        add(e, f"enum:{pname}")
    return sorted(found.values(), key=lambda r: r["role"].lower())


def _blocked_host(host: str) -> bool:
    """Do not let this feature reach the cloud-metadata / link-local range from the backend."""
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                return True
    except (socket.gaierror, ValueError):
        return False
    return False


def fetch_profiles(openapi_url: str, timeout: int = 12) -> List[Dict[str, str]]:
    u = urlparse(openapi_url or "")
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("La URL de OpenAPI debe ser http(s)")
    if _blocked_host(u.hostname):
        raise ValueError("Esa dirección no está permitida")
    r = requests.get(openapi_url, timeout=timeout, verify=False, stream=True, headers={"Accept": "application/json"})
    r.raise_for_status()
    body = r.raw.read(MAX_BYTES + 1, decode_content=True)
    if len(body) > MAX_BYTES:
        raise ValueError("El documento OpenAPI es demasiado grande")
    try:
        return parse_profiles(json.loads(body))
    except json.JSONDecodeError:
        raise ValueError("La URL no devolvió un JSON de OpenAPI (YAML no está soportado)")
