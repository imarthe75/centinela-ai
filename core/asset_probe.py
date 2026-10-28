"""
Pruebas de conexión previas al alta de un activo: formato de la dirección, alcance de red (TCP) y, si se dan credenciales,
login SSH + comprobación de sudo. Nada se persiste y la contraseña nunca viaja en argv ni se escribe en logs.

Política: no se aceptan cuentas `root`. Se exige un usuario normal con sudo.
"""
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import time
from typing import Optional

ROOT_USERS = {"root"}
_USER_RE = re.compile(r"^[a-z_][a-z0-9_.@-]{0,63}$", re.I)
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)
SSH_TYPES = {"SERVER_LINUX", "SERVER", "AppServer", "WORKSTATION", "CISCO_NETWORK", "VMWARE_ESXI", "CONTAINER", "KUBERNETES"}
PORTS_TO_TRY = [22, 443, 80, 3389, 445, 5985, 8443]

ROOT_MESSAGE = ("No se permite registrar el usuario root. Usa un usuario normal con privilegios sudo "
                "(p. ej. 'centinela' o 'ubuntu'); Centinela escala con sudo solo cuando lo necesita.")


class ProbeInputError(ValueError):
    pass


def reject_root_user(user: Optional[str]) -> None:
    """Raises ProbeInputError if `user` is root (case/whitespace-insensitive). Empty is allowed (field is optional)."""
    if user and user.strip().lower() in ROOT_USERS:
        raise ProbeInputError(ROOT_MESSAGE)


def parse_host(endpoint: str) -> str:
    """Extracts a bare host from 'host', 'host:port', '[v6]:port' or 'http(s)://host/...'; validates it and refuses loopback,
    link-local (incl. cloud metadata), multicast and unspecified targets so this endpoint cannot be used to probe the backend itself."""
    h = (endpoint or "").strip()
    h = re.sub(r"^[a-z]+://", "", h, flags=re.I).split("/")[0]
    if h.startswith("["):
        h = h[1:].split("]")[0]
    elif h.count(":") == 1:
        h = h.split(":")[0]
    if not h:
        raise ProbeInputError("Escribe una dirección IP o nombre de host.")
    try:
        ips = [ipaddress.ip_address(h)]
    except ValueError:
        if not _HOST_RE.match(h):
            raise ProbeInputError(f"'{h}' no es una IPv4, IPv6 ni un nombre de host válido.")
        try:
            ips = [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(h, None)]
        except socket.gaierror:
            raise ProbeInputError(f"El nombre '{h}' no resuelve en DNS: revisa que esté bien escrito.")
    for ip in ips:
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ProbeInputError(f"La dirección {ip} no es válida como activo (loopback / link-local / multicast).")
    return h


def _tcp(host: str, port: int, timeout: float = 2.5):
    t0 = time.time()
    try:
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True, round((time.time() - t0) * 1000, 1)
    except OSError:
        return False, None


def _explain_ssh_failure(stderr: str, rc: int) -> str:
    e = (stderr or "").lower()
    if "permission denied" in e or "authentication failed" in e:
        return "Usuario o contraseña/llave incorrectos (el servidor rechazó la autenticación)."
    if "connection refused" in e:
        return "El puerto 22 rechazó la conexión: SSH no está activo o hay un firewall."
    if "timed out" in e or "no route to host" in e or rc == 124:
        return "No hubo respuesta SSH a tiempo: la IP es incorrecta, está apagada o un firewall la bloquea."
    if "could not resolve" in e:
        return "El nombre del host no resuelve."
    if "host key verification failed" in e:
        return "Falló la verificación de la llave del host."
    if "too many authentication failures" in e:
        return "Demasiados intentos de autenticación fallidos con las llaves ofrecidas."
    return f"SSH falló (código {rc}). Detalle: {(stderr or '').strip()[-200:]}"


def probe(endpoint: str, asset_type: str = "", user: str = "", auth_type: str = "PASSWORD",
          password: str = "", ssh_private_key: str = "") -> dict:
    """Runs the checks and returns {ok, steps:[{id,label,status,detail}]}. status: ok | fail | skip | warn."""
    steps = []

    def add(id_, label, status, detail):
        steps.append({"id": id_, "label": label, "status": status, "detail": detail})

    try:
        host = parse_host(endpoint)
    except ProbeInputError as e:
        add("format", "Formato de la dirección", "fail", str(e))
        return {"ok": False, "steps": steps}
    add("format", "Formato de la dirección", "ok", f"Host: {host}")

    try:
        reject_root_user(user)
    except ProbeInputError as e:
        add("user", "Usuario de conexión", "fail", str(e))
        return {"ok": False, "steps": steps}

    open_ports = {}
    for port in PORTS_TO_TRY:
        ok, ms = _tcp(host, port)
        if ok:
            open_ports[port] = ms
            if len(open_ports) >= 3:
                break
    if open_ports:
        add("reach", "Alcance de red (TCP)", "ok",
            "Responde en puertos " + ", ".join(f"{p} ({ms} ms)" for p, ms in open_ports.items()))
    else:
        add("reach", "Alcance de red (TCP)", "fail",
            f"{host} no responde en ninguno de los puertos {PORTS_TO_TRY}. Revisa que la IP sea correcta, que el equipo esté encendido "
            "y que ningún firewall lo bloquee. (El contenedor no puede enviar ICMP, por eso se prueba por TCP.)")
        return {"ok": False, "steps": steps}

    wants_ssh = asset_type in SSH_TYPES and bool(user)
    if not wants_ssh:
        add("ssh", "Login SSH", "skip",
            "Sin usuario o tipo de activo sin SSH: solo se verificó el alcance de red." if asset_type in SSH_TYPES or not asset_type
            else "Este tipo de activo no usa SSH.")
        return {"ok": True, "steps": steps}
    if not _USER_RE.match(user):
        add("ssh", "Login SSH", "fail", "El nombre de usuario tiene caracteres no válidos.")
        return {"ok": False, "steps": steps}
    if 22 not in open_ports and not _tcp(host, 22)[0]:
        add("ssh", "Login SSH", "fail", "El puerto 22 no está abierto en ese host; no se puede probar SSH.")
        return {"ok": False, "steps": steps}
    if not password and not ssh_private_key:
        add("ssh", "Login SSH", "skip", "No capturaste contraseña ni llave: no se probó el login.")
        return {"ok": True, "steps": steps}

    keyfile = None
    env = dict(os.environ)
    base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
            "-o", "LogLevel=ERROR"]
    try:
        if auth_type == "SSH_KEY" and ssh_private_key:
            fd, keyfile = tempfile.mkstemp(prefix="probe_key_")
            with os.fdopen(fd, "w") as f:
                f.write(ssh_private_key.strip() + "\n")
            os.chmod(keyfile, 0o600)
            cmd = base + ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-i", keyfile]
        else:
            env["SSHPASS"] = password
            cmd = ["sshpass", "-e"] + base + ["-o", "PreferredAuthentications=password,keyboard-interactive",
                                                "-o", "PubkeyAuthentication=no"]
        # id -u first; then sudo: -n works only if NOPASSWD, otherwise the password is fed on stdin (never on argv).
        remote = "id -u; (sudo -n true 2>/dev/null && echo SUDO_NOPASSWD) || (sudo -S -p '' true 2>/dev/null && echo SUDO_PASSWORD) || echo SUDO_NO"
        cmd += [f"{user}@{host}", remote]
        res = subprocess.run(cmd, input=(password + "\n") if password else None, capture_output=True, text=True,
                             timeout=30, env=env)
    except subprocess.TimeoutExpired:
        add("ssh", "Login SSH", "fail", "La conexión SSH excedió el tiempo de espera.")
        return {"ok": False, "steps": steps}
    finally:
        if keyfile and os.path.exists(keyfile):
            os.unlink(keyfile)

    out = [l.strip() for l in res.stdout.splitlines() if l.strip()]
    if res.returncode != 0 and not out:
        add("ssh", "Login SSH", "fail", _explain_ssh_failure(res.stderr, res.returncode))
        return {"ok": False, "steps": steps}
    add("ssh", "Login SSH", "ok", f"Autenticación correcta como '{user}'.")

    uid = out[0] if out else ""
    if uid == "0":
        add("user", "Usuario no-root", "fail", "Esa cuenta tiene UID 0 (equivale a root). " + ROOT_MESSAGE)
        return {"ok": False, "steps": steps}
    add("user", "Usuario no-root", "ok", f"UID {uid}.")

    if "SUDO_NOPASSWD" in out:
        add("sudo", "Privilegios sudo", "ok", "Tiene sudo sin contraseña (NOPASSWD).")
    elif "SUDO_PASSWORD" in out:
        add("sudo", "Privilegios sudo", "ok", "Tiene sudo con la contraseña indicada.")
    else:
        add("sudo", "Privilegios sudo", "fail",
            "El usuario NO puede usar sudo (o la contraseña sudo es incorrecta). Agrégalo al grupo sudo/wheel.")
        return {"ok": False, "steps": steps}
    return {"ok": all(s["status"] != "fail" for s in steps), "steps": steps}
