#!/usr/bin/env python3
"""
Restablece la contraseña del usuario `admin` de SonarQube y deja un token de administrador en `.env` como SONAR_ADMIN_TOKEN, para que
Centinela pueda activar `sonar.security.secretSourceRedaction.enabled` (ocultar secretos en la vista de código de SonarQube).

Lo corre el dueño, a mano, dentro de centinela-backend (que ya lee SONARQUBE_DB_USER/PASSWORD y SONAR_HOST_URL de .env):

    docker exec -it centinela-backend python3 scripts/sonarqube_admin_reset.py

Qué hace, en orden:
  1. Respalda la fila `admin` de la tabla `users` en data/db_backups/sonarqube_admin_row_<fecha>.json (permisos 600).
  2. Genera una contraseña aleatoria y escribe su hash con el mismo algoritmo que SonarQube 26.11 usa al guardar una contraseña
     (CredentialsLocalAuthentication$PBKDF2Function, leído del bytecode de la versión instalada): PBKDF2WithHmacSHA512,
     100000 iteraciones, llave de 512 bits, sal aleatoria de 20 bytes guardada en base64, y crypted_password = "100000$" + base64(hash).
  3. Comprueba el login contra la API de SonarQube. Si NO valida, restaura la fila respaldada y termina con error (no deja nada a medias).
  4. Genera un token de usuario para admin y guarda en .env SONAR_ADMIN_TOKEN y SONAR_ADMIN_PASSWORD (el .env es 600). No imprime ninguno.

Después: `docker compose up -d centinela-ai centinela-backend` (recrear, no restart) para que lean el token; el próximo escaneo de SonarQube
activa el ajuste y /api/health deja de mostrar SonarQube en ámbar.
"""
import base64
import datetime
import hashlib
import json
import os
import re
import secrets
import sys

import psycopg2
import requests

ITERATIONS = 100000
ENV_PATH = os.getenv("CENTINELA_ENV_FILE", "/app/.env")
BACKUP_DIR = "/app/data/db_backups"
SONAR = os.getenv("SONAR_HOST_URL", "http://centinela-sonarqube:9000").rstrip("/")


def sonar_hash(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, ITERATIONS, dklen=64)
    return f"{ITERATIONS}${base64.b64encode(digest).decode()}"


def set_env(key: str, value: str) -> None:
    with open(ENV_PATH) as f:
        lines = f.read().splitlines()
    pattern = re.compile(rf"^{re.escape(key)}=")
    lines = [ln for ln in lines if not pattern.match(ln)] + [f"{key}={value}"]
    with open(ENV_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    conn = psycopg2.connect(host=os.getenv("SONARQUBE_DB_HOST", "192.0.2.15"), dbname="centinela_sonarqube_db",
                            user=os.environ["SONARQUBE_DB_USER"], password=os.environ["SONARQUBE_DB_PASSWORD"])
    cur = conn.cursor()
    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'users'")
    columns = {r[0] for r in cur.fetchall()}
    cur.execute("SELECT row_to_json(u) FROM users u WHERE login = 'admin'")
    row = cur.fetchone()
    if not row:
        print("No existe el usuario 'admin' en SonarQube; nada que hacer.")
        return 1
    original = row[0]
    if not original.get("active"):
        print("El usuario 'admin' está desactivado en SonarQube; actívalo antes (o pide ayuda): no se cambió nada.")
        return 1

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup = os.path.join(BACKUP_DIR, f"sonarqube_admin_row_{datetime.date.today().isoformat()}.json")
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(original, f, default=str)
    print(f"Respaldo de la fila admin: {backup}")

    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(20)
    sets = ["crypted_password = %s", "salt = %s", "hash_method = 'PBKDF2'"]
    params = [sonar_hash(password, salt), base64.b64encode(salt).decode()]
    if "reset_password" in columns:
        sets.append("reset_password = FALSE")
    cur.execute(f"UPDATE users SET {', '.join(sets)} WHERE login = 'admin'", params)
    conn.commit()

    ok = False
    try:
        r = requests.get(f"{SONAR}/api/authentication/validate", auth=("admin", password), timeout=30)
        ok = r.ok and r.json().get("valid") is True
    except Exception as e:
        print(f"No se pudo validar contra SonarQube: {type(e).__name__}: {e}")
    if not ok:
        restore = ["crypted_password = %s", "salt = %s", "hash_method = %s"]
        values = [original.get("crypted_password"), original.get("salt"), original.get("hash_method")]
        if "reset_password" in columns:
            restore.append("reset_password = %s")
            values.append(original.get("reset_password"))
        cur.execute(f"UPDATE users SET {', '.join(restore)} WHERE login = 'admin'", values)
        conn.commit()
        print("El login con la contraseña nueva NO validó: se restauró la fila original. No se cambió nada en .env.")
        return 1

    name = f"centinela-admin-{datetime.datetime.now():%Y%m%d%H%M}"
    r = requests.post(f"{SONAR}/api/user_tokens/generate", auth=("admin", password), data={"name": name}, timeout=30)
    r.raise_for_status()
    token = r.json()["token"]
    set_env("SONAR_ADMIN_PASSWORD", password)
    set_env("SONAR_ADMIN_TOKEN", token)
    print(f"Listo: login validado, token '{name}' creado. SONAR_ADMIN_PASSWORD y SONAR_ADMIN_TOKEN guardados en {ENV_PATH}.")
    print("Siguiente paso: docker compose up -d centinela-ai centinela-backend")
    return 0


if __name__ == "__main__":
    sys.exit(main())
