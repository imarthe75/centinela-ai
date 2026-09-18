# Centinela-AI — despliegue `setag.mx` (autónomo, sin infra 10.4.3.x)

Este host (VM ARM/aarch64, 2 vCPU, 11 GB) **no tiene ruta a la infra CASMARTS**
(`10.4.3.23` Postgres/Valkey, `10.4.3.208` Vault, `10.4.3.10` GitLab). Corre la
plataforma de forma **totalmente autónoma** con datos propios.

## Qué cambia respecto a `master`

| Archivo | Motivo |
|---|---|
| `docker-compose.override.yml` | Añade `centinela-postgres` y `centinela-valkey` locales; repunta SonarQube al Postgres local; sube el límite de RAM del frontend. |
| `database/init/10-extra-databases.sql` | Crea `centinela_sonarqube_db` en el Postgres local. |
| `database/init/20-schema-core.sql` | **Esquema central reconstruido.** Las tablas `infra_inventory`, `vulnerability_log`, `remediation_history`, `runtime_alerts` + catálogos no tenían DDL en el repo (vivían solo en el `centinela_db` externo). Reconstruido desde las referencias SQL del código. Se carga solo en el primer arranque del volumen `centinela-pgdata`. |
| `Dockerfile` | Descarga binarios `arm64` (nuclei/ffuf) en vez de `amd64`; kiterunner se omite (no hay build arm64 upstream); `pip install` en dos fases + `semgrep`/`prowler`/`cvss` fijados para que el resolver no entre en backtracking de horas. |
| `requirements.txt` | Pins de `semgrep==1.141.0`, `prowler==5.22.0`, `cvss==3.6` (las versiones que ya resolvían en la imagen del backend). |
| `scripts/sync-repo.sh` | Sincronización con GitHub (`git pull --ff-only` + push opcional). |
| `deploy/nginx/*.conf` | Reverse proxy del host: `/` → frontend `:8301`, `/api/` → backend `:8302`, WebSockets. |

## `.env` (NO versionado — `.gitignore`)

Diferencias clave con `.env.example`:

```
DB_HOST=centinela-postgres          # era 10.4.3.23
VALKEY_HOST=centinela-valkey        # era 10.4.3.23
DOCKER_GID=111                      # getent group docker en este host
SONARQUBE_DB_PASSWORD=centinela_sonar_db_2026
CLICKHOUSE_USER=centinela
CLICKHOUSE_PASSWORD=centinela_ch_2026
```

Credenciales de IA / GitLab / Vault: vacías por ahora (la plataforma corre sin ellas;
los escaneos con IA quedan en modo heurístico hasta que se añada al menos un
`*_API_KEY`).

## Arranque

```bash
docker network create aura-network 2>/dev/null || true
docker compose up -d centinela-postgres centinela-valkey centinela-neo4j \
                     centinela-backend centinela-frontend centinela-ai centinela-sentinel
# pesados, según quepan en RAM:
docker compose up -d centinela-clickhouse centinela-zeek falco falcosidekick
docker compose up -d centinela-sonarqube        # 4 GB
docker compose up -d wazuh-manager              # revisar imagen arm64
curl -s http://127.0.0.1:8302/api/health | python3 -m json.tool
```

## Permisos del bind-mount (`.:/app`)

El usuario del host es **uid 1001** (`ubuntu`), pero los contenedores corren como
**uid 1000** (`appuser`, fijado en los Dockerfiles). Sin ajuste, el contenedor no puede
escribir en `/app` (p.ej. `centinela.py` escribe scripts a `/app/data/remediation/`).
Resuelto con ACLs (no rebuild, el host conserva su propiedad y escritura):

```bash
sudo apt-get install -y acl
sudo setfacl -R    -m u:1000:rwX -m m:rwX /opt/centinela-ai
sudo setfacl -R -d -m u:1000:rwX -m m:rwX /opt/centinela-ai   # default ACL para archivos nuevos
```

## SSL

nginx del host sirve `:80` con `server_name _` (catch-all). El firewall local (iptables
de la imagen OCI) ya tiene 80/443 abiertos y persistidos (`/etc/iptables/rules.v4`).

Para emitir el certificado:

```bash
sudo certbot --nginx -d setag.mx --redirect -m <correo> --agree-tos
```

**Prerrequisitos que faltan (fuera de esta VM):**

| Requisito | Estado |
|---|---|
| DNS `A setag.mx` → IP pública de esta VM (`158.101.124.197`) | ❌ `setag.mx` resuelve hoy a `129.159.171.36` (otro host). Hay que repuntar el registro A. |
| Puertos 80/443 abiertos en la **Security List** de Oracle Cloud (ingress) para la subred de esta VM | ❌ Pendiente en la consola de OCI (el firewall *local* ya está abierto). |

Mientras tanto nginx sirve HTTP en la IP pública en cuanto se abra el ingress de OCI;
el SSL queda a un solo `certbot` cuando el DNS apunte aquí.

## Sincronización con el repo

```bash
printf 'https://imarthe75:%s@github.com\n' '<GITHUB_PAT>' > /home/ubuntu/.git-credentials
chmod 600 /home/ubuntu/.git-credentials
scripts/sync-repo.sh --restart      # git pull --ff-only + limpia __pycache__ + reinicia servicios
```
