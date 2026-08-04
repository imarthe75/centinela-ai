# Centinela-AI

SOC/SOAR platform for the CASMARTS ("Casmart") infrastructure: continuous vulnerability
scanning across many scanner engines, an AI correlation/remediation engine, a Wazuh EDR
integration, and a React dashboard. Spanish is the primary language for UI copy, DB content,
and most in-repo docs/comments.

## Architecture

Everything runs via `docker-compose.yml`, one service per concern, all bind-mounting the repo
root (`.:/app`) so code changes are live without a rebuild — **except compiled Python
bytecode** (see Gotchas below) and anything baked at image-build time (system packages, pip
installs not in `requirements.txt`/the Dockerfile's own pip list).

| Service | Entry point | Role |
|---|---|---|
| `centinela-ai` | `centinela.py` | Orchestrator: discovery loop, all scanner dispatch (`auditors/auditor_ext.py`), AI correlation loop, Falco/Zeek/BloodHound ingestion |
| `centinela-backend` | `main.py` (FastAPI/uvicorn) | REST API the frontend talks to, PDF reports, health check, Wazuh agent actions |
| `centinela-sentinel` | `sentinel.py` | Executes *approved* remediations via Ansible, marks vulns `RESOLVED` |
| `centinela-frontend` | Vite/React | Dashboard UI |
| `centinela-neo4j` | — | BloodHound/AD attack-path graph |
| `centinela-zeek` | — | Network IDS sensor (writes to `/usr/local/zeek/logs`, must run with `working_dir` set there or logs go to `/` and never reach the app) |
| `wazuh-manager` (container name `casmarts-core-wazuh-manager`) | — | Wazuh EDR manager, added 2026-08-04. Ports 1514/1515/55000 published to the host so remote agents and the host's own `wazuh-agent` (systemd) can enroll. |

### External dependencies (NOT part of this docker-compose stack)

- **Postgres `centinela_db`** — on a separate server, `10.4.3.23`. This is the shared source of
  truth; see the phantom-deployment gotcha below.
- **HashiCorp Vault** — on `10.4.3.208` (`casmarts-core-vault`, part of a *different* project,
  `core-casmarts`). Stores Ansible sudo passwords / SSH keys per asset, never the DB.
- **Authentik** (SSO) — also on `10.4.3.208`.

Auditors that shell out to external tools (nuclei, trivy, nmap, sqlmap, semgrep, prowler,
medusa, trufflehog, checkov, syft/grype) expect those binaries in the image — see the two
Dockerfiles. `auditor_zap.py` runs ZAP via `docker run` on the host's Docker socket instead of
being baked into the image.

## Common tasks

```bash
# Rebuild after touching requirements.txt or either Dockerfile
docker compose build centinela-ai centinela-backend
docker compose up -d centinela-ai centinela-backend

# After a refactor that moves/renames .py files, always clear stale bytecode first:
find /opt/centinela-ai -iname "__pycache__" -type d -exec rm -rf {} +
docker restart centinela-ai centinela-backend centinela-sentinel

# Full health check
curl -s http://127.0.0.1:8302/api/health | python3 -m json.tool

# Ansible against inventory.ini hosts — keys live at /app/keys/*.key inside the
# container (bind-mounted from ./keys/), NOT /app/*.key.
docker exec centinela-backend bash -c "cd /app && ansible all -i inventory.ini -m ping"
```

## Gotchas (learned the hard way, 2026-08-04)

1. **Stale `__pycache__` survives refactors.** Because `/app` is a live bind mount, editing a
   `.py` file is *usually* enough — but leftover `.pyc` files from before a big rename/refactor
   can get treated as up to date and keep executing old logic even after a restart. If behavior
   doesn't match what the source says it should, clear `__pycache__` everywhere and restart.
   Verify what's actually loaded with:
   `docker exec <c> python3 -c "import inspect,<mod>; print(inspect.getsource(<mod>.<fn>))"`

2. **Check for phantom duplicate deployments before assuming a bug is "still not fixed."**
   `centinela_db` is shared across servers. A second, orphaned copy of this whole stack ran on
   `10.4.3.208` for 4+ days after this repo was migrated to its current host, silently
   corrupting shared data no matter what got fixed here. If a bug persists despite a verified,
   in-memory-confirmed clean fix, check `SELECT pid, client_addr, query FROM pg_stat_activity
   WHERE datname='centinela_db'` for a `client_addr` you don't recognize.

3. **`vulnerability_log` has no unique constraint** beyond the `id` primary key. Any insert
   path that doesn't explicitly dedupe by `(asset_id, cve_id)` before inserting will happily
   create infinite duplicates on every scan cycle. `ON CONFLICT DO NOTHING` without a matching
   constraint is a silent no-op, not a safety net.

4. **`/api/inventory`'s vulnerability count must use `COUNT(DISTINCT v.id)`**, not `COUNT(v.id)`
   — the query LEFT JOINs `vulnerability_log` to both `remediation_history` and
   `runtime_alerts`, and a plain `COUNT` gets inflated/distorted by that fan-out.

5. **Per-container env vars, not just `.env`.** `docker-compose.yml` explicitly lists env vars
   per service; a var only being set for one service (e.g. `NEO4J_URI` was only on
   `centinela-ai`, not `centinela-backend`) silently breaks that *other* service even though
   `.env` "has it."

## Known open issues (as of 2026-08-04)

- **Vault is sealed.** The auto-unsealer on 10.4.3.208 (`casmarts-core-vault-unsealer`) is
  running but its baked-in `VAULT_UNSEAL_KEY` doesn't match Vault's storage anymore (cipher
  auth failure). A candidate key file exists at
  `/opt/ecosistema-casmarts/core-casmarts/vault/vault-init-keys.txt` on 10.4.3.208 — reading it
  requires explicit user involvement (it's a raw secrets file). Until unsealed, "Vault Creds"
  will show "No" for every asset regardless of what's configured.
- ~~Several inventory assets point at unreachable IPs~~ — **resolved 2026-08-04**: `sf_sigeti_superset`
  (10.4.3.17), `casmart_ia` (10.4.3.28), `CLONE-COMPRAMEX-DIGITAL` (10.4.3.200),
  `CLONE-COMPRAMEX-DIGITAL-BD` (10.4.3.201), `CLONE-PMCP-BD` (10.4.3.205), `CLONE-SICOPA-BD`
  (10.4.3.207) were confirmed dead by both ICMP and TCP and removed from `infra_inventory`
  (with their findings/remediation rows) at the user's request — those IPs no longer exist.
  `10.4.3.51` (pmcp) was also removed from `inventory.ini`'s `[casmarts_nodes]` group for the
  same reason.
- **`auditor_medusa.py`'s CLI flags** (`--no-ai-safe`, `echo "yes" | medusa scan ...`) were
  written against an assumed interactive-confirmation behavior; the `medusa-security` PyPI
  package's documented flags don't obviously include either. Worth a real test run once medusa
  is actually invoked against a repo, since it may silently fail today.
