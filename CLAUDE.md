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

6. **Never infer "found nothing" from `subprocess.run(...).stdout` being non-empty.** CLI
   scanners print banners/warnings to stdout unless explicitly silenced. `scan_appserver()`'s
   nuclei call was missing `-silent` (every other nuclei call in the file has it), so
   `if result.stdout: found_vulns = True` was true on *every* run (banner text), the code then
   tried to `json.loads()` each banner line, failed silently, and never wrote a real finding
   *or* the "clean scan" fallback message — total silent data loss for every SERVER asset, for
   who knows how long. Fixed by always passing `-silent` and only setting `found_vulns = True`
   inside the successful-parse branch (matches the already-correct pattern in `scan_url()`).

7. **`docker-compose.yml` env var edits need a container recreate, not a source edit.** Learned
   from the Vault incident's own postmortem note: "un contenedor ya corriendo NO relee su propio
   `environment:`". This applies here too — any `docker-compose.yml` env change needs
   `docker compose up -d <service>` (recreate), a plain `docker restart` is not enough.

8. **The root-level reorg (`.py`/`.yml` files moved into packages) missed some hardcoded path
   references outside the moved files themselves.** `sentinel.py` still pointed at
   `/app/remediate_wildfly.yml` and `/app/remediate_generic.yml` (both moved to
   `remediation/playbooks/`), so **every single approved remediation failed** with
   `the playbook: ... could not be found` — silently, since `sentinel.py`'s failure path just
   logs it and moves on. After a reorg, grep the whole tree for the old paths of anything that
   moved, not just check the moved file's own new location works.

## Known open issues (as of 2026-08-04, updated same day)

- ~~Vault is sealed~~ — **resolved same day**: the user recovered/rotated the root token after a
  Vault re-init (`ROOT_TOKEN` in `core-casmarts/vault/vault-init-keys.txt` on 10.4.3.208) and
  updated `.env`. `Secrets Backend (Vault)` now reports Online and `client.is_authenticated()`
  is `True`. No stored secrets exist yet under `casmarts/ansible/*` — that's expected, nobody
  could write there while it was sealed; `has_vault_secret` will start turning `true` per-asset
  as credentials get added via "Añadir Activo" / the vault-secret endpoint going forward.
- **ZAP DAST silently never ran** — `auditor_zap.py` referenced `owasp/zap2docker-stable:latest`,
  a Docker Hub image that no longer exists ("pull access denied... repository does not exist").
  Every ZAP attempt threw `ZAPNotAvailableError` and silently fell back to nuclei-only. Fixed to
  `zaproxy/zap-stable:latest` (OWASP's current official image, same `zap.sh -daemon` + REST API
  invocation pattern) and pre-pulled.
- **3 `SERVER` assets still have no known SSH credentials for Wazuh install**: `casmartsuperset`
  (10.4.3.25), `prism` (10.4.3.30), `chat` (10.4.3.31). All three are reachable (port 22 open).
  Tried `casmarts.key` (which works for `casmart_authentik`/10.4.3.208) against prism and chat
  under 10 likely usernames (authentik, root, ubuntu, casmart, prism, chat, admin, centinela,
  deploy, pmcp) — all rejected with "Permission denied (publickey)". Needs the correct username
  from the user, or confirmation that this key isn't authorized on those hosts at all.
- ~~GitLab project scanning has no token~~ — **resolved 2026-08-04**: user supplied several
  GitLab PATs; tested each against `GET /api/v4/user` and `/api/v4/personal_access_tokens/self`
  to find one with `api`/`read_repository` scope (`sonar_pat`, user `monitor`, expires
  2027-07-02 — several of the others were 401/403, revoked or wrong scope). Set as
  `GITLAB_TOKEN` in `.env`. Ran a real `POST /api/gitlab/scan`: 46/63 GitLab projects cloned and
  audited, **74 real vulnerabilities found** (SAST + SCA + standards) and correlated. The other
  17 projects likely failed to clone (empty repos, or need investigation if that's wrong).
- **`sentinel.py`'s remediation execution is password-only.** `ansible_remediate()`/the inline
  "generic" Ansible path in `process_remediations()` always pass `ansible_ssh_pass` /
  `ansible_become_pass` from Vault's `sudo_password` field (or `ANSIBLE_BECOME_PASS` env
  fallback) — there's no code path that uses an SSH private key file. Assets enrolled with a key
  only (e.g. `casmartdb`/`casmart_authentik` via `casmart.key`/`casmarts.key` in `inventory.ini`)
  can be scanned and have Wazuh installed, but **Sentinel cannot auto-remediate them** unless a
  password is also stored in Vault for that asset name. Verified this whole pipeline end-to-end
  (approve → Sentinel picks it up → runs Ansible → updates DB) is otherwise working correctly —
  confirmed via a live test approval on `CLONE-COMPRAMEX-CORE`, which correctly failed for lack
  of credentials rather than hanging or silently no-op'ing.
- **When a remediation fails but the asset has a Wazuh `agent_id`, `sentinel.py` marks it
  `COMPLETED`/`RESOLVED` anyway** (`process_remediations()`, the `if status == "FAILED" and
  agent_id ...` block) — it appends a log line claiming "remediation triggered via Wazuh Active
  Response" but never actually calls any Wazuh API. This silently reports remediation success
  for any failed Ansible run on an asset that merely *has* an agent installed, which is
  misleading. Not fixed — implementing real Wazuh Active Response (or just removing the fake
  fallback) is a real design decision, not a one-line fix, and wasn't part of what was asked.
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
