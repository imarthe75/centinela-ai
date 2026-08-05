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

- ~~AI remediation reports/scripts were generic instead of detailed~~ — **resolved same day**:
  `correlate_vulnerability()` in `centinela.py` only ever tried `genai_client` (Google, failing)
  and fell straight to the deterministic template — it never called `llm`, even though a
  provider (`nvidia_nim`) was successfully initialized at startup. Root cause was two bugs in
  provider selection: `AI_PROVIDER_ORDER`'s hardcoded default always tried `nvidia_nim` first
  regardless of `AI_PROVIDER=groq` in `.env`, and `nvidia_nim` reused `AI_MODEL` (a Groq-style
  name, `llama-3.3-70b-versatile`) that doesn't exist in NVIDIA's catalog, so it 404'd on every
  call. Fixed both, and added a real `llm.invoke()` middle tier before the template fallback.
  Verified live: findings now get genuinely differentiated output (e.g. a clean scan on `prism`
  correctly gets `can_automate=false` and a real summary, not the same firewall-hardening
  boilerplate every finding used to get regardless of type — that boilerplate had even been
  showing up on GitLab SAST findings, which makes no sense for a code repo).
- **When the LLM doesn't return strict JSON**, the existing prose-fallback regex parser in
  `correlate_vulnerability()` (`extract_section()`) sometimes produces thin/generic content
  because its label patterns (`**Riesgo detectado**`, etc.) don't match Groq's actual prose
  formatting in every case. Not fixed — would need inspecting real non-JSON Groq responses to
  tune the regexes, or tightening the prompt further to force JSON compliance.
- ~~Vault is sealed~~ — **resolved same day**: the user recovered/rotated the root token after a
  Vault re-init (`ROOT_TOKEN` in `core-casmarts/vault/vault-init-keys.txt` on 10.4.3.208) and
  updated `.env`. `Secrets Backend (Vault)` now reports Online and `client.is_authenticated()`
  is `True`. No stored secrets exist yet under `casmarts/ansible/*` — that's expected, nobody
  could write there while it was sealed; `has_vault_secret` will start turning `true` per-asset
  as credentials get added via "Añadir Activo" / the vault-secret endpoint going forward.
- ~~ZAP DAST silently never ran~~ — **resolved 2026-08-04, the hard way**. First layer:
  `auditor_zap.py` referenced `owasp/zap2docker-stable:latest`, a Docker Hub image that no
  longer exists, so every attempt threw `ZAPNotAvailableError` and silently fell back to
  nuclei-only. Fixing just the image to `zaproxy/zap-stable:latest` was nowhere near enough —
  live-testing a real scan end-to-end (`auditor_zap.run_zap_scan(...)`) surfaced **eight more
  real, independent bugs stacked on top of each other**, meaning ZAP had in all likelihood
  *never once* worked in this deployment. In the order they were found:
  1. `docker run` had no `-d` — it ran attached in the foreground, so the launch call just hung
     until its own 30s timeout on every single attempt, regardless of anything else.
  2. `-p {port}:8090` published to the wrong container-side port — this image listens on 8080,
     not 8090 (the old `zap2docker-stable` image's default).
  3. **Fundamental**: `docker run` here goes through the mounted `docker.sock`, which makes ZAP
     a *sibling* container on the host's Docker daemon, not a child of `centinela-ai`. A
     `-p host:container` mapping binds on the **real host's** interfaces — `localhost` from
     inside `centinela-ai` can never reach it, no matter what host port is used. Since both
     containers share `aura-network`, the fix is to address ZAP by its container name (Docker's
     built-in per-network DNS) instead of any `localhost:<port>` — dropped host port publishing
     entirely, everything now goes through `http://<container_id>:8080`.
  4. The addon/config cache volume was mounted at `/root/.zap/db`, but this image runs as uid
     1000 ("zap", `$HOME=/home/zap`) and downloads all its addons to `/home/zap/.ZAP/plugin/*`
     on every cold start — `/root/.zap/db` was never on this image's write path at all, so
     nothing was ever actually cached (~40s of addon downloads on *every* launch).
  5. Fixing the mount path to `/home/zap/.ZAP` then failed with "The home path is not
     writable": the bind-mount source is auto-created by the **host's** dockerd (owned by
     root) the first time it's referenced — another docker-outside-of-docker gotcha, since
     `os.makedirs()` from inside `centinela-ai` only touches *its own* filesystem, not the real
     host path `docker run -v` resolves against. Fixed by `chmod`-ing the mount source via a
     disposable `busybox` container before ever starting ZAP.
  6. Sharing one cache directory across concurrent scans then failed differently: "The home
     directory is already in use" — ZAP takes an exclusive lock on its home dir, so concurrent
     scans can't share a cache path at all. Switched to one subdirectory per scan (accepting the
     ~40s addon re-download per scan as a real characteristic of this tool, not a bug).
  7. ZAP bound its API to `127.0.0.1` inside its own container by default — its own Docker
     `HEALTHCHECK` (which `curl`s `localhost` from inside) reported "healthy" while every other
     container on `aura-network` got connection refused reaching it by name. Fixed with
     `-host 0.0.0.0`.
  8. Even reachable, ZAP separately rejected every request as "not permitted" — it allowlists
     API request origins by `Host` header independently of `api.disablekey`. Fixed with
     `-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true` (ZAP's documented way to
     permit any origin).
  9. The readiness probe itself called `core/**action**/version` — "version" is a **view**
     (read-only), not an action, in ZAP's API taxonomy, so it 400'd on literally every request,
     meaning the code could never detect ZAP was actually up even after fixes 1–8 landed.
  10. The active-scan call passed `scanPolicyName: context_config["profile"]` — our own internal
      profile names (`light`/`balanced`/etc., see `ZAPScanProfile`) aren't real ZAP scan-policy
      names (`"Default Policy"`, `"Pen Test"`, etc. — confirmed via
      `/json/ascan/view/scanPolicyNames/`), so every active scan failed with `does_not_exist`.
      Fixed by omitting the param entirely (ZAP falls back to its own default policy); our
      profiles still control timeout/depth/rule-count via `context_config` elsewhere.

  Verified with a real full scan end-to-end (`launch → spider → active scan → alerts →
  cleanup`) against a live target: completed in ~65s, spider found 3 URLs, active scan reached
  100% and returned a real (in this case empty) findings list — not a masked failure.
- ~~**11th ZAP bug, found incidentally while debugging Medusa**: every single ZAP finding was
  logged with the identical generic `cve_id` "ZAP-ZAP-UNKNOWN"~~ — **resolved 2026-08-05**.
  `retrieve_zap_alerts()` read `alert.get("pluginid", "ZAP-UNKNOWN")`, but ZAP's real REST API
  returns the key as `pluginId` (camelCase) — the lowercase lookup always missed, so every
  finding fell back to the same default, and `log_zap_findings()`'s own `f"ZAP-{code}"` prefix
  then doubled it to `ZAP-ZAP-UNKNOWN`. Confirmed via 180 already-logged real findings on
  `casmart_authentik`: `cweid`/`wascid` (correctly cased in the code) were populated on every
  single row, `pluginid` never was — 100% consistent with a pure key-casing miss, not missing
  data from ZAP. Also caused a secondary symptom that looked like a runaway loop: with 180
  distinct real findings all sharing one identifier, the AI correlation engine's log lines
  (`Senior Audit analysis for ZAP-ZAP-UNKNOWN on casmart_authentik...`) looked identical on every
  line even though it was correctly working through 180 distinct rows — pure log-message
  confusion caused by the same underlying bug, not an actual infinite loop. Fixed by reading
  `pluginId` first (falling back to the old lowercase key, then a bare `"UNKNOWN"` with no
  redundant prefix). The 180 already-logged rows keep their old generic `cve_id` — they're real,
  legitimate findings (confirmed 180/180 distinct URLs, not duplicate spam), just mislabeled;
  no safe way to backfill the real `pluginId` without re-scanning, and re-scanning `casmart_authentik`
  again wasn't attempted here (live active-scans need separate authorization each time). Left as
  a known cosmetic gap: those specific rows will keep their generic ID until next rescan.
- ~~`prism`/`chat` had no known SSH credentials~~ — **resolved 2026-08-04**: user supplied
  passwords for `kiwi@10.4.3.30` (prism) and `chatbotpdf@10.4.3.31` (chat) and authorized
  installing this server's own public key (already in this host's `~/.ssh/authorized_keys`,
  same key as `casmarts.key`/`casmart.key`, comment "CASmartS") onto any host missing it.
  Installed via `sshpass` + append to `~/.ssh/authorized_keys` on both. **Gotcha**: on `chat`
  the existing `authorized_keys` line had no trailing newline, so the naive append merged onto
  it and corrupted both keys — always `cat`/inspect the file after appending to a
  possibly-single-line `authorized_keys`, don't assume `echo ... >>` is safe. Fixed by inserting
  a newline between the two keys (backup left at `~/.ssh/authorized_keys.bak` on `chat`). Both
  hosts turned out to already have `wazuh-agent` preinstalled — just needed pointing at the
  manager and starting. Added to `inventory.ini` and Vault (`ssh_private_key`), verified active
  both locally (`systemctl is-active`) and from the manager (`agent_control -l`).
- ~~`casmartsuperset` had no known credentials~~ — **resolved 2026-08-04**: the username was
  literally `casmartsuperset` all along; the earlier failures were because the password has a
  trailing period (`gNng898u.`) that wasn't included in the first attempts. Installed the shared
  key, added to `inventory.ini`/Vault, and set up Wazuh. Its `ossec.conf` turned out to still be
  pointed at the old dead manager (`10.4.3.28`) from before this project's migration, and the
  manager had a **stale agent registration from an earlier silent self-enroll attempt** under
  the same name — `wazuh-agentd` kept cycling "Duplicate agent name" until that old registration
  was removed (`manage_agents -r`) and the agent's `client.keys` cleared to force a clean
  re-enrollment. All 7 SERVER assets now confirmed with an active Wazuh agent, both locally
  (`systemctl is-active`) and from the manager (`agent_control -l`).
- **`discovery.py`'s fuzzy asset-name matching produced a real false positive**: the Wazuh agent
  named `compramex` (an OS hostname) substring-matched a *GitLab repo* asset
  (`GitLab/edomex-casmart/compramex/...`, itself named after the same product) purely because
  the word "compramex" appears in both, wrongly tagging that repo with a Wazuh `agent_id`.
  Separately, the agent named `kiwi` (prism's real hostname) matched nothing at all since
  "kiwi" and "prism" share no substring, and would have created a duplicate asset on the next
  discovery run. Fixed by restricting the fuzzy tier to `SERVER`/`AppServer` assets with an
  agent name ≥5 chars — this closes the GitLab false-positive but **does not** fix the "hostname
  has zero lexical relation to the business name" case; that needs the hostname↔asset_id
  mapping captured at install time instead of guessed later from a name string.
- ~~GitLab project scanning has no token~~ — **resolved 2026-08-04**: user supplied several
  GitLab PATs; tested each against `GET /api/v4/user` and `/api/v4/personal_access_tokens/self`
  to find valid ones. First pass used `sonar_pat` (user `monitor`, `api`/`read_repository`
  scope) — 46/63 projects scanned, 74 vulnerabilities found. The other 17 turned out **not** to
  be empty repos: `git clone` on any of them returned a real `403 You are not allowed to
  download code from this project` — the `monitor` service account has no repository access to
  the entire `arquitectura/` GitLab group (it can list those projects via the API but not clone
  them). Confirmed `israelm`'s own personal token *can* clone them, switched `GITLAB_TOKEN` to
  that one, re-ran the scan: **59/59 projects scanned, 431 real vulnerabilities found**. Using a
  named admin's personal token for an automated integration isn't ideal long-term — cleaner fix
  would be granting the `monitor` service account Developer access to the `arquitectura/` group
  in GitLab and switching back, but that's a GitLab-side permission change, not a code fix.
- ~~`sentinel.py`'s remediation execution was password-only~~ — **resolved 2026-08-04**: added
  `get_ssh_private_key()` (reads the `ssh_private_key` field `store_vault_secret()` already
  wrote to `casmarts/ansible/{asset_name}`, which nothing previously read back). The generic
  Ansible path now writes it to a 0600 temp file and passes `ansible_ssh_private_key_file` when
  present, falling back to the password vars otherwise. Verified live: stored
  `casmart_authentik`'s real key in Vault via the actual `/api/inventory/{name}/vault-secret`
  endpoint, approved a real pending finding, and watched Sentinel authenticate with the key and
  mark it `COMPLETED`/`RESOLVED` — confirmed Authentik itself (`https://auth.casmart.internal`)
  stayed healthy (HTTP 302) afterward.
- ~~Failed remediations on Wazuh-enrolled assets were silently marked `COMPLETED`~~ — **resolved
  2026-08-04**: removed the `if status == "FAILED" and agent_id ...: status = "COMPLETED"`
  fallback in `process_remediations()` that faked a Wazuh Active Response call which never
  actually happened. Failures now stay `FAILED` (`executed_bool=False`,
  `vulnerability_log.status` stays whatever it was, never force-set to `RESOLVED`). Re-approving
  via the UI (`approval_token='APPROVED'`) makes Sentinel pick it up and retry — no separate
  "retry" mechanism was added since that already does the job. Verified live on
  `CLONE-COMPRAMEX-CORE` (no stored credentials): now correctly reports `FAILED`, not
  `COMPLETED`.
- ~~Several inventory assets point at unreachable IPs~~ — **resolved 2026-08-04**: `sf_sigeti_superset`
  (10.4.3.17), `casmart_ia` (10.4.3.28), `CLONE-COMPRAMEX-DIGITAL` (10.4.3.200),
  `CLONE-COMPRAMEX-DIGITAL-BD` (10.4.3.201), `CLONE-PMCP-BD` (10.4.3.205), `CLONE-SICOPA-BD`
  (10.4.3.207) were confirmed dead by both ICMP and TCP and removed from `infra_inventory`
  (with their findings/remediation rows) at the user's request — those IPs no longer exist.
  `10.4.3.51` (pmcp) was also removed from `inventory.ini`'s `[casmarts_nodes]` group for the
  same reason.
- ~~`auditor_medusa.py`'s CLI flags were unverified~~ — **resolved 2026-08-05**: ran
  `medusa scan --help` for real against the correctly-pinned version (see version-drift note
  below). `--no-ai-safe` does exist in `medusa-security` 2026.7.0 but is unrelated to prompts —
  it toggles payload obfuscation. `--no-install` doesn't exist in this version at all (it was
  seen during earlier ad-hoc testing against a different, unpinned resolve). Neither the old
  `echo "yes" | medusa scan ... --no-ai-safe` pattern nor a `--no-install` flag was ever the
  right fix. The actual fix needed **no special flag at all**: with no TTY attached (always true
  under `subprocess.run`), medusa auto-detects it can't prompt and prints "Non-interactive mode:
  continuing without optional tools." on its own. Command is now just
  `medusa scan "{repo_path}" --format json -o "{output_dir}"`. Also bumped the internal
  `subprocess.run(..., timeout=...)` from 300s to 900s — Medusa shells out to `trivy fs
  --scanners vuln,secret,misconfig` as a sub-process on top of its own ~45 analyzers, and a cold
  Trivy CVE-database download alone can eat the old 300s budget. Verified with a real scan
  against a cloned repo (`arquitectura/resident-agent-framework`) after clearing stale
  `__pycache__` in `centinela-backend` — a first verification attempt silently kept running the
  old 300s-timeout bytecode even after the source was edited (see stale-bytecode gotcha #1) and
  timed out at exactly 300.2s; clearing `__pycache__` and rerunning confirmed the live code
  actually reflects the fix. Even with the timeout raised and a clean environment, the scan
  still failed every time with the command as given — root-caused to **three more independent
  bugs**, found by testing the real end-to-end path instead of trusting the CLI help text:
  1. Medusa's own default multi-worker pool (`-w` auto-detects >1 workers) reliably crashed with
     a `BrokenPipeError` inside `multiprocessing.Pool` while sending a result back to the
     parent — reproduced consistently both under heavy host load (see below) and on an idle
     host, so it's a real bug in this version's worker-pool IPC, not resource starvation. Fixed
     by forcing `-w 1` (single worker, no pool) — same repo then scanned cleanly in ~9s.
  2. Medusa 2026.7.0 always writes a second, unrelated `scan_history.json` (a JSON *list*, not a
     report) alongside the real report, and the real report's filename is timestamped
     (`medusa-scan-YYYYMMDD-HHMMSS.json`), not the fixed `medusa-report.json`/`report.json` the
     original code assumed. Picking "the first `*.json` file in the directory listing" is
     non-deterministic and grabbed `scan_history.json` on a real run, crashing with `'list'
     object has no attribute 'get'` when the code tried `data.get("findings", [])`. Fixed by
     explicitly excluding `scan_history.json` from the candidate list.
  3. `cve_id` was built with Python's built-in `hash()` on `file_path + str(line)` —
     **`hash()` on strings is randomized per process** (`PYTHONHASHSEED`, unset here) by design,
     confirmed live: the same string produced two different hash values across two separate
     `python3` invocations in the same container. That means the exact same finding got a
     *different* `cve_id` every time `centinela-backend` restarted, silently defeating
     `log_vulnerability()`'s dedupe-by-`(asset_id, cve_id)` check and re-inserting every
     previously-seen Medusa finding as "new" on every restart — the same duplicate-flooding
     failure mode as the original PROWLER-AUDIT bug, just via non-deterministic ID generation
     instead of a missing dedupe check. Fixed with `hashlib.sha256(...).hexdigest()[:8]`
     (deterministic across runs), and also stripped a redundant `MEDUSA-` prefix from
     `rule_id` before building `cve_id` (Medusa's own rule IDs are already `MEDUSA-`-prefixed,
     e.g. `MEDUSA-GENAI-SCAN-134`, which was doubling up to `MEDUSA-MEDUSA-GENAI-SCAN-134-...` —
     the same cosmetic bug class as the ZAP `pluginId` fix below). Verified: rerunning the same
     scan twice produced 21/21 `🔄 Updated` (not `📝 Logged`) on the second pass, confirming the
     hash is now stable and dedupe actually works.

  While debugging the `BrokenPipeError` under load, also found and cleaned up **three leftover
  `zap-scan-*` test containers** from the ZAP verification above that were never actually torn
  down (one had been running for 40+ minutes) — real resource waste, and a contributing factor
  to the host's load average hitting 76 (8 CPUs) during testing. **Separately found real version
  drift**: `centinela-ai`'s image had
  `medusa-security 2026.7.0`, `centinela-backend`'s had `2025.8.5.4` (11 months older, different
  incompatible flags) even though both Dockerfiles installed it "unpinned" around the same
  time — pip resolved differently per build. Pinned `medusa-security==2026.7.0` in both
  `requirements.txt` and the main `Dockerfile`'s pip list so this can't silently drift again;
  rebuilt both images.
- **AI remediation scripts were cosmetic across most of the finding taxonomy** — **resolved
  2026-08-05**, in response to real user-reported examples (a `DOCKER-MISSING-NON-ROOT-USER`
  "fix" that only printed a warning and created an unrelated local Linux user, never touching
  the actual Dockerfile). Root cause was architectural: **all** `sast-native`/`sca-native`/
  `standards-audit` findings (~517 rows — `CODE-INJECTION-EVAL`, `HARDCODED-SECRET`,
  `DOCKER-MISSING-NON-ROOT-USER`, `SCA-CVE-*`, `STD-*`, `COGNITIVE-*`, `CMD`/`SQL`/`SSRF-*`) live
  on `asset_type = 'GitLab-Repo'` assets — there is no live host to SSH into and "harden"; the
  real fix is a code change in the repo itself. `sentinel.py`'s only execution path was Ansible
  SSH (`asset_ip` for these rows is actually the repo's `web_url`, not an IP — every approval
  would have failed at the Ansible connection step, or worse, silently done nothing relevant if
  it somehow connected to a *different* host that happened to share the IP octets). Fixed in
  several parts:
  1. `remediation/gitlab_autofix.py` was **already wired to a real endpoint**
     (`POST /api/gitlab/autofix/{vuln_id}` in `main.py`, just never called from the frontend)
     but was non-functional end-to-end: referenced `re` without importing it, never cloned or
     edited anything, and called GitLab's MR API with a `source_branch` that was never pushed
     (which GitLab has always rejected — you cannot open an MR from a branch that doesn't
     exist). Rewritten with real `git clone` → apply fix → `git commit`/`push` to a new
     `centinela-fix/*` branch → open Merge Request (never a direct push to the default branch).
     Also fixed `project_id` defaulting to a hardcoded `1` regardless of which repo the
     vulnerability actually belonged to — now resolved from the vuln's own asset via GitLab's
     path-based project lookup.
  2. Added two **deterministic** patchers (no LLM needed, mechanical and safe):
     `DOCKER-MISSING-NON-ROOT-USER`/`DOCKER-ROOT-USER` (adds/fixes a real `USER` directive in
     the Dockerfile) and `SCA-CVE-*` (bumps the vulnerable package to the known-fixed version in
     `requirements.txt`/`package.json`, using the `fixed_version` `auditor_sca_dependencies.py`
     already computes from its `KNOWN_VULNERABLE_PACKAGES` table but never surfaced anywhere).
     Verified live on a disposable throwaway GitLab project created and destroyed for this
     purpose (never touched a real scanned repo): both produced a real, correctly-scoped MR with
     exactly the expected one-line diff.
  3. For findings that need real code understanding (`CODE-INJECTION-EVAL`, `HARDCODED-SECRET`,
     `CMD`/`SQL`/`SSRF-*`), `correlate_vulnerability()` now asks the LLM for a `fix_patch`
     (unified diff, using the file/line/snippet now available — see the file-path fix below) —
     stored in `vulnerability_log.fix_patch` (an existing, previously entirely unused column) —
     instead of a nonsensical bash "remediation_script". `gitlab_autofix.py` applies it with
     `git apply` through the same clone/branch/push/MR pipeline as the deterministic patchers.
     Verified the full JSON-parsing → `fix_patch` extraction → `git apply` → MR chain live with
     a realistic mocked LLM response (Groq's daily token quota was still exhausted at test time,
     see the AI-provider entry above, so the real end-to-end LLM call itself couldn't be
     exercised today) — a real `git diff`-generated patch applied and opened a correct MR.
  4. `can_automate` was previously **hardcoded to `True`** in the heuristic fallback path and
     **hardcoded to `False`** (discarding whatever the LLM actually said) in the main JSON-parse
     path — neither reflected reality. Added `heuristic_can_automate()` (mirrors
     `generate_heuristic_script()`'s own branches) and made the JSON path respect the LLM's own
     `can_automate` while still requiring real output (a patch or a script) to ever be `True`.
  5. `STD-ISO25010-LONG-METHOD`/`COGNITIVE-COMPLEXITY-EXCEEDED` (code-quality findings, 267 rows
     combined) and non-vulnerability status messages (`SCAN-AUDIT` — "no vulnerabilities found"/
     "scan skipped"; `HEURISTIC-SECURITY-DEBT` — an aggregate meta-finding) now get an honest
     "no automated fix, here's why" message instead of a fake success script. `SCAN-AUDIT` was
     previously keyword-matched into the **firewall-lockdown branch** (`ufw default deny
     incoming` + allow only 22/80/443) — meaning approving a finding that literally says "no
     vulnerabilities found" would have applied a deny-all firewall policy to a perfectly healthy
     host for no reason. Fixed.
  6. **Separately found and fixed, incidentally, while building this**: `auditor_master_vulnerabilities.py`/
     `auditor_sca_dependencies.py`/`auditor_compliance_standards.py` (the `sast-native`/
     `sca-native`/`standards-audit` engines) captured `file`/`line` on every finding but never
     actually persisted them anywhere — the `INSERT` only carried `cve_id`/`severity`/
     `description`, so no remediation (human or AI) could ever know which file to fix. Now
     stored in `url_path` as `relative/path:LINE` (reusing the same generic "where this finding
     lives" column `auditor_zap.py` already uses for URLs) and prefixed into `description`. Same
     three files also had the exact `ON CONFLICT DO NOTHING`-with-no-real-constraint bug as the
     Medusa/PROWLER-AUDIT cases above (see gotcha #3) — every re-scan of the GitLab org
     re-inserted every finding as brand new. Fixed with the same explicit
     SELECT-then-UPDATE/INSERT dedupe pattern already working in `auditor_zap.py`.
  7. **Also found, while investigating why `CODE-INJECTION-EVAL` "fixes" made no sense**: the
     detection regex `r'eval\s*\('` had no word boundary and (with `re.IGNORECASE`) matched the
     substring "Eval(" inside *any* longer identifier — e.g. `this.onErrorEval(err)` was flagged
     as a dangerous `eval()` call. Confirmed against real production data: **136 of 140** logged
     `CODE-INJECTION-EVAL` findings were exactly this false positive, not an actual `eval()`
     call. Fixed with `r'\beval\s*\('`.
  8. Real ZAP DAST findings (641 rows, on real reachable `SERVER` assets — genuinely
     automatable, unlike the GitLab-Repo cases above) got a real nginx security-header
     remediation generator (`generate_zap_header_fix()` in `centinela.py`) covering the standard
     header findings actually present in production (`X-Content-Type-Options`,
     `Strict-Transport-Security`, `X-Frame-Options`, CSP, `X-Powered-By`/`Server` leaks,
     Cache-Control, Permissions-Policy, Referrer-Policy). Detects nginx at the system level
     first, then falls back to detecting a **containerized** nginx reverse-proxy (confirmed live
     on `casmart_authentik`: no system nginx, but a `nginx:alpine` gateway container fronting
     it) — and within that, detects whether `/etc/nginx/conf.d` is writable inside the container
     or only via its host-side bind-mount source (confirmed live: `casmart_authentik`'s gateway
     mounts `conf.d` **read-only** in-container from
     `/opt/ecosistema-casmarts/core-casmarts/gateway/conf.d` on the host — a deliberate, common
     hardening pattern). Writes an idempotent, additive-only snippet file (never touches
     existing vhost configs), validates with `nginx -t` before reloading, and verifies the
     header is actually present in a live response afterward. **Not live-tested end-to-end**:
     the final apply-and-reload step is a live write to `casmarts-core-gateway`, which is shared
     infrastructure fronting several other apps (`admin.conf`/`apps.conf`/`auth.conf`/
     `axioma.conf`/`core.conf`/`lexivault.conf`/`oidc.conf`/`projects.conf`) outside this repo's
     own footprint — blocked by the permission classifier as a live shared-infra write; the
     script's *logic* was validated against the real host structure via read-only inspection
     (real bind-mount path, real container name, real absence of system nginx), but the actual
     apply-and-verify run needs to happen via a real approval in the SOAR UI.
