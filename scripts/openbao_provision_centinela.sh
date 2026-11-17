#!/usr/bin/env bash
# Provisions Centinela's own OpenBao token (Vault was replaced by OpenBao 2.7.2 on the identity host, ADR 0006 of
# core-org). The old `hvs.` Vault token is rejected by the new cluster ("permission denied" in every service log).
#
# Follows the server's own rule (core-org/openbao/OPENBAO_GUIA_INTERNA.md): one token per service with a scoped
# policy; the root token is only for administration and never leaves that host.
#
# What it does (run it from the Centinela host, as the owner):
#   1. On the OpenBao host, with the root token read there from core-org/.env (never printed, never copied here):
#      - makes sure the `secret/` mount is KV v2,
#      - writes the policy `centinela` (CRUD on secret/data/<prefix>/*, list/read/delete on secret/metadata/<prefix>/*),
#      - creates an orphan periodic token (renewable forever while Centinela renews it; period 768h),
#      - reports how many secret NAMES exist under <prefix>/ and <prefix>/ansible/ (names only, never values).
#   2. Here: writes the new token into .env as VAULT_TOKEN (the previous value is kept in .env.bak-openbao, mode 600).
#
# Nothing is printed except counts and status. Afterwards the Python services must be RECREATED to read the new .env:
#   docker compose up -d centinela-ai centinela-backend centinela-sentinel
# (that wipes the GitLab clones in centinela-ai's /tmp; the next scans re-clone them).
#
# Usage:  bash scripts/openbao_provision_centinela.sh [ssh_target]      default: authentik@192.0.2.20
set -euo pipefail

TARGET="${1:-authentik@192.0.2.20}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
KEY="$REPO/keys/org.key"
PREFIX="$(grep -E '^VAULT_NAMESPACE=' "$REPO/.env" | cut -d= -f2- | tr -d '"'"'" | sed 's#/*$##')"
PREFIX="${PREFIX:-centinela}"

REMOTE_OUT="$(ssh -i "$KEY" -o ConnectTimeout=15 "$TARGET" PREFIX="$PREFIX" bash -s <<'REMOTE'
set -euo pipefail
cd /opt/ecosystem/core-org
BAO_TOKEN="$(grep -E '^OPENBAO_ROOT_TOKEN=' .env | cut -d= -f2- | tr -d '"'"'")"
export BAO_TOKEN
[ -n "$BAO_TOKEN" ] || { echo "ERROR: OPENBAO_ROOT_TOKEN no está en core-org/.env" >&2; exit 2; }
# Never `docker exec -i` by default: this script itself arrives on stdin (`bash -s`), and an attached stdin swallows the
# rest of it, so the remote session ended silently after the first call. Only `Bi` (policy text on its own heredoc) attaches stdin.
B()  { docker exec    -e BAO_TOKEN -e BAO_ADDR=http://127.0.0.1:8200 org-core-openbao bao "$@" </dev/null; }
Bi() { docker exec -i -e BAO_TOKEN -e BAO_ADDR=http://127.0.0.1:8200 org-core-openbao bao "$@"; }

ver="$(B secrets list -format=json | python3 -c 'import sys,json;d=json.load(sys.stdin).get("secret/");print("none" if not d else (d.get("options") or {}).get("version","1"))')"
if [ "$ver" = "none" ]; then
  B secrets enable -path=secret -version=2 kv >/dev/null; echo "INFO: montaje secret/ creado (KV v2)" >&2
elif [ "$ver" != "2" ]; then
  echo "ERROR: secret/ existe pero es KV v$ver; Centinela usa KV v2. No se modifica." >&2; exit 3
fi

Bi policy write centinela - >/dev/null <<POLICY
# Centinela-AI (192.0.2.17): only its own prefix of the KV v2 mount.
path "secret/data/${PREFIX}/*"     { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/${PREFIX}/*" { capabilities = ["read", "list", "delete"] }
path "secret/metadata/${PREFIX}"   { capabilities = ["list"] }
POLICY
echo "INFO: política 'centinela' escrita (prefijo ${PREFIX}/)" >&2

n_all="$(B kv list -format=json -mount=secret "$PREFIX" 2>/dev/null | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' || echo 0)"
n_ans="$(B kv list -format=json -mount=secret "$PREFIX/ansible" 2>/dev/null | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' || echo 0)"
echo "INFO: nombres bajo ${PREFIX}/: ${n_all}; bajo ${PREFIX}/ansible/: ${n_ans}" >&2

tok="$(B token create -orphan -policy=centinela -period=768h -display-name=centinela-ai -field=token)"
printf 'TOKEN:%s\n' "$tok"
REMOTE
)"

NEW="$(printf '%s\n' "$REMOTE_OUT" | sed -n 's/^TOKEN://p' | head -1)"
[ -n "$NEW" ] || { echo "ERROR: no se obtuvo token (la sesión remota no devolvió TOKEN:; revise los mensajes INFO/ERROR de arriba)" >&2; exit 4; }

umask 077
cp "$REPO/.env" "$REPO/.env.bak-openbao"
NEW_TOKEN="$NEW" python3 - "$REPO/.env" <<'PY'
import os, re, sys
p = sys.argv[1]
s = open(p).read()
line = "VAULT_TOKEN=" + os.environ["NEW_TOKEN"]
s = re.sub(r"(?m)^VAULT_TOKEN=.*$", line, s) if re.search(r"(?m)^VAULT_TOKEN=", s) else s.rstrip("\n") + "\n" + line + "\n"
open(p, "w").write(s)
PY
chmod 600 "$REPO/.env" "$REPO/.env.bak-openbao"

CA="$REPO/keys/org-internal-ca.pem"   # OpenBao is reached over HTTPS (vault.example.internal) signed by this internal CA
CURL_CA=(); [ -f "$CA" ] && CURL_CA=(--cacert "$CA")
if curl -sf -m 10 "${CURL_CA[@]}" -H "X-Vault-Token: $NEW" "$(grep -E '^VAULT_ADDR=' "$REPO/.env" | cut -d= -f2-)/v1/auth/token/lookup-self" >/dev/null; then
  echo "OK: token nuevo escrito en .env y aceptado por OpenBao (política centinela, periodo 768h)."
else
  echo "AVISO: el token se escribió pero lookup-self falló; revise VAULT_ADDR." >&2
fi
echo "Siguiente paso: docker compose up -d centinela-ai centinela-backend centinela-sentinel"
