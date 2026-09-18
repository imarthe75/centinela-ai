#!/usr/bin/env bash
# =====================================================================================
# Centinela-AI repo sync helper
# =====================================================================================
# This host runs on the local-only `deploy/setag.mx` branch: it is `origin/master` plus
# one deploy commit (docker-compose.override.yml, ARM Dockerfile, reconstructed schema,
# nginx config...). Sync = pull the latest upstream code and replay the deploy commit
# on top, so env-specific config never diverges from the real code.
#
# Auth: git's `store` credential helper. The PAT lives in
#   /home/ubuntu/.git-credentials
# as one line (mode 600, NOT in the repo):
#   https://imarthe75:<GITHUB_PAT>@github.com
# Create it once:
#   printf 'https://imarthe75:%s@github.com\n' '<PAT>' > /home/ubuntu/.git-credentials
#   chmod 600 /home/ubuntu/.git-credentials
#
# Usage:
#   scripts/sync-repo.sh            # fetch origin, rebase deploy branch on origin/master
#   scripts/sync-repo.sh --restart  # ...then clear __pycache__ and restart the services
#   scripts/sync-repo.sh --push     # force-push the rebased deploy branch to origin
#                                   #   (only if you actually want it on the remote)
# =====================================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

UPSTREAM="${CENTINELA_UPSTREAM:-origin/master}"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
DO_PUSH=0
DO_RESTART=0
for arg in "$@"; do
  case "$arg" in
    --push) DO_PUSH=1 ;;
    --restart) DO_RESTART=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

echo "[sync] repo=$REPO_DIR branch=$BRANCH upstream=$UPSTREAM  $(date -Is)"

if [ ! -f /home/ubuntu/.git-credentials ]; then
  echo "[sync] ERROR: /home/ubuntu/.git-credentials not found -- add the GitHub PAT first (see header)." >&2
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "[sync] ERROR: working tree is dirty. Commit or stash before syncing." >&2
  git status --short >&2
  exit 1
fi

BEFORE="$(git rev-parse HEAD)"
git fetch --prune origin

if git merge-base --is-ancestor "$UPSTREAM" HEAD; then
  echo "[sync] already contains $UPSTREAM -- nothing upstream to replay."
else
  echo "[sync] rebasing $BRANCH onto $UPSTREAM ..."
  git rebase "$UPSTREAM"
fi
AFTER="$(git rev-parse HEAD)"

if [ "$DO_PUSH" -eq 1 ]; then
  echo "[sync] force-pushing $BRANCH -> origin (rebased history) ..."
  git push --force-with-lease origin "$BRANCH"
fi

if [ "$BEFORE" != "$AFTER" ]; then
  echo "[sync] updated: $BEFORE -> $AFTER"
  git --no-pager log --oneline "$BEFORE..$AFTER" 2>/dev/null | sed 's/^/[sync]   /' || true
  if [ "$DO_RESTART" -eq 1 ]; then
    echo "[sync] clearing __pycache__ and restarting Python services (stale-bytecode gotcha)"
    find "$REPO_DIR" -iname '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
    docker restart centinela-ai centinela-backend centinela-sentinel || true
  fi
else
  echo "[sync] no changes."
fi
echo "[sync] done."
