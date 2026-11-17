# Dependency locks (ADR-0008 #6)

`ai.txt` (image `centinela-ai`/`centinela-sentinel`, Python 3.11) and `backend.txt` (image `centinela-backend`, Python 3.10) are the exact
`pip freeze` of the containers that were running and passing the test suite on 2026-10-05. The Dockerfiles install with `-c locks/<name>.txt`
(constraints), so a rebuild resolves to the same versions instead of whatever PyPI has that day (this is what once produced two different
versions of the same tool in two images and a semgrep<->cvss resolver loop).

To upgrade on purpose: rebuild WITHOUT the constraint in a scratch image, run `scripts/run_tests.sh`, then regenerate:
`docker exec <container> pip freeze | grep -v "^-e \| @ file://" > locks/<name>.txt`.

## CLI engines outside the locks (2026-11-05)

`semgrep`, `checkov` and `prowler` are NOT in these locks. Their latest releases pin mutually incompatible versions of shared
libraries (an unconstrained resolve downgraded semgrep 1.141 -> 1.52 and prowler 5.42 -> 5.9 to satisfy each other), and
Centinela only runs them as commands. Each lives in its own virtualenv (`/opt/tools/<name>`, symlinked into `/usr/local/bin`)
with the exact version pinned in the Dockerfile. To upgrade one, change its `==` there and rebuild.

When regenerating these locks, resolve with every current version as a FLOOR (`name>=x` constraints) so nothing silently
downgrades, then compare old vs new before committing. Packages the code imports directly must be declared (in
`requirements.txt` / the Dockerfile list), not left to arrive as someone else's dependency: `python-multipart`, `dnspython`
and `xlsxwriter` were only present through semgrep/prowler/mcp until this change.
