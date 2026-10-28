# Dependency locks (ADR-0008 #6)

`ai.txt` (image `centinela-ai`/`centinela-sentinel`, Python 3.11) and `backend.txt` (image `centinela-backend`, Python 3.10) are the exact
`pip freeze` of the containers that were running and passing the test suite on 2026-10-05. The Dockerfiles install with `-c locks/<name>.txt`
(constraints), so a rebuild resolves to the same versions instead of whatever PyPI has that day (this is what once produced two different
versions of the same tool in two images and a semgrep<->cvss resolver loop).

To upgrade on purpose: rebuild WITHOUT the constraint in a scratch image, run `scripts/run_tests.sh`, then regenerate:
`docker exec <container> pip freeze | grep -v "^-e \| @ file://" > locks/<name>.txt`.
