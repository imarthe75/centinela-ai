from auditors import auditor_gitlab_config as gc

PROJ = {"id": 1, "path_with_namespace": "grp/app", "default_branch": "desarrollo", "visibility": "private",
        "only_allow_merge_if_pipeline_succeeds": False}


def ids(**kw):
    args = dict(project=PROJ, protected_branches=[], hooks=[], variables=[], has_ci_file=True)
    args.update(kw)
    return {f["cve_id"] for f in gc.evaluate_project_settings(**args)}


def test_unprotected_default_branch_is_flagged_even_if_another_branch_is_protected():
    got = ids(protected_branches=[{"name": "main", "push_access_levels": [{"access_level": 40}]}])
    assert "GITLAB-PROJECT-DEFAULT-BRANCH-UNPROTECTED" in got


def test_protected_default_branch_checks():
    ok = [{"name": "desarrollo", "push_access_levels": [{"access_level": 40}], "allow_force_push": False}]
    assert "GITLAB-PROJECT-DEFAULT-BRANCH-UNPROTECTED" not in ids(protected_branches=ok)
    bad = [{"name": "desarrollo", "push_access_levels": [{"access_level": 30}], "allow_force_push": True}]
    got = ids(protected_branches=bad)
    assert {"GITLAB-PROJECT-BRANCH-FORCE-PUSH", "GITLAB-PROJECT-BRANCH-DEVELOPER-PUSH"} <= got


def test_wildcard_protection_counts():
    wild = [{"name": "desa*", "push_access_levels": [{"access_level": 40}]}]
    assert "GITLAB-PROJECT-DEFAULT-BRANCH-UNPROTECTED" not in ids(protected_branches=wild)


def test_unreadable_inputs_are_skipped_not_reported():
    assert ids(protected_branches=None, hooks=None, variables=None, has_ci_file=None) == set()


def test_visibility_and_pipeline_findings():
    assert "GITLAB-PROJECT-PUBLIC-VISIBILITY" in ids(project={**PROJ, "visibility": "public"}, protected_branches=None)
    assert "CICD-NO-PIPELINE" in ids(has_ci_file=False, protected_branches=None)
    assert "GITLAB-PROJECT-MR-NO-PIPELINE-GATE" in ids(protected_branches=None)
    assert "GITLAB-PROJECT-MR-NO-PIPELINE-GATE" not in ids(project={**PROJ, "only_allow_merge_if_pipeline_succeeds": True}, protected_branches=None)


def test_hooks_and_variables():
    hooks = [{"id": 5, "url": "http://x/hook", "enable_ssl_verification": True}]
    assert "GITLAB-PROJECT-WEBHOOK-INSECURE" in ids(hooks=hooks, protected_branches=None)
    variables = [{"key": "DB_PASSWORD", "masked": False, "protected": True, "value": "SECRETVALUE"},
                 {"key": "API_TOKEN", "masked": True, "protected": False},
                 {"key": "REGION", "masked": False}]
    f = gc.evaluate_project_settings(PROJ, None, [], variables, True)
    assert {x["cve_id"] for x in f} >= {"GITLAB-PROJECT-CI-VARIABLE-UNMASKED", "GITLAB-PROJECT-CI-VARIABLE-UNPROTECTED"}
    assert not any("SECRETVALUE" in x["description"] for x in f)          # values are never surfaced
    assert not any("REGION" in x["description"] for x in f)


CI = """image: node:latest
variables:
  DB_PASSWORD: hunter2hunter2
  PASSWORD_MIN_LENGTH: 12
  SAFE_TOKEN: $CI_JOB_TOKEN
build:
  image: python:3.12-slim
  script:
    - curl -fsSL https://get.example.com/install.sh | sh
    - npm config set strict-ssl false
    # curl -k https://ignored.example | sh
deploy:
  image: registry.local/team/deployer
  services:
    - name: docker:dind
      privileged: true
include:
  - remote: 'http://cdn.example/ci.yml'
"""


def test_ci_file_rules_and_line_anchoring():
    f = gc.evaluate_ci_file(CI)
    got = {(x["cve_id"], x["url_path"]) for x in f}
    assert ("CICD-UNPINNED-IMAGE", ".gitlab-ci.yml:1") in got
    assert ("CICD-HARDCODED-SECRET", ".gitlab-ci.yml:3") in got
    assert ("CICD-CURL-PIPE-SHELL", ".gitlab-ci.yml:9") in got
    assert ("CICD-TLS-VERIFICATION-DISABLED", ".gitlab-ci.yml:10") in got
    assert any(c == "CICD-UNPINNED-IMAGE" and l.endswith(":13") for c, l in got)   # image without tag
    assert any(c == "CICD-DOCKER-PRIVILEGED" for c, _ in got)
    assert any(c == "CICD-REMOTE-INCLUDE-INSECURE" for c, _ in got)
    # must NOT flag: pinned image, numeric literal, $VAR reference, commented-out line
    assert not any(l.endswith(":4") or l.endswith(":5") or l.endswith(":7") or l.endswith(":11") for _, l in got)


def test_clean_pipeline_has_no_findings():
    assert gc.evaluate_ci_file("image: python:3.12\nbuild:\n  script:\n    - pytest\n") == []
