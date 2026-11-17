import pytest

from core import agent_ledger


def pytest_configure(config):
    """Fail closed (ADR-0008 #7): the suite must never touch the production database. Run it with scripts/run_tests.sh, which
    points it at the disposable centinela-test-db container. Set CENTINELA_ALLOW_PROD_DB_TESTS=1 only as a conscious override."""
    import os
    from core import db_manager
    import pytest as _pytest
    name = db_manager.DB_CONFIG.get("database")
    if name != "centinela_test" and os.getenv("CENTINELA_ALLOW_PROD_DB_TESTS") != "1":
        _pytest.exit(
            f"Refusing to run: tests would use database '{name}' on '{db_manager.DB_CONFIG.get('host')}'. "
            "Use scripts/run_tests.sh (disposable test DB).", returncode=2)


@pytest.fixture()
def capture_ledger(monkeypatch):
    """Capture agent_ledger.record_action calls instead of writing test rows into the real
    production ledger (found polluting it on 2026-09-23)."""
    calls = []

    def fake(action_type, summary, **kw):
        calls.append({"action_type": action_type, "summary": summary, **kw})
        return -1

    monkeypatch.setattr(agent_ledger, "record_action", fake)
    return calls


@pytest.fixture(scope="session", autouse=True)
def _core_schema():
    """Tests exercise real tables; make sure code-defined schema (core/schema.py) is applied."""
    from core import db_manager
    from core.schema import ensure_core_schema
    with db_manager.get_db_cursor() as cur:
        ensure_core_schema(cur)


@pytest.fixture(scope="session", autouse=True)
def _seed_test_assets(_core_schema):
    """Minimal inventory for the disposable test DB (ADR-0008 #7). Several tests used to borrow whatever real asset happened to be in
    production; the test DB starts empty, so seed a few clearly-fake assets here. Only ever runs against `centinela_test`."""
    from core import db_manager
    if db_manager.DB_CONFIG.get("database") != "centinela_test":
        return
    assets = [
        ("GitLab/proyecto-g/frontend/frontend-proyecto-g", "GitLab-Repo", "http://gitlab.test/proyecto-g/frontend/frontend-proyecto-g"),
        ("GitLab/otros/proyecto-de-prueba", "GitLab-Repo", "http://gitlab.test/otros/proyecto-de-prueba"),
        ("servidor-de-pruebas", "SERVER", "192.0.2.27"),
    ]
    with db_manager.get_db_cursor() as cur:
        ids = {}
        for name, atype, endpoint in assets:
            cur.execute("SELECT id FROM infra_inventory WHERE asset_name = %s", (name,))
            row = cur.fetchone()
            if not row:
                cur.execute("""INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, status)
                               VALUES (%s, %s, %s, 'MEDIUM', 'monitored') RETURNING id""", (name, atype, endpoint))
                row = cur.fetchone()
            ids[name] = row[0]
        # one analysed finding on the proyecto-g asset, so the per-asset report has a real card to render
        cur.execute("SELECT 1 FROM vulnerability_log WHERE asset_id = %s AND cve_id = 'TEST-SEED-FINDING'", (ids[assets[0][0]],))
        if not cur.fetchone():
            cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, status, url_path, description, executive_summary,
                                                          business_impact, developer_steps, fingerprint_hash, detected_at, finding_category, scan_engine)
                           VALUES (%s, 'TEST-SEED-FINDING', 'HIGH', 'CORRELATED', 'src/app.ts:1', 'hallazgo sembrado para pruebas',
                                   'Resumen de prueba', 'Impacto de prueba', 'Pasos de prueba', 'test-seed-finding-fp', NOW(),
                                   'VULNERABILITY', 'sast-native')""", (ids[assets[0][0]],))


@pytest.fixture(autouse=True)
def _api_auth_off(monkeypatch):
    """The suite runs inside centinela-backend, which carries production's API_AUTH_MODE (enforce). Tests of other endpoints must not depend
    on it: authentication is off unless a test sets the mode itself (tests/test_api_auth.py, test_agent_install_command.py)."""
    monkeypatch.setenv("API_AUTH_MODE", "off")


# --- added by the public-release builder: tests that depend on what the sanitizing removes or rewrites ---
_PUBLIC_RELEASE_SKIPS = {'tests/test_ai_data_policy.py::TestClassifier::test_internal_signals': 'la copia pública reescribe las IP privadas de los ejemplos a IP de documentación (192.0.2.x), que no son internas', 'tests/test_runtime_and_dependency_audits.py::TestDependencyProbe::test_findings_severity_by_profile_and_secret_free': 'la copia pública reescribe las IP privadas de los ejemplos a IP de documentación (192.0.2.x)', 'tests/test_api_auth.py::test_docs_routes_serve_the_right_documents': 'los manuales (docs-public) son internos y no forman parte de la copia pública', 'tests/test_cmmi_evidence.py::TestOrgCollectorsAgainstThisRepository::test_pad_manifests_are_valid_in_this_repo': 'los manifiestos del generador de entregables son internos y no forman parte de la copia pública', 'tests/test_preflight_and_checklist.py::TestChecklistEvidence::test_counts_are_split_and_use_effective_severity': 'el checklist 0A-4 vive en el generador de entregables, interno y fuera de la copia pública', 'tests/test_no_org_names.py::TestNoOrganisationNames::test_source_and_readme_do_not_name_the_organisation': 'el depurado reescribe el nombre buscado; el constructor de la copia pública aplica esa misma revisión a todo el árbol'}


def pytest_collection_modifyitems(config, items):
    import pytest as _pytest
    for item in items:
        reason = _PUBLIC_RELEASE_SKIPS.get(item.nodeid)
        if reason:
            item.add_marker(_pytest.mark.skip(reason="copia pública: " + reason))
