"""API contract drift: route extraction per framework, path normalisation/suffix tolerance, and the repo-level rules with negative cases."""
import json
import os
import tempfile
import unittest

from auditors import auditor_api_contract as A

SPRING = '''
@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {
    @GetMapping
    public List<U> all() { return null; }
    @GetMapping("/{id}")
    public U one(@PathVariable Long id) { return null; }
    @PostMapping(value = "/buscar")
    public List<U> search() { return null; }
    @RequestMapping(value = "/viejo", method = RequestMethod.DELETE)
    public void old() {}
    @RequestMapping("/ambiguo")
    public void amb() {}
}
'''


class TestExtraction(unittest.TestCase):
    def test_spring_class_prefix_verbs_and_params(self):
        got = sorted(A.routes_spring(SPRING))
        self.assertEqual(got, sorted([("GET", "/api/usuarios"), ("GET", "/api/usuarios/{}"), ("POST", "/api/usuarios/buscar"), ("DELETE", "/api/usuarios/viejo")]))   # bare @RequestMapping skipped

    def test_spring_without_controller_annotation_has_no_routes(self):
        self.assertEqual(A.routes_spring("public class X { @GetMapping(\"/a\") void a() {} }"), [])

    def test_nest_express_python(self):
        self.assertEqual(sorted(A.routes_nest("@Controller('cats')\nclass C { @Get(':id') f(){}  @Post() g(){} }")), [("GET", "/cats/{}"), ("POST", "/cats")])
        self.assertEqual(A.routes_express("router.get('/users/:id', h); app.post(\"/login\", h)"), [("GET", "/users/{}"), ("POST", "/login")])
        self.assertEqual(sorted(A.routes_python("@router.get('/a/{x}')\n@app.route('/b/<int:y>', methods=['POST'])")), [("GET", "/a/{}"), ("POST", "/b/{}")])

    def test_angular_component_ts_is_never_parsed_for_express_routes(self):
        self.assertEqual(A.extract_routes("x.component.ts", "this.router.get('/a'); router.get('/b', h)"), [])


class TestNormalisationAndCoverage(unittest.TestCase):
    def test_param_styles_converge(self):
        self.assertEqual(A.normalize_path("/Users/{id}/"), A.normalize_path("/users/:id"))
        self.assertEqual(A.normalize_path("/u/<int:id>"), "/u/{}")
        self.assertEqual(A.normalize_path("/a//b?x=1"), "/a/b")

    def test_gateway_prefix_on_either_side_still_matches(self):
        spec = {"/v1/usuarios/{}"}
        self.assertTrue(A.covered("/usuarios/{}", spec))            # context-path stripped in code
        self.assertTrue(A.covered("/api/v1/usuarios/{}", spec))     # prefix added in code
        self.assertFalse(A.covered("/usuarios/otra", spec))

    def test_root_never_matches_everything(self):
        self.assertFalse(A.covered("/anything", {"/"}))

    def test_spec_servers_and_basepath_are_alternatives(self):
        doc = json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://h.example/api/v2"}], "paths": {"/items/{id}": {}}})
        ps = A.load_spec_paths(doc, "openapi.json")
        self.assertIn("/items/{}", ps)
        self.assertIn("/api/v2/items/{}", ps)
        self.assertIsNone(A.load_spec_paths("not json", "openapi.json"))
        self.assertIsNone(A.load_spec_paths("a: 1", "openapi.yaml"))          # a YAML without `paths` is not a contract


def make_repo(files):
    d = tempfile.mkdtemp()
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(content)
    return d


def spec(paths):
    return json.dumps({"openapi": "3.0.0", "paths": {p: {} for p in paths}})


CTRL = "src/main/java/x/UsuarioController.java"


class TestRepoRules(unittest.TestCase):
    def test_undocumented_routes_are_listed_per_controller(self):
        d = make_repo({CTRL: SPRING, "openapi.json": spec(["/api/usuarios", "/api/usuarios/{id}"])})
        out = {f["cve_id"]: f for f in A.audit_repo(d)}
        self.assertIn("API-ROUTE-NOT-IN-CONTRACT", out)
        desc = out["API-ROUTE-NOT-IN-CONTRACT"]["description"]
        self.assertIn("/api/usuarios/buscar", desc)
        self.assertIn("/api/usuarios/viejo", desc)
        self.assertNotIn("GET /api/usuarios/{}", desc)                  # documented routes are not listed as shadow ones
        self.assertNotIn("GET /api/usuarios;", desc)
        self.assertEqual(out["API-ROUTE-NOT-IN-CONTRACT"]["url_path"], CTRL)
        self.assertNotIn("API-CONTRACT-ROUTE-NOT-IMPLEMENTED", out)

    def test_fully_documented_api_is_clean(self):
        d = make_repo({CTRL: SPRING, "openapi.json": spec(["/api/usuarios", "/api/usuarios/{id}", "/api/usuarios/buscar", "/api/usuarios/viejo"])})
        self.assertEqual(A.audit_repo(d), [])

    def test_contract_paths_without_code_are_reported_once(self):
        d = make_repo({CTRL: SPRING, "openapi.json": spec(["/api/usuarios", "/api/usuarios/{id}", "/api/usuarios/buscar", "/api/usuarios/viejo", "/api/fantasma", "/api/otro"])})
        out = [f for f in A.audit_repo(d) if f["cve_id"] == "API-CONTRACT-ROUTE-NOT-IMPLEMENTED"]
        self.assertEqual(len(out), 1)
        self.assertIn("/api/fantasma", out[0]["description"])

    def test_unrelated_contract_yields_one_mismatch_and_no_route_findings(self):
        d = make_repo({CTRL: SPRING, "swagger.json": spec(["/pets", "/pets/{id}"])})
        out = A.audit_repo(d)
        self.assertEqual([f["cve_id"] for f in out], ["API-CONTRACT-MISMATCH"])

    def test_no_contract_flagged_only_with_enough_routes_and_no_runtime_docs(self):
        self.assertEqual([f["cve_id"] for f in A.audit_repo(make_repo({CTRL: SPRING}))], ["API-NO-CONTRACT"])
        self.assertEqual(A.audit_repo(make_repo({CTRL: SPRING, "pom.xml": "<artifactId>springdoc-openapi-ui</artifactId>"})), [])       # published at runtime: cannot compare, says nothing
        self.assertEqual(A.audit_repo(make_repo({CTRL: "@RestController\npublic class C { @GetMapping(\"/a\") void a(){} }"})), [])    # < 3 routes
        self.assertEqual(A.audit_repo(make_repo({"README.md": "x"})), [])

    def test_tests_and_node_modules_are_ignored(self):
        d = make_repo({"src/test/java/x/TCtrl.java": SPRING, "node_modules/x/app.js": "router.get('/a',h);router.get('/b',h);router.get('/c',h)"})
        self.assertEqual(A.audit_repo(d), [])

    def test_unparseable_spec_files_make_no_claims(self):
        self.assertEqual(A.audit_repo(make_repo({CTRL: SPRING, "openapi.json": "{ broken"})), [])
