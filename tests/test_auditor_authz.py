"""
Unit tests for the static Broken Access Control auditor (auditors/auditor_authz.py),
added 2026-08-31 after a SIDECO retest where a non-admin account (TcsCSA2) reached the
user-administration API because a sibling route family was hardened and this one was not.

All fixtures are throwaway temp dirs; nothing hits the DB (asset_id=None).
"""
import os
import tempfile
import textwrap
import unittest

from auditors.auditor_authz import run_authz_audit


def _write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(content))
    return path


# a SecurityConfig that hardens /v1/catalogos/roles* with an admin check but has NO rule for
# /v1/usr/** -- the exact SIDECO shape.
_SECCONF_INCONSISTENT = """
    package x.config;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    public class ResourceServerConfig {
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                .antMatchers("/v1/catalogos/roles/**").access("@roleSecurity.isAdmin(authentication)")
                .antMatchers("/v1/catalogos/permisos/**").access("@roleSecurity.isAdmin(authentication)")
                .antMatchers("/v1/**").authenticated()
                .anyRequest().authenticated();
            http.csrf().disable();
        }
    }
"""

_USER_CONTROLLER_UNPROTECTED = """
    package x.controller.usuario;
    import org.springframework.web.bind.annotation.*;
    @RestController
    @RequestMapping("/v1/usr")
    public class UsuarioController {
        @GetMapping("/getUsuarios")
        public Object getUsuarios() { return null; }

        @PostMapping("/guardarUsuarios")
        public Object guardarUsuarios(@RequestBody Object m) { return null; }

        @PutMapping("/{idUsuario}")
        public Object actualizarUsuario(@PathVariable Long idUsuario, @RequestBody Object m) { return null; }
    }
"""

_USER_CONTROLLER_PROTECTED = """
    package x.controller.usuario;
    import org.springframework.web.bind.annotation.*;
    import org.springframework.security.access.prepost.PreAuthorize;
    @RestController
    @RequestMapping("/v1/usr")
    @PreAuthorize("hasRole('ADMIN')")
    public class UsuarioController {
        @GetMapping("/getUsuarios")
        public Object getUsuarios() { return null; }
        @PostMapping("/guardarUsuarios")
        public Object guardarUsuarios(@RequestBody Object m) { return null; }
    }
"""

_ANGULAR_ADMIN_ROUTING = """
    import { NgModule } from '@angular/core';
    import { RouterModule, Routes } from '@angular/router';
    import { AutorizacionGuard } from '../guards/autorizacion.guard';
    const routes: Routes = [
      { path: '', component: CatalogosAdminComponent, canActivate: [AutorizacionGuard],
        children: [
          { path: 'usuarios', component: CatUsuariosAdminComponent },
          { path: 'roles', component: CatRolesAdminComponent },
        ] },
    ];
    @NgModule({ imports: [RouterModule.forChild(routes)], exports: [RouterModule] })
    export class CatalogosAdminRoutingModule {}
"""


class TestAuthzInconsistentFamily(unittest.TestCase):
    def test_hardened_sibling_plus_forgotten_usr_family_fires(self):
        with tempfile.TemporaryDirectory() as root:
            _write(root, "src/main/java/x/config/ResourceServerConfig.java", _SECCONF_INCONSISTENT)
            _write(root, "src/main/java/x/controller/usuario/UsuarioController.java",
                   _USER_CONTROLLER_UNPROTECTED)
            findings = run_authz_audit(root, asset_id=None)
            fam = [f for f in findings if f["cve_id"] == "AUTHZ-INCONSISTENT-FAMILY"]
            self.assertTrue(fam, f"expected AUTHZ-INCONSISTENT-FAMILY, got {[f['cve_id'] for f in findings]}")
            # every one must be HIGH and point at UsuarioController
            self.assertTrue(all(f["severity"] == "HIGH" for f in fam))
            self.assertTrue(any("UsuarioController" in f["file"] for f in fam))

    def test_method_annotations_on_identity_controller_suppress_it(self):
        with tempfile.TemporaryDirectory() as root:
            _write(root, "src/main/java/x/config/ResourceServerConfig.java", _SECCONF_INCONSISTENT)
            _write(root, "src/main/java/x/controller/usuario/UsuarioController.java",
                   _USER_CONTROLLER_PROTECTED)
            findings = run_authz_audit(root, asset_id=None)
            fam = [f for f in findings if f["cve_id"] == "AUTHZ-INCONSISTENT-FAMILY"]
            self.assertFalse(fam, f"@PreAuthorize present -> must NOT fire; got {fam}")


class TestSecurityConfigParser(unittest.TestCase):
    def test_chained_antmatchers_with_nested_parens_and_comments_all_parsed(self):
        # Regression: SIDECO's develop ResourceServerConfig chains
        #   .antMatchers(POST,"/v1/catalogos/**").access("@roleSecurity.isAdmin(authentication)")
        #   // comment
        #   .antMatchers(POST,"/v1/recepcion/x").permitAll()
        #   ...
        #   .antMatchers("/v1/**").authenticated()
        # The old single-regex parser stopped after the first rule (nested parens in .access(...)
        # + a blank line/// comment between calls), so 53 genuinely .authenticated() endpoints
        # were mis-flagged AUTHZ-NO-RULE.
        from auditors.auditor_authz import _parse_security_configs, _match_rule
        cfg = """
            package x;
            public class ResourceServerConfig {
              public void configure(HttpSecurity http) throws Exception {
                http.requestMatchers()
                    .and()
                    .authorizeRequests()
                    // 1. mutation locked to admin
                    .antMatchers(HttpMethod.POST, "/v1/catalogos/**").access("@roleSecurity.isAdmin(authentication)")
                    .antMatchers(HttpMethod.PUT, "/v1/catalogos/**").access("@roleSecurity.isAdmin(authentication)")

                    // 2. explicit public endpoints
                    .antMatchers(HttpMethod.POST, "/v1/recepcion/agregarSolicitud").permitAll()
                    .antMatchers(HttpMethod.GET, "/v1/version").permitAll()

                    // 3. catalog reads
                    .antMatchers("/v1/catalogos/**").access("isAuthenticated() or @siatSecurity.test(request)")

                    // 4. catch-all
                    .antMatchers("/v1/**").authenticated()
                    .and().csrf().disable();
              }
            }
        """
        rules, cfiles, csrf = _parse_security_configs([("ResourceServerConfig.java", cfg)])
        self.assertGreaterEqual(len(rules), 6, f"expected >=6 rules, got {len(rules)}: {[(r['methods'], r['pattern'], r['decision']) for r in rules]}")
        self.assertTrue(csrf)
        # a plain GET catalog endpoint must resolve to a rule, not None
        m = _match_rule({"path": "/v1/catalogos/obtieneTipoJornadas", "method": "GET", "annotated": False}, rules)
        self.assertIsNotNone(m)
        self.assertEqual(m["decision"], "authenticated")
        # POST catalog mutation must resolve to admin
        m2 = _match_rule({"path": "/v1/catalogos/guardarAlgo", "method": "POST", "annotated": False}, rules)
        self.assertEqual(m2["decision"], "admin")


class TestAuthzClientSideOnly(unittest.TestCase):
    def test_angular_admin_module_guard_only_no_backend_role(self):
        with tempfile.TemporaryDirectory() as root:
            # backend with zero role enforcement anywhere
            _write(root, "src/main/java/x/config/PlainConfig.java", """
                package x.config;
                import org.springframework.security.config.annotation.web.builders.HttpSecurity;
                public class PlainConfig {
                    protected void configure(HttpSecurity http) throws Exception {
                        http.authorizeRequests().antMatchers("/v1/**").authenticated();
                    }
                }
            """)
            _write(root, "src/app/modulos/catalogos-admin/catalogos-admin-routing.module.ts",
                   _ANGULAR_ADMIN_ROUTING)
            findings = run_authz_audit(root, asset_id=None)
            cso = [f for f in findings if f["cve_id"] == "AUTHZ-CLIENT-SIDE-ONLY"]
            self.assertTrue(cso, f"expected AUTHZ-CLIENT-SIDE-ONLY, got {[f['cve_id'] for f in findings]}")
            self.assertEqual(cso[0]["severity"], "HIGH")


class TestAuthzNoFalsePositivesOnCentinela(unittest.TestCase):
    def test_centinela_own_python_tree_is_clean(self):
        # auditors/ + core/ are pure-Python (no Spring/Angular) -> the auditor must find nothing.
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for sub in ("core", "auditors"):
            findings = run_authz_audit(os.path.join(repo_root, sub), asset_id=None)
            self.assertEqual(findings, [], f"unexpected authz findings under {sub}/: {findings}")


if __name__ == "__main__":
    unittest.main()
