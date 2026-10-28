"""Positive AND negative cases for every rule in auditors/auditor_arch_rules.py (a rule without a negative case is how false positives ship)."""
import os
import tempfile

import pytest

from auditors.auditor_arch_rules import scan_arch_rules


def ids(file_path, content):
    return [f["cve_id"] for f in scan_arch_rules(file_path, content)]


# ------------------------------------------------------------------ Java
def test_eager_collection_is_flagged_medium_and_lazy_is_not():
    bad = "class A { @OneToMany(mappedBy=\"a\", fetch = FetchType.EAGER) List<B> bs; }"
    out = scan_arch_rules("A.java", bad)
    assert [(f["cve_id"], f["severity"]) for f in out] == [("JPA-EAGER-FETCH", "MEDIUM")]
    assert ids("A.java", "class A { @OneToMany(mappedBy=\"a\", fetch = FetchType.LAZY) List<B> bs; }") == []


def test_eager_to_one_is_only_low():
    out = scan_arch_rules("A.java", "class A { @ManyToOne(fetch = FetchType.EAGER) B b; }")
    assert out[0]["severity"] == "LOW"


CTRL = "@RestController\nclass UsuarioController {\n%s\n}\n"


def test_findall_in_controller_flagged_and_in_memory_filter_raises_severity():
    out = scan_arch_rules("UsuarioController.java", CTRL % "List<U> x() { return usuarioRepository.findAll().stream().filter(u -> u.ok()).toList(); }")
    assert [(f["cve_id"], f["severity"]) for f in out if f["cve_id"] == "REPOSITORY-FINDALL-UNPAGINATED"] == [("REPOSITORY-FINDALL-UNPAGINATED", "MEDIUM")]


def test_findall_with_pageable_or_in_a_test_is_not_flagged():
    assert "REPOSITORY-FINDALL-UNPAGINATED" not in ids("UsuarioController.java", CTRL % "Page<U> x(Pageable p) { return usuarioRepository.findAll(p); }")
    assert ids("src/test/java/UsuarioControllerTest.java", CTRL % "x() { repo.findAll(); }") == []


def test_query_in_loop_flagged_and_batch_query_is_not():
    svc = "@Service\nclass S {\n void f(List<Long> ids) {\n  for (Long id : ids) {\n   var u = userRepository.findById(id);\n  }\n }\n}\n"
    assert "JPA-QUERY-IN-LOOP" in ids("S.java", svc)
    ok = "@Service\nclass S {\n void f(List<Long> ids) {\n  var us = userRepository.findAllById(ids);\n  for (var u : us) { u.touch(); }\n }\n}\n"
    assert "JPA-QUERY-IN-LOOP" not in ids("S.java", ok)
    assert "JPA-QUERY-IN-LOOP" in ids("S.java", "@Service\nclass S { void f(List<Long> l){ l.forEach(i -> itemRepository.findById(i)); } }")


def test_requestbody_without_valid_flagged_with_valid_and_with_string_not():
    assert "REQUESTBODY-WITHOUT-VALID" in ids("C.java", CTRL % "@PostMapping(\"/x\") ResponseEntity<?> post(@RequestBody UsuarioDto dto) { return null; }")
    assert "REQUESTBODY-WITHOUT-VALID" not in ids("C.java", CTRL % "@PostMapping(\"/x\") ResponseEntity<?> post(@Valid @RequestBody UsuarioDto dto) { return null; }")
    assert "REQUESTBODY-WITHOUT-VALID" not in ids("C.java", CTRL % "@PostMapping(\"/x\") ResponseEntity<?> post(@RequestBody @Valid UsuarioDto dto) { return null; }")
    assert "REQUESTBODY-WITHOUT-VALID" not in ids("C.java", CTRL % "@PostMapping(\"/x\") ResponseEntity<?> post(@RequestBody String raw) { return null; }")


def test_requestbody_valid_on_a_different_parameter_does_not_hide_the_missing_one():
    code = CTRL % "@PostMapping(\"/x\") ResponseEntity<?> post(@Valid @RequestBody AaaDto a, @RequestBody BbbDto b) { return null; }"
    out = [f for f in scan_arch_rules("C.java", code) if f["cve_id"] == "REQUESTBODY-WITHOUT-VALID"]
    assert len(out) == 1 and "BbbDto" in out[0]["description"]


def test_entity_returned_from_controller():
    bad = "import mx.gob.x.entity.Usuario;\n" + CTRL % "@GetMapping(\"/u\") public ResponseEntity<Usuario> get() { return null; }"
    assert "ENTITY-RETURNED-FROM-CONTROLLER" in ids("C.java", bad)
    assert "ENTITY-RETURNED-FROM-CONTROLLER" in ids("C.java", CTRL % "@GetMapping(\"/u\") public List<UsuarioEntity> all() { return null; }")
    ok = "import mx.gob.x.entity.Usuario;\n" + CTRL % "@GetMapping(\"/u\") public ResponseEntity<UsuarioDto> get() { return null; }"
    assert "ENTITY-RETURNED-FROM-CONTROLLER" not in ids("C.java", ok)


def test_controller_injecting_repository_once_and_service_is_fine():
    bad = CTRL % "private final UsuarioRepository usuarioRepository;\nprivate final OtroRepository otroRepository;"
    assert ids("C.java", bad).count("CONTROLLER-INJECTS-REPOSITORY") == 1
    assert "CONTROLLER-INJECTS-REPOSITORY" not in ids("C.java", CTRL % "private final UsuarioService usuarioService;")
    assert "CONTROLLER-INJECTS-REPOSITORY" not in ids("UsuarioService.java", "@Service class S { private final UsuarioRepository r; }")


# ------------------------------------------------------------------ Angular TS
COMP = "@Component({selector:'x'})\nexport class X {\n%s\n}\n"


def test_nested_subscribe_reported_once_at_the_outer_call():
    code = COMP % "load(){ this.a.get().subscribe(u => { this.b.get(u.id).subscribe(r => { this.c.get(r).subscribe(); }); }); }"
    assert ids("x.component.ts", code).count("ANGULAR-NESTED-SUBSCRIBE") == 1
    assert "ANGULAR-NESTED-SUBSCRIBE" not in ids("x.component.ts", COMP % "load(){ this.a.get().pipe(switchMap(u => this.b.get(u.id))).subscribe(); }")


def test_subscribe_no_cleanup_only_for_streams_that_outlive_the_component():
    leak = COMP % "ngOnInit(){ this.sesionService.usuario$.subscribe(u => this.u = u); }"
    assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" in ids("x.component.ts", leak)
    assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" in ids("x.component.ts", COMP % "ngOnInit(){ interval(1000).subscribe(() => this.t++); }")
    # NOT flagged: one-shot HTTP verb, router streams, component-owned form, explicit cleanup, ngOnDestroy present
    assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" not in ids("x.component.ts", COMP % "ngOnInit(){ this.usuarioService.obtener(1).subscribe(u => this.u = u); }")
    assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" not in ids("x.component.ts", COMP % "ngOnInit(){ this.route.paramMap.subscribe(p => this.id = p.get('id')); }")
    assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" not in ids("x.component.ts", COMP % "ngOnInit(){ this.form.valueChanges.subscribe(v => this.v = v); }")
    assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" not in ids("x.component.ts", COMP % "ngOnInit(){ this.sesionService.usuario$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(); }")
    assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" not in ids("x.component.ts", COMP % "ngOnInit(){ this.sesionService.usuario$.subscribe(); }\nngOnDestroy(){ this.s.unsubscribe(); }")


def test_valuechanges_without_debounce():
    bad = COMP % "ngOnInit(){ this.filtro.valueChanges.subscribe(v => this.usuarioService.buscar(v).subscribe()); }"
    assert "ANGULAR-VALUECHANGES-NO-DEBOUNCE" in ids("x.component.ts", bad)
    ok = COMP % "ngOnInit(){ this.filtro.valueChanges.pipe(debounceTime(300), switchMap(v => this.usuarioService.buscar(v))).subscribe(); }"
    assert "ANGULAR-VALUECHANGES-NO-DEBOUNCE" not in ids("x.component.ts", ok)
    # a valueChanges that does not call the backend is not a request storm
    assert "ANGULAR-VALUECHANGES-NO-DEBOUNCE" not in ids("x.component.ts", COMP % "ngOnInit(){ this.f.valueChanges.subscribe(v => this.total = v * 2); }")


def test_effect_with_http_and_effect_that_writes_what_it_reads():
    assert "ANGULAR-EFFECT-HTTP" in ids("x.component.ts", COMP % "constructor(){ effect(() => { const f = this.filtro(); this.http.get('/api/x').subscribe(); }); }")
    cyc = COMP % "filtro = signal(1);\nconstructor(){ effect(() => { const f = this.filtro(); this.filtro.set(f + 1); }); }"
    out = [f for f in scan_arch_rules("x.component.ts", cyc) if f["cve_id"] == "ANGULAR-EFFECT-SELF-WRITE"]
    assert out and out[0]["severity"] == "HIGH"
    fine = COMP % "a = signal(1); b = signal(0);\nconstructor(){ effect(() => { this.b.set(this.a() * 2); }); }"
    assert "ANGULAR-EFFECT-SELF-WRITE" not in ids("x.component.ts", fine)
    assert "ANGULAR-EFFECT-HTTP" not in ids("x.component.ts", COMP % "constructor(){ effect(() => console.log(this.a())); }")


def test_http_in_loop():
    assert "ANGULAR-HTTP-IN-LOOP" in ids("x.component.ts", COMP % "f(us:any[]){ us.forEach(u => { this.rolService.obtener(u.id).subscribe(r => u.rol = r); }); }")
    assert "ANGULAR-HTTP-IN-LOOP" in ids("x.component.ts", COMP % "f(us:any[]){ for (const u of us) { this.http.get('/api/' + u.id).subscribe(); } }")
    assert "ANGULAR-HTTP-IN-LOOP" not in ids("x.component.ts", COMP % "f(us:any[]){ us.forEach(u => { u.ok = true; }); }")


def test_signal_mutated_in_place_only_when_it_is_really_a_signal():
    bad = COMP % "lista = signal<string[]>([]);\nadd(x:string){ this.lista().push(x); }"
    assert "ANGULAR-SIGNAL-MUTATION-IN-PLACE" in ids("x.component.ts", bad)
    ok = COMP % "lista = signal<string[]>([]);\nadd(x:string){ this.lista.update(l => [...l, x]); }"
    assert "ANGULAR-SIGNAL-MUTATION-IN-PLACE" not in ids("x.component.ts", ok)
    not_signal = COMP % "lista(){ return this.items; }\nadd(x:string){ this.lista().push(x); }"
    assert "ANGULAR-SIGNAL-MUTATION-IN-PLACE" not in ids("x.component.ts", not_signal)


def test_double_load_between_ngoninit_and_effect():
    bad = COMP % "constructor(){ effect(() => { this.filtro(); this.cargarDatos(); }); }\nngOnInit(){ this.cargarDatos(); }\ncargarDatos(){}"
    assert "ANGULAR-DOUBLE-LOAD-INIT-EFFECT" in ids("x.component.ts", bad)
    ok = COMP % "ngOnInit(){ this.cargarDatos(); }\ncargarDatos(){}"
    assert "ANGULAR-DOUBLE-LOAD-INIT-EFFECT" not in ids("x.component.ts", ok)


def test_settimeout_workaround_and_any_threshold():
    assert "ANGULAR-SETTIMEOUT-WORKAROUND" in ids("x.component.ts", COMP % "ngAfterViewInit(){ setTimeout(() => { this.v = 1; }, 0); }")
    assert "ANGULAR-SETTIMEOUT-WORKAROUND" not in ids("x.component.ts", COMP % "retry(){ setTimeout(() => this.go(), 5000); }")
    many = "\n".join(f"let v{i}: any = 1;" for i in range(6))
    out = [f for f in scan_arch_rules("a.service.ts", many) if f["cve_id"] == "TS-EXPLICIT-ANY"]
    assert len(out) == 1 and "6 veces" in out[0]["description"]          # one finding per file, not six
    assert "TS-EXPLICIT-ANY" not in ids("a.service.ts", "let a: any = 1; let b: any = 2;")   # below the noise threshold
    assert scan_arch_rules("types.d.ts", many) == []


# ------------------------------------------------------------------ templates
def test_template_method_in_loop_needs_arguments_and_ignores_signal_reads():
    assert "ANGULAR-TEMPLATE-METHOD-IN-LOOP" in ids("x.component.html", "@for (u of filtrarUsuarios(texto); track u.id) { <p>{{u}}</p> }")
    assert "ANGULAR-TEMPLATE-METHOD-IN-LOOP" in ids("x.component.html", '<li *ngFor="let u of getActivos(true)">{{u}}</li>')
    assert "ANGULAR-TEMPLATE-METHOD-IN-LOOP" not in ids("x.component.html", "@for (u of usuarios(); track u.id) { <p>{{u}}</p> }")


def test_lazyload_plus_ngoninit_load_reads_the_sibling_component():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "x.component.ts"), "w").write(COMP % "ngOnInit(){ this.cargarPagina(); }\ncargarPagina(){}")
        html = os.path.join(d, "x.component.html")
        tpl = '<p-table [lazy]="true" (onLazyLoad)="cargarPagina($event)"></p-table>'
        assert "ANGULAR-LAZYLOAD-PLUS-INIT-LOAD" in ids(html, tpl)
        assert "ANGULAR-LAZYLOAD-PLUS-INIT-LOAD" not in ids(html, tpl.replace("[lazy]", '[lazyLoadOnInit]="false" [lazy]'))
        open(os.path.join(d, "x.component.ts"), "w").write(COMP % "ngOnInit(){ this.config(); }\nconfig(){}")
        assert "ANGULAR-LAZYLOAD-PLUS-INIT-LOAD" not in ids(html, tpl)


def test_submit_without_busy_guard_only_once_per_template():
    bad = '<p-button label="Guardar" (onClick)="guardar()"></p-button><button (click)="eliminar()">Eliminar</button>'
    out = [f for f in scan_arch_rules("x.component.html", bad) if f["cve_id"] == "ANGULAR-SUBMIT-NO-BUSY-GUARD"]
    assert len(out) == 1
    assert "ANGULAR-SUBMIT-NO-BUSY-GUARD" not in ids("x.component.html", '<p-button label="Guardar" [loading]="saving()" (onClick)="guardar()"></p-button>')
    assert "ANGULAR-SUBMIT-NO-BUSY-GUARD" not in ids("x.component.html", '<button (click)="abrir()">Ver detalle</button>')


def test_vendored_and_test_files_are_skipped():
    assert scan_arch_rules("src/app/x.spec.ts", COMP % "a(){ this.s.usuario$.subscribe(); }") == []
    assert scan_arch_rules("node_modules/x/y.ts", COMP % "a(){ interval(1).subscribe(); }") == []


def test_requestbody_and_entity_findings_are_one_per_controller_not_one_per_endpoint():
    body = ("@PostMapping(\"/a\") ResponseEntity<?> a(@RequestBody ADto d) { return null; }\n"
            "@PostMapping(\"/b\") ResponseEntity<?> b(@RequestBody BDto d) { return null; }\n"
            "@PutMapping(\"/c\") ResponseEntity<?> c(@Valid @RequestBody CDto d) { return null; }\n")
    out = [f for f in scan_arch_rules("C.java", CTRL % body) if f["cve_id"] == "REQUESTBODY-WITHOUT-VALID"]
    assert len(out) == 1
    assert out[0]["description"].startswith("2 endpoint(s)") and "ADto" in out[0]["description"] and "BDto" in out[0]["description"] and "CDto" not in out[0]["description"]
    ent = ("import mx.x.entity.Usuario;\n" + CTRL % "@GetMapping(\"/u\") public List<Usuario> all() { return null; }\n@GetMapping(\"/v\") public Usuario one() { return null; }")
    er = [f for f in scan_arch_rules("C.java", ent) if f["cve_id"] == "ENTITY-RETURNED-FROM-CONTROLLER"]
    assert len(er) == 1 and "2 endpoint(s)" in er[0]["description"]


# ------------------------------------------------------------------ subscribe: one-shot HTTP resolved through the injected service (13-oct-2026, proyecto-a)
SVC_HTTP = ("import { HttpClient } from '@angular/common/http';\n@Injectable({providedIn:'root'})\nexport class CargoService {\n"
            "  constructor(private http: HttpClient) {}\n  toggle(id: number, v: boolean) {\n    return this.http.put(`/cargo/${id}`, { v });\n  }\n"
            "  live() {\n    return this.updates$.asObservable();\n  }\n  updates$ = new Subject<number>();\n}\n")
CMP = ("import { CargoService } from './cargo.service';\n@Component({selector:'a',template:''})\nexport class A {\n"
       "  constructor(private cargoService: CargoService) {}\n  go() {\n    this.cargoService.%s.subscribe({ next: () => {} });\n  }\n}\n")


def _project(tmp, service_src):
    open(os.path.join(tmp, "tsconfig.json"), "w").write("{}")
    open(os.path.join(tmp, "cargo.service.ts"), "w").write(service_src)
    return os.path.join(tmp, "a.component.ts")


def test_subscribe_on_a_service_method_that_returns_one_shot_http_is_not_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        path = _project(tmp, SVC_HTTP)
        assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" not in ids(path, CMP % "toggle(1, true)")


def test_subscribe_on_a_service_method_that_returns_a_subject_is_still_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        path = _project(tmp, SVC_HTTP)
        assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" in ids(path, CMP % "live()")


def test_subscribe_is_still_flagged_when_the_service_cannot_be_resolved():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "a.component.ts")
        assert "ANGULAR-SUBSCRIBE-NO-CLEANUP" in ids(path, CMP % "toggle(1, true)")
