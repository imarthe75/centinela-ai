"""
Static architecture / performance rules for Spring Boot (Java) and Angular (TypeScript) code.

Source: the two audit prompts un colaborador shares (backend: persistence, DTO boundaries, validation; frontend: duplicated HTTP, Signals/effect misuse,
RxJS subscriptions, forms, templates). Only what is decidable from the text of ONE file (plus the sibling template of a component) is implemented;
everything that needs the whole call graph (the same endpoint reached from parent AND child, stale state, race between two components) is NOT
detected here -- those need a human or a cross-file analysis and are left out on purpose rather than guessed.

Every rule says "requiere validación" when the text alone cannot prove the problem. Pure functions: no DB, no network.
Called from auditor_master_vulnerabilities.scan_sast_code().
"""
import os
import re
from typing import Any, Dict, List, Optional

_VENDORED_RE = re.compile(r"(\.min\.|\.bundle\.|/assets/plugins/|/vendor/|/node_modules/|/dist/|/build/|/target/)", re.IGNORECASE)
_TEST_RE = re.compile(r"(\.spec\.ts$|\.test\.ts$|(^|/)src/test/|Test\.java$|Tests\.java$|IT\.java$)")


def _line(content: str, idx: int) -> int:
    return content.count("\n", 0, idx) + 1


def _match_close(text: str, open_idx: int, open_ch: str = "(", close_ch: str = ")") -> int:
    """Index of the bracket closing the one at open_idx, skipping quoted strings; -1 when unbalanced."""
    depth, i, n, quote = 0, open_idx, len(text), None
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _f(rule: str, severity: str, file_path: str, line: int, description: str) -> Dict[str, Any]:
    return {"cve_id": rule, "severity": severity, "file": file_path, "line": line, "description": description}


# ----------------------------------------------------------------------------------------------------------------------
# Java / Spring Boot
# ----------------------------------------------------------------------------------------------------------------------
_EAGER_RE = re.compile(r"@(OneToMany|ManyToMany|ManyToOne|OneToOne)\s*\(([^)]*FetchType\.EAGER[^)]*)\)")
_FIND_ALL_RE = re.compile(r"\b(\w*(?:Repository|Repo|Dao))\s*\.\s*findAll\s*\(\s*\)")
_LOOP_QUERY_RE = re.compile(r"\b\w*(?:Repository|Repo|Dao)\s*\.\s*(?:find\w*|get\w*|count\w*|exists\w*|read\w*)\s*\(")
_JAVA_BODY_TYPES_SKIP = ("String", "Map", "byte", "MultipartFile", "Object", "JsonNode", "Resource", "InputStream")


def _scan_java_arch(file_path: str, content: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    is_controller = bool(re.search(r"@(Rest)?Controller\b", content))
    is_service = bool(re.search(r"@Service\b", content)) or file_path.endswith("Service.java") or file_path.endswith("ServiceImpl.java")

    # JPA-EAGER-FETCH -- an explicit EAGER association loads the related rows on EVERY query of the owner, including list screens
    # that never show them (the usual root of N+1 / oversized-result problems). Collections are the real risk; to-one is common and lower.
    for m in _EAGER_RE.finditer(content):
        kind = m.group(1)
        to_many = kind in ("OneToMany", "ManyToMany")
        out.append(_f(
            "JPA-EAGER-FETCH", "MEDIUM" if to_many else "LOW", file_path, _line(content, m.start()),
            f"La asociación @{kind} está declarada con FetchType.EAGER: cada consulta de la entidad carga también las filas relacionadas, "
            f"aunque la pantalla no las use"
            + (" (al ser una colección, el costo crece con el número de hijos y suele producir consultas N+1 o resultados enormes). " if to_many
               else ". ")
            + "Valorar FetchType.LAZY más JOIN FETCH / proyección DTO solo en las consultas que sí necesitan la relación. "
              "Requiere validación: algunas relaciones pequeñas y siempre usadas sí justifican EAGER."))

    # REPOSITORY-FINDALL-UNPAGINATED -- findAll() with no Pageable in a controller/service loads the whole table; a filter applied afterwards
    # in memory (stream().filter) is the same cost plus CPU. Skipped in repositories/config/tests.
    if (is_controller or is_service) and not _TEST_RE.search(file_path):
        for m in _FIND_ALL_RE.finditer(content):
            tail = content[m.end():m.end() + 160]
            in_memory = bool(re.match(r"\s*\.\s*stream\s*\(\s*\)\s*\.\s*(filter|sorted|limit|skip)\b", tail))
            out.append(_f(
                "REPOSITORY-FINDALL-UNPAGINATED", "MEDIUM" if in_memory else "LOW", file_path, _line(content, m.start()),
                f"{m.group(1)}.findAll() sin Pageable"
                + (", seguido de un filtro/orden en memoria (stream)" if in_memory else "")
                + ": trae la tabla completa a memoria en cada llamada. Con el crecimiento de la tabla degrada tiempo de respuesta y memoria. "
                  "Usar paginación (Pageable), un método de repositorio con el criterio en la consulta o una proyección. "
                  "Requiere validación: es aceptable en catálogos pequeños y acotados."))

    # JPA-QUERY-IN-LOOP -- N+1 in service code: a repository finder called inside a loop / forEach.
    if (is_controller or is_service) and not _TEST_RE.search(file_path):
        seen = set()
        for m in re.finditer(r"\bfor\s*\([^;)]*:[^)]*\)\s*\{|\.forEach\s*\(", content):
            if m.group(0).startswith(".forEach"):
                end = _match_close(content, m.end() - 1)
                body = content[m.end():end] if end != -1 else ""
            else:
                end = _match_close(content, m.end() - 1, "{", "}")
                body = content[m.end():end] if end != -1 else ""
            q = _LOOP_QUERY_RE.search(body)
            if q and m.start() not in seen:
                seen.add(m.start())
                out.append(_f(
                    "JPA-QUERY-IN-LOOP", "MEDIUM", file_path, _line(content, m.start()),
                    "Se invoca un método de repositorio dentro de un ciclo (for / forEach): una consulta por elemento (patrón N+1). "
                    "Con N elementos son N+1 viajes a la base de datos. Consolidar en una sola consulta (IN / JOIN FETCH / método "
                    "findAllById) y agrupar en memoria. Requiere validación: si N es pequeño y fijo el costo puede ser aceptable."))

    if is_controller and not _TEST_RE.search(file_path):
        # REQUESTBODY-WITHOUT-VALID -- the body is bound but never validated: Bean Validation annotations on the DTO are silently ignored.
        # ONE finding per controller (measured 2026-10-12: one per endpoint produced 2,125 findings, 1,101 in a single project -- noise that buried the rest
        # of the report); the description lists every endpoint so nothing is hidden.
        rb_hits = []
        for m in re.finditer(r"@RequestBody\b", content):
            open_p = content.rfind("(", 0, m.start())
            if open_p == -1:
                continue
            close_p = _match_close(content, open_p)
            params = content[open_p + 1:close_p] if close_p != -1 else ""
            # the parameter that holds this @RequestBody: bounded by the commas at depth 0 around it
            start = max(params.rfind(",", 0, m.start() - open_p - 1) + 1, 0)
            nxt = params.find(",", m.start() - open_p - 1)
            seg = params[start: nxt if nxt != -1 else len(params)]
            if re.search(r"@(Valid|Validated)\b", seg):
                continue
            type_m = re.search(r"@RequestBody\s+(?:@\w+(?:\([^)]*\))?\s+)*([A-Za-z_][\w<>\[\], ?]*?)\s+\w+\s*$", seg.strip())
            tname = type_m.group(1) if type_m else ""
            if tname.startswith(_JAVA_BODY_TYPES_SKIP) or tname.endswith("[]"):
                continue
            rb_hits.append((_line(content, m.start()), tname))
        if rb_hits:
            listing = ", ".join(f"línea {ln}" + (f" ({t})" if t else "") for ln, t in rb_hits[:15]) + (f" y {len(rb_hits) - 15} más" if len(rb_hits) > 15 else "")
            out.append(_f(
                "REQUESTBODY-WITHOUT-VALID", "MEDIUM", file_path, rb_hits[0][0],
                f"{len(rb_hits)} endpoint(s) de este controlador reciben @RequestBody sin @Valid/@Validated: {listing}. Las restricciones de Bean Validation "
                f"del DTO (@NotNull, @Size, @Pattern...) no se ejecutan y datos inválidos llegan a la lógica de negocio. Añadir @Valid y manejar "
                f"MethodArgumentNotValidException con un 400 claro. Requiere validación: la validación puede hacerse manualmente en el servicio."))

        # ENTITY-RETURNED-FROM-CONTROLLER -- a JPA entity (name ends in Entity, or imported from an entity package) is the response type.
        # One finding per controller, listing every endpoint (same reasoning as REQUESTBODY-WITHOUT-VALID).
        entity_imports = set(re.findall(r"import\s+[\w.]*\.(?:entity|entities)\.(\w+)\s*;", content))
        er_hits = []
        for m in re.finditer(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b[^{;]*?\b(?:public\s+)?([\w<>?,\s\[\]]+?)\s+\w+\s*\(", content):
            ret = m.group(1).strip()
            names = re.findall(r"[A-Z]\w*", ret)
            hit = [n for n in names if n.endswith("Entity") or n in entity_imports]
            if hit and "Dto" not in ret and "DTO" not in ret:
                er_hits.append((_line(content, m.start()), hit[0], ret))
        if er_hits:
            listing = ", ".join(f"línea {ln} ({ret})" for ln, _n, ret in er_hits[:10]) + (f" y {len(er_hits) - 10} más" if len(er_hits) > 10 else "")
            out.append(_f(
                "ENTITY-RETURNED-FROM-CONTROLLER", "MEDIUM", file_path, er_hits[0][0],
                f"El controlador devuelve directamente entidades JPA en {len(er_hits)} endpoint(s): {listing}. Se expone el modelo de persistencia completo "
                f"(columnas internas, relaciones perezosas que pueden provocar LazyInitializationException o consultas extra al serializar) y se acopla el "
                f"contrato de la API a la tabla. Devolver un DTO de respuesta con solo los campos necesarios."))

        # CONTROLLER-INJECTS-REPOSITORY -- persistence reached straight from the web layer: no service boundary, no place for transactions.
        for m in re.finditer(r"\b([A-Z]\w*(?:Repository|Repo|Dao))\s+(\w+)\s*[;,)=]", content):
            if re.search(r"\bimport\b", content[max(0, m.start() - 20):m.start()]):
                continue
            out.append(_f(
                "CONTROLLER-INJECTS-REPOSITORY", "MEDIUM", file_path, _line(content, m.start()),
                f"El controlador depende directamente de {m.group(1)}: la lógica de acceso a datos y las transacciones quedan en la capa web, sin una "
                f"capa de servicio que las delimite ni que pueda reutilizarse/probarse. Mover el acceso a un @Service y que el controlador solo traduzca "
                f"HTTP a llamadas de servicio."))
            break  # one finding per controller is enough; the fix is architectural, not per-field
    return out


# ----------------------------------------------------------------------------------------------------------------------
# Angular / TypeScript
# ----------------------------------------------------------------------------------------------------------------------
# method names that denote a finite HTTP request (completes by itself) -> no subscription leak
_FINITE_VERB_RE = re.compile(
    r"^(get|post|put|patch|delete|find|search|load|save|list|fetch|create|update|remove|obtener|listar|guardar|eliminar|buscar|consultar|cargar|"
    r"actualizar|crear|registrar|descargar|subir|enviar|validar|generar|exportar|importar|calcular|resolver|refresh|login|logout)", re.IGNORECASE)

def _project_root(file_path: str) -> Optional[str]:
    d = os.path.dirname(os.path.abspath(file_path))
    for _ in range(12):
        if os.path.exists(os.path.join(d, "tsconfig.json")) or os.path.exists(os.path.join(d, "angular.json")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return None


def _resolve_ts_import(file_path: str, spec: str) -> Optional[str]:
    """Resolve `./x`, `../x` or a baseUrl-style `src/app/x` import to a .ts file on disk, or None when it cannot be resolved."""
    if spec.startswith("."):
        base = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(file_path)), spec))
    elif spec.startswith("src/"):
        root = _project_root(file_path)
        if not root:
            return None
        base = os.path.join(root, spec)
    else:
        return None
    for cand in (base + ".ts", os.path.join(base, "index.ts")):
        if os.path.isfile(cand):
            return cand
    return None


def _service_method_is_one_shot_http(file_path: str, content: str, field: str, method: str) -> bool:
    """True only when the injected service's `method` can be PROVEN to return a one-shot HTTP call: the method body calls `this.http*.get/post/put/delete/patch/request`
    and contains no Subject/interval/timer/fromEvent/webSocket. HttpClient observables emit once and complete, so subscribing without cleanup leaks nothing, and
    cancelling them on destroy (takeUntilDestroyed) would drop an in-flight save. Anything that cannot be resolved returns False (stays reported)."""
    tm = re.search(r"(?:private|public|protected)\s+(?:readonly\s+)?" + re.escape(field) + r"\s*:\s*(\w+)", content) \
        or re.search(r"\b" + re.escape(field) + r"\s*=\s*inject\(\s*(\w+)\s*\)", content)
    if not tm:
        return False
    type_name = tm.group(1)
    im = re.search(r"import\s*\{[^}]*\b" + re.escape(type_name) + r"\b[^}]*\}\s*from\s*['\"]([^'\"]+)['\"]", content)
    if not im:
        return False
    svc_path = _resolve_ts_import(file_path, im.group(1))
    if not svc_path:
        return False
    try:
        svc = open(svc_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return False
    md = re.search(r"(?m)^\s*(?:public\s+|private\s+|protected\s+|async\s+)*" + re.escape(method) + r"\s*(?:<[^>]*>)?\s*\(", svc)
    if not md:
        return False
    brace = svc.find("{", _match_close(svc, svc.find("(", md.start())) if _match_close(svc, svc.find("(", md.start())) != -1 else md.end())
    if brace == -1:
        return False
    end = _match_close(svc, brace, "{", "}")
    body = svc[brace:end if end != -1 else brace + 2000]
    return bool(re.search(r"this\.\w*[hH]ttp\w*\s*\.\s*(get|post|put|delete|patch|request)\b|this\.\w*[hH]ttp\w*\s*\.\s*\w+\s*<", body)) \
        and not re.search(r"\b(Subject|BehaviorSubject|ReplaySubject|interval|timer|fromEvent|webSocket|EventSource)\b", body)


_CLEANUP_RE = re.compile(r"takeUntilDestroyed|takeUntil\s*\(|\.pipe\s*\(\s*take\s*\(|first\s*\(|\btake\s*\(\s*1\s*\)|DestroyRef|toSignal|\basync\b")
_PERSISTENT_SOURCE_RE = re.compile(r"\b(interval|timer|fromEvent|webSocket|EventSource)\s*\(")
_LOAD_NAME_RE = re.compile(r"^(cargar|buscar|load|search|listar|consultar|obtener|fetch|get|init)\w*", re.IGNORECASE)


def _statement_start(content: str, idx: int) -> int:
    best = max(content.rfind(";", 0, idx), content.rfind("{", 0, idx), content.rfind("}", 0, idx))
    return best + 1


def _method_body(content: str, name: str) -> str:
    m = re.search(r"\b" + re.escape(name) + r"\s*\([^)]*\)\s*(?::\s*[\w<>\[\]| ]+)?\s*\{", content)
    if not m:
        return ""
    end = _match_close(content, m.end() - 1, "{", "}")
    return content[m.end():end] if end != -1 else ""


def _scan_angular_ts(file_path: str, content: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    is_component = bool(re.search(r"@(Component|Directive|Injectable)\s*\(", content))
    has_on_destroy = "ngOnDestroy" in content
    fname = os.path.basename(file_path)

    # --- subscribe analysis ---------------------------------------------------------------------------------------------------------
    nested_ranges: List[range] = []
    for m in re.finditer(r"\.subscribe\s*\(", content):
        open_p = m.end() - 1
        close_p = _match_close(content, open_p)
        if close_p == -1:
            continue
        inner = content[open_p + 1:close_p]
        stmt = content[_statement_start(content, m.start()):m.start()]

        # ANGULAR-NESTED-SUBSCRIBE (reported once, at the outermost call)
        if re.search(r"\.subscribe\s*\(", inner) and not any(m.start() in r for r in nested_ranges):
            nested_ranges.append(range(open_p, close_p))
            out.append(_f(
                "ANGULAR-NESTED-SUBSCRIBE", "MEDIUM", file_path, _line(content, m.start()),
                "Un subscribe() contiene a otro subscribe() en su callback: las llamadas se encadenan a mano, el error de la interna no se propaga y no se "
                "cancela la anterior si llega una nueva emisión (condición de carrera). Componer con switchMap/concatMap/forkJoin (según sean dependientes o "
                "paralelas) y suscribirse una sola vez."))

        # ANGULAR-SUBSCRIBE-NO-CLEANUP -- only streams that can outlive the component: service streams that are not obviously one-shot HTTP, plus
        # timers/DOM events/sockets. Route streams (paramMap, queryParams...) and form controls of the component itself are cleaned up by Angular.
        if not is_component or _CLEANUP_RE.search(stmt) or has_on_destroy:
            continue
        if re.search(r"\.(paramMap|queryParamMap|params|queryParams|data|fragment|url)\b", stmt) or re.search(r"\.(valueChanges|statusChanges)\b", stmt):
            continue
        svc = re.search(r"this\.(\w*(?:[sS]ervice|[sS]tore|[fF]acade|[sS]tate))\.(\w+)", stmt)
        risky = False
        if _PERSISTENT_SOURCE_RE.search(stmt):
            risky = True
        elif svc and not _FINITE_VERB_RE.match(svc.group(2)) and not _service_method_is_one_shot_http(file_path, content, svc.group(1), svc.group(2)):
            risky = True
        if risky:
            out.append(_f(
                "ANGULAR-SUBSCRIBE-NO-CLEANUP", "MEDIUM", file_path, _line(content, m.start()),
                "Suscripción a un flujo que puede vivir más que el componente (servicio/store/temporizador/evento) sin takeUntilDestroyed, async pipe ni "
                "ngOnDestroy: tras destruir la pantalla el callback sigue ejecutándose y retiene el componente en memoria (fuga acumulativa al navegar). "
                "Usar takeUntilDestroyed(this.destroyRef) o toSignal(). Requiere validación: si el observable es de una sola emisión no hay fuga."))

    # --- ANGULAR-VALUECHANGES-NO-DEBOUNCE ---------------------------------------------------------------------------------------------
    for m in re.finditer(r"\.valueChanges\b", content):
        sub = content.find(".subscribe(", m.end(), m.end() + 400)
        if sub == -1:
            continue
        close_p = _match_close(content, sub + len(".subscribe"))
        chain = content[m.end():close_p if close_p != -1 else sub + 400]
        if "debounceTime" in chain:
            continue
        if re.search(r"this\.\w*(?:[sS]ervice|[sS]tore|[fF]acade)\.\w+\s*\(|\bhttp\.", chain) or re.search(r"this\.(buscar|search|filtrar|cargar|load|consultar)\w*\s*\(", chain):
            out.append(_f(
                "ANGULAR-VALUECHANGES-NO-DEBOUNCE", "MEDIUM", file_path, _line(content, m.start()),
                "Cada cambio del formulario (cada tecla) dispara una consulta porque valueChanges se suscribe sin debounceTime: ráfaga de peticiones al "
                "backend y riesgo de que una respuesta antigua llegue después y sobrescriba la reciente. Usar valueChanges.pipe(debounceTime(300), "
                "distinctUntilChanged(), switchMap(...))."))

    # --- effect() misuse --------------------------------------------------------------------------------------------------------------
    for m in re.finditer(r"\beffect\s*\(", content):
        close_p = _match_close(content, m.end() - 1)
        if close_p == -1:
            continue
        body = content[m.end():close_p]
        if re.search(r"\.subscribe\s*\(|\bthis\.http\b|\bhttp\.(get|post|put|patch|delete)\b|this\.\w*(?:[sS]ervice|[sS]tore|[fF]acade)\.(?!set|update)\w+\s*\([^)]*\)\s*\.\s*subscribe", body):
            out.append(_f(
                "ANGULAR-EFFECT-HTTP", "MEDIUM", file_path, _line(content, m.start()),
                "Un effect() ejecuta una petición HTTP / subscribe. El effect se vuelve a ejecutar cada vez que cambia cualquier señal que lee, y si además "
                "ngOnInit o un evento de la tabla ya cargan los mismos datos se duplican las llamadas (o se forma un ciclo si la respuesta actualiza esa señal). "
                "Disparar la carga desde un evento explícito o derivar el estado con computed/toSignal en lugar de efectos con efectos secundarios de red."))
        for w in set(re.findall(r"this\.(\w+)\.(?:set|update)\s*\(", body)):
            if re.search(r"this\." + re.escape(w) + r"\s*\(\s*\)", body):
                out.append(_f(
                    "ANGULAR-EFFECT-SELF-WRITE", "HIGH", file_path, _line(content, m.start()),
                    f"El effect() lee y a la vez modifica la señal '{w}': es el esquema de un ciclo infinito (el cambio de la señal vuelve a disparar el "
                    f"effect) y Angular lo rechaza salvo con allowSignalWrites. Derivar el valor con computed() o linkedSignal() en lugar de escribir "
                    f"dentro del effect."))
                break

    # --- ANGULAR-HTTP-IN-LOOP (N+1 in the frontend) --------------------------------------------------------------------------------------
    for m in re.finditer(r"\.forEach\s*\(|\bfor\s*\((?:const|let)\s+\w+\s+of\s+[^)]*\)\s*\{", content):
        if m.group(0).startswith(".forEach"):
            end = _match_close(content, m.end() - 1)
        else:
            end = _match_close(content, m.end() - 1, "{", "}")
        body = content[m.end():end] if end != -1 else ""
        if re.search(r"\.subscribe\s*\(|\bhttp\.(get|post|put|patch|delete)\b|lastValueFrom\s*\(|firstValueFrom\s*\(", body):
            out.append(_f(
                "ANGULAR-HTTP-IN-LOOP", "MEDIUM", file_path, _line(content, m.start()),
                "Se hace una petición HTTP por cada elemento de una lista (N+1 en el frontend): N elementos = N llamadas al backend. Pedir los datos "
                "en lote (un endpoint que reciba varios ids o devuelva el DTO completo) o ejecutarlas acotadas con forkJoin/mergeMap(concurrency). "
                "Si requiere un endpoint nuevo, el cambio también es de backend."))

    # --- ANGULAR-SIGNAL-MUTATION-IN-PLACE ------------------------------------------------------------------------------------------------
    signal_names = set(re.findall(r"\b(\w+)\s*=\s*(?:signal|model)\s*[<(]", content))
    for m in re.finditer(r"this\.(\w+)\(\)\s*\.\s*(push|splice|pop|shift|unshift|sort|reverse)\s*\(", content):
        if m.group(1) in signal_names:
            out.append(_f(
                "ANGULAR-SIGNAL-MUTATION-IN-PLACE", "MEDIUM", file_path, _line(content, m.start()),
                f"Se muta el arreglo guardado en la señal '{m.group(1)}' con .{m.group(2)}(): la referencia no cambia, los computed/effect que dependen de "
                f"ella no se recalculan y la vista queda desincronizada. Reemplazar con {m.group(1)}.update(l => [...l, x]) / .set(nuevaCopia)."))

    # --- ANGULAR-DOUBLE-LOAD-INIT-EFFECT -------------------------------------------------------------------------------------------------
    if is_component:
        init = _method_body(content, "ngOnInit")
        if init:
            init_calls = {c for c in re.findall(r"this\.(\w+)\s*\(", init) if _LOAD_NAME_RE.match(c)}
            effect_bodies = ""
            for m in re.finditer(r"\beffect\s*\(", content):
                close_p = _match_close(content, m.end() - 1)
                effect_bodies += content[m.end():close_p] if close_p != -1 else ""
            dup = sorted(c for c in init_calls if re.search(r"this\." + re.escape(c) + r"\s*\(", effect_bodies))
            if dup:
                out.append(_f(
                    "ANGULAR-DOUBLE-LOAD-INIT-EFFECT", "MEDIUM", file_path, _line(content, content.find("ngOnInit")),
                    f"El método {dup[0]}() se invoca desde ngOnInit y también dentro de un effect(): en la carga inicial la consulta puede ejecutarse dos "
                    f"veces. Requiere validación (depende de las señales que lea el effect). Dejar un único disparador."))

    # --- ANGULAR-SETTIMEOUT-WORKAROUND ---------------------------------------------------------------------------------------------------
    if fname.endswith(".component.ts"):
        for m in re.finditer(r"setTimeout\s*\(", content):
            close_p = _match_close(content, m.end() - 1)
            seg = content[m.end():close_p] if close_p != -1 else ""
            if re.search(r",\s*0\s*$", seg.strip()) or re.search(r"detectChanges|markForCheck", seg):
                out.append(_f(
                    "ANGULAR-SETTIMEOUT-WORKAROUND", "LOW", file_path, _line(content, m.start()),
                    "setTimeout con retraso 0 o junto a detectChanges/markForCheck: suele ser un parche para un ExpressionChangedAfterItHasBeenChecked o un "
                    "problema de orden de inicialización, y oculta la causa real. Mover la lógica al hook correcto (ngAfterViewInit, computed, input signal)."))
                break

    # --- TS-EXPLICIT-ANY (one finding per file, not per occurrence) -------------------------------------------------------------------------
    if not fname.endswith(".d.ts"):
        anys = [m for m in re.finditer(r"(?::\s*any\b|<any>|\bas\s+any\b|\bany\[\])", content)]
        if len(anys) >= 5:
            out.append(_f(
                "TS-EXPLICIT-ANY", "LOW", file_path, _line(content, anys[0].start()),
                f"El archivo usa 'any' {len(anys)} veces: se desactiva la verificación de tipos justo donde se manejan datos externos (respuestas HTTP), "
                f"los errores aparecen en tiempo de ejecución en lugar de compilar. Tipar con interfaces/DTO o usar unknown + validación."))
    return out


def _scan_angular_template(file_path: str, content: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # ANGULAR-TEMPLATE-METHOD-IN-LOOP -- the list expression is a METHOD CALL WITH ARGUMENTS: re-evaluated on every change-detection pass and returns a
    # new array each time (re-renders the whole list). Calls with no arguments are skipped: they are indistinguishable from signal reads.
    for m in re.finditer(r"(?:@for\s*\(\s*\w+\s+of\s+|\*ngFor\s*=\s*\"\s*let\s+\w+\s+of\s+)(\w+(?:\.\w+)*)\(([^)]+)\)", content):
        out.append(_f(
            "ANGULAR-TEMPLATE-METHOD-IN-LOOP", "MEDIUM", file_path, _line(content, m.start()),
            f"La lista del bucle se obtiene llamando a {m.group(1)}({m.group(2).strip()}) dentro del template: se reevalúa en cada ciclo de detección de "
            f"cambios y devuelve un arreglo nuevo, lo que re-renderiza toda la lista. Calcularla una vez con computed() (o en el store) y enlazar la señal."))

    # PrimeNG lazy table that also loads from ngOnInit -> the first page is requested twice (onLazyLoad fires on init unless lazyLoadOnInit=false).
    if re.search(r"\(onLazyLoad\)\s*=", content) and not re.search(r"\[lazyLoadOnInit\]\s*=\s*\"false\"", content):
        ts_path = re.sub(r"\.html$", ".ts", file_path)
        try:
            ts = open(ts_path, encoding="utf-8", errors="ignore").read() if ts_path != file_path and os.path.exists(ts_path) else ""
        except OSError:
            ts = ""
        init = _method_body(ts, "ngOnInit") if ts else ""
        calls = [c for c in re.findall(r"this\.(\w+)\s*\(", init) if _LOAD_NAME_RE.match(c)]
        if calls:
            idx = content.find("(onLazyLoad)")
            out.append(_f(
                "ANGULAR-LAZYLOAD-PLUS-INIT-LOAD", "MEDIUM", file_path, _line(content, idx),
                f"La tabla usa (onLazyLoad) y el componente además llama a {calls[0]}() en ngOnInit: onLazyLoad se dispara solo al inicializar la tabla, así que "
                f"la primera página se pide dos veces. Requiere validación (comprobar en la pestaña Red). Quitar la carga de ngOnInit o poner "
                f"[lazyLoadOnInit]=\"false\"."))

    # Submit/save/delete buttons with no busy guard in the template -> double click = two requests.
    for m in re.finditer(r"<(?:p-button|button)\b[^>]*>", content):
        tag = m.group(0)
        if not re.search(r"\(click\)|\(onClick\)|type=\"submit\"", tag):
            continue
        label = re.search(r"label=\"([^\"]*)\"", tag)
        window = content[m.end():m.end() + 120]
        text = (label.group(1) if label else "") + " " + re.sub(r"<[^>]+>", " ", window)
        if not re.search(r"\b(guardar|enviar|eliminar|borrar|crear|registrar|confirmar|aceptar|firmar|save|submit|delete)\b", text, re.IGNORECASE):
            continue
        if re.search(r"\[disabled\]|\[loading\]|\bdisabled\b|\[ngClass\]", tag):
            continue
        out.append(_f(
            "ANGULAR-SUBMIT-NO-BUSY-GUARD", "LOW", file_path, _line(content, m.start()),
            "Botón de acción (guardar/eliminar/enviar) sin [disabled] ni [loading] ligado a un estado de petición en curso: un doble clic envía la operación "
            "dos veces. Requiere validación: el bloqueo puede estar en el método del componente; aun así conviene reflejarlo en el botón."))
        break  # one per template; the fix is a pattern, not per button
    return out


def scan_arch_rules(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Entry point used by scan_sast_code(). Returns [] for vendored/generated/test files and for extensions it does not handle."""
    norm = file_path.replace("\\", "/")
    if _VENDORED_RE.search("/" + norm.lstrip("/")) or _TEST_RE.search(norm):
        return []
    if norm.endswith(".java"):
        return _scan_java_arch(file_path, content)
    if norm.endswith(".ts") and not norm.endswith(".d.ts"):
        return _scan_angular_ts(file_path, content)
    if norm.endswith(".component.html") or norm.endswith(".html"):
        return _scan_angular_template(file_path, content)
    return []
