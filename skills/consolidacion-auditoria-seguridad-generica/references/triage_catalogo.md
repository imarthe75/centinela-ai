# Catálogo de causas raíz y reglas (triage)

El triage separa cada ocurrencia de Centinela en **Vulnerabilidad / Falso positivo / Calidad** por *causa raíz*. Esa decisión es del analista: ningún escáner la deriva.
`triage_report.py` solo la **aplica** desde un catálogo JSON; lo que el catálogo no cubre sale como `SIN CLASIFICAR`, nunca adivinado (regla del proyecto: no inventar).

## Las cuatro preguntas (cómo decidir una causa raíz)
1. ¿Existe en código que se ejecuta? (comentado, archivo copia, datos dummy, dependencia que no se empaqueta o perfil que no llega a producción → falso positivo)
2. ¿Un atacante lo alcanza en producción? (si solo importa cuando otra cosa ya falló → Calidad/endurecimiento; si la premisa de la herramienta no se cumple → falso positivo)
3. ¿Qué se pierde si se explota? (confidencialidad, integridad, disponibilidad, identidad, firmas; si no hay pérdida de seguridad → Calidad/cumplimiento)
4. ¿Se puede demostrar? (prueba mínima en QA; si no se ha hecho, certeza = «Requiere prueba»)
Un falso positivo **nunca** es el valor por defecto de una regla: un hallazgo nuevo que parece el mismo patrón puede ser real.

## Formato (`assets/catalogo_ejemplo.json` es un ejemplo completo)
```json
{"group": {"instance": "primary", "group_path": "grupo/sistema", "title": "SISTEMA", "hours_per_day": 8, "test_pct": 0.3, "fp_check_hours": 0.5,
           "areas": [{"name": "Gerencia de Programación", "people": 1, "dedication": 1}, "... 4 áreas"]},
 "root_causes": [
   {"code": "V-01", "classification": "Vulnerabilidad", "title": "Credenciales en texto claro…", "kind": "Seguridad · manejo de secretos",
    "severity": "Crítico", "certainty": "Confirmada (el reporte muestra los valores)", "how_to_confirm": "…", "strategy": "…", "owner": "Gerencia de … — …",
    "outdated": false, "dedup_scope": "line",
    "plan": {"order": 1, "phase": "1 · Inmediato", "activity": "…", "unit": "por ocurrencia única", "minutes": 60, "minutes_source": "Análisis (…)",
             "extra_hours": 9, "extra_text": "…", "confirm_hours": 0, "area_pct": [0.4, 0.4, 0.2, 0], "fixed_qty": null}},
   {"code": "FP-01", "classification": "Falso positivo", "title": "…", "kind": "Artefacto de desarrollo", "certainty": "Requiere prueba",
    "rationale": "…", "how_to_confirm": "…cuándo reclasificar…"},
   {"code": "C-07", "classification": "Calidad", "title": "…", "kind": "Accesibilidad", "rationale": "…", "strategy": "…", "owner": "…",
    "plan": {"…": "…", "default_criticality": "Medio"}}],
 "rules": [
   {"rule_regex": "^CONFIG-SECRET-LITERAL$", "engine": null, "asset_regex": null, "path_regex": null, "line": null, "root_cause_code": "V-01", "priority": 0, "note": null},
   {"rule_regex": "^CONFIG-SECRET-LITERAL$", "asset_regex": "/servicio-a$", "path_regex": "^src/main/resources/application-(local|develop)\\.properties(:\\d+)?$",
    "root_cause_code": "FP-01", "priority": 10, "note": "perfil de desarrollo"}]}
```
- **Código** = clasificación: `V-` Vulnerabilidad, `FP-` Falso positivo, `C-` Calidad (de ahí sale la clasificación en el libro).
- **Reglas:** `rule_regex` se busca en el id de la regla (para Semgrep el id largo, p. ej. `spring\-actuator`); `engine`, `asset_regex` (contra `GitLab/grupo/sistema/backend/servicio-a`),
  `path_regex` (contra `archivo:línea`) y `line` acotan. Gana la de mayor `priority`: **0** genérica, **10** por archivo, **20** por archivo y línea.
- **Plan:** `minutes` × cantidad = corrección; `extra_hours` trabajo adicional (purga de historial, coordinación…); `confirm_hours` prueba de confirmación; `area_pct` reparto entre las
  4 áreas; `fixed_qty` si la unidad de trabajo no es «una por ocurrencia» (p. ej. 5 saltos de versión mayor); `dedup_scope: "file"` cuando varios motores reportan lo mismo en líneas distintas del
  mismo archivo (un Dockerfile). Solo la columna «Según Centinela» es estimación de la herramienta (SonarQube); lo demás son supuestos del analista y así se rotulan.

## Ciclo de trabajo con un sistema nuevo
1. `parse_centinela.py` → revisar el cuadre contra el encabezado de cada PDF.
2. `triage_report.py … catalogo.json` con un catálogo vacío o heredado de otro proyecto (las causas genéricas —WCAG, `@Version` JPA, Dockerfile sin USER, secretos en `application*.properties`—
   suelen reutilizarse; las específicas no). Sale una lista `SIN CLASIFICAR` agrupada por repositorio y regla.
3. Para cada grupo de esa lista: leer el hallazgo (ubicación, evidencia), aplicar las cuatro preguntas, **proponer** la causa raíz al analista y registrarla solo con su aprobación.
   No cerrar nada como falso positivo sin la condición que lo reabriría.
4. Repetir hasta que `SIN CLASIFICAR = 0` o quede explícitamente pendiente en el informe.
