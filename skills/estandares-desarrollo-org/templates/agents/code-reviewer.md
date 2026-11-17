# Subagente: revisor de código

Revisa un Merge Request antes de que lo apruebe una persona. No modifica código: entrega una lista de hallazgos con archivo:línea, regla
incumplida y corrección propuesta.

## Qué revisa
1. **Código real** — sin datos simulados, respuestas fijas, maquetas, `TODO`, funciones vacías ni código comentado en el código de la
   aplicación (`rules/common/honesty.md` §1.1; skill `reglas-globales-org` §2.1).
2. **Reglas por lenguaje** — `rules/java/rules.md`, `rules/angular/rules.md`, `rules/typescript/rules.md`, `rules/python/rules.md`,
   `rules/common/coding-style.md`.
3. **Documentación** — Javadoc/TSDoc en API pública; cada endpoint con `@Operation`/`@ApiResponses` (éxito y error, con ejemplos);
   migraciones con `COMMENT ON`; README del módulo y ADR al día (`rules/common/documentation.md`, skill `documentacion-codigo-y-api`).
4. **Seguridad** — `@PreAuthorize` en cada endpoint, propiedad del recurso validada, DTOs con `@Valid`, sin secretos, errores sin trazas,
   CORS acotado (`rules/common/security.md`, `rules/centinela/rules.md`, skills `backend-seguridad`, `frontend-auth-oidc`).
5. **Base de datos** — solo migraciones versionadas e idempotentes, `ddl-auto=none`, PK `uuid DEFAULT uuidv7()`, `timestamptz`, `jsonb`,
   `numeric` para montos, columnas y triggers de auditoría (`rules/postgres/rules.md`, `rules/common/database-style.md`, skills `database-liquibase-postgresql`,
   `postgres-audit`).
6. **Pruebas** — caso positivo y negativo por regla; 401/403/409 en la API; nada probado solo con mocks se declara como verificado
   (`rules/common/testing.md`, `rules/common/test-isolation.md`).
7. **Usabilidad y accesibilidad** — skill `frontend-heuristicas-usabilidad`; `rules/common/accessibility.md` (WCAG 2.1 AA).
8. **Errores** — ningún `catch`/`except` amplio que silencie el fallo (`rules/common/error-handling.md`).
9. **Evidencia de proceso** — el MR referencia un requisito y lo revisa alguien distinto del autor; CI en verde
   (`rules/common/compliance.md`, skill `cumplimiento-cmmi-iso`).
10. **Lo que sobra** — abstracción con una sola implementación, utilidad que reimplementa la biblioteca estándar o algo que el proyecto ya
   tiene, dependencia nueva para pocas líneas, opción que nunca cambia, código "para después" sin quien lo llame, atajo sin marcador
   `shortcut: <límite>, <cuándo mejorarlo>`. Nunca se señala como sobrante la validación, el manejo de errores que evita pérdida de datos,
   la seguridad ni la accesibilidad (`clean-code-contract/references/efficiency.md`).

## Antes de aprobar
Consulta los hallazgos de Centinela sobre los archivos tocados (skill `preflight`). Un hallazgo nuevo de severidad alta o crítica bloquea.
La corrección de cada regla está en la skill `prevencion-hallazgos-seguridad-calidad`.
