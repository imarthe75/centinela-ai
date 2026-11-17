---
name: estandares-desarrollo-org
description: Estándares obligatorios de desarrollo para todos los proyectos org — código real, documentación (código, OpenAPI, base de datos), seguridad verificada, base de datos con auditoría, reglas por lenguaje (Java/Spring Boot, Angular/TypeScript, Python, SQL) y evidencia CMMI/ISO — con la skill que aplica en cada caso y plantillas AGENTS.md/CLAUDE.md para la raíz del proyecto. Cárgala junto con reglas-globales-org al iniciar trabajo en un proyecto.
---

# Estándares de desarrollo org

Aplican a todo proyecto de la empresa. Base de arranque: el Starter de GitLab (`starters/`). Escáner de seguridad: Centinela (consulta previa
con `preflight`, corrección regla por regla en `prevencion-hallazgos-seguridad-calidad`). Auditoría de base de datos: Estándar de auditoría org
(`postgres-audit`). Metodología de entregables: the organization (CMMI V3.0), skills `generador-entregables-ca` (v4.9.0) y `resident-entregables-ca`; reglas de negocio de los módulos del CORE en `reglas-negocio-core-starter`.

## Obligatorio en todo cambio
| Tema | Regla mínima | Detalle |
|---|---|---|
| Código real | Sin datos simulados, maquetas, `TODO` ni funciones vacías en el código de la aplicación; mocks solo en pruebas | `reglas-globales-org` §2.1 |
| Documentación | Javadoc/TSDoc/docstring en API pública; OpenAPI completo en cada endpoint; `COMMENT ON` en BD; README por módulo; ADR por decisión | `documentacion-codigo-y-api` |
| Seguridad | Secretos fuera del código; autenticación OIDC; autorización en cada endpoint; validación de entrada; errores sin fuga; cero hallazgos nuevos de Centinela | `backend-seguridad`, `frontend-auth-oidc`, `clean-code-contract`, `prevencion-hallazgos-seguridad-calidad` |
| Base de datos | Migraciones idempotentes; PK `uuidv7()`; `timestamptz`, `jsonb`, `numeric`; columnas y triggers de auditoría | `database-liquibase-postgresql`, `postgres-audit` |
| Pruebas | Caso positivo y negativo por regla; 401/403/409 en API; contra servicios reales desechables | `test-driven-development`, `backend-pruebas-unitarias`, `generacion-pruebas-servicios` |
| Proceso | Requisito trazable, MR revisado por otra persona, CI en verde, tags, ADR | `cumplimiento-cmmi-iso` |
| Entrega | Estado honesto con evidencia ejecutada | `verification-before-completion` |

## Qué skill cargar según la tarea
| Tarea | Skills |
|---|---|
| Endpoint o módulo Spring Boot | `backend-base-spring`, `backend-modulo-crud` / `backend-endpoint-paginado`, `backend-soporte-api`, `backend-persistencia-jpa`, `documentacion-codigo-y-api` |
| Pantalla Angular | `primeng21-expert` (tabla de ruteo), `generacion-componentes-ts`/`-html`, `generacion-servicios`, `frontend-heuristicas-usabilidad` |
| Migración SQL | `database-liquibase-postgresql`, `postgres-audit` |
| Pruebas | `backend-pruebas-unitarias`, `bdd-spec-driven-development`, `bdd-frontend-playwright`, `generacion-pruebas-servicios` |
| Cualquier código, configuración, SQL, Dockerfile o pipeline | `prevencion-hallazgos-seguridad-calidad` (reglas del escáner y lista de chequeo antes de entregar) |
| Plan o cambio grande | `blueprint`, `writing-plans`, `preflight` |
| Consolidar una auditoría de seguridad o verificar un cierre | `triage-findings`, `consolidacion-auditoria-seguridad-generica` |
| Requerimientos, diseño funcional, pruebas/UAT o ticket de soporte | `metodologia-ca` (Manual v3.7 y guías) |
| Entregable de metodología the organization | `generador-entregables-ca` (genera el `.docx`), `resident-entregables-ca` (evidencia de Centinela) |
| Módulo del CORE/Starter (usuarios, roles, menús, folios, bitácora, correos, citas…) | `reglas-negocio-core-starter` |
| Error o prueba que falla | `systematic-debugging` |

Reglas por lenguaje: `clean-code-contract/references/` (`java.md`, `angular.md`, `typescript.md`, comunes). Lo que Centinela detecta y cómo
corregirlo: `prevencion-hallazgos-seguridad-calidad`.

## Kit de agente para la raíz del proyecto (`templates/`)
Copia el contenido de `templates/` a la raíz del repositorio y las skills a `.claude/skills/` (Claude Code) o `.agents/skills/` (otros
agentes):
| Archivo o carpeta | Para qué |
|---|---|
| `AGENTS.md` | Instrucciones para cualquier agente (Codex, Gemini, Copilot, Claude). Llena la sección «Proyecto». |
| `CLAUDE.md` | Claude Code; remite a `AGENTS.md` para no duplicar reglas. |
| `rules/` | Reglas detalladas: Centinela (`rules/centinela/`), comunes (honestidad, seguridad por capa, documentación, CMMI/ISO, BD, pruebas, accesibilidad, versiones) y por lenguaje (Java/Spring Boot, Angular, TypeScript, Python, PostgreSQL). |
| `agents/` | Subagentes de revisión de código, de seguridad, arquitecto y planificador. |
| `contexts/` | Modos de trabajo: desarrollo, revisión, investigación. |

`AGENTS.md` enumera estas carpetas: un agente que lo lee encuentra el resto. Al cambiar una regla aquí, se cambia también en
`clean-code-contract/references/` si tiene equivalente.
