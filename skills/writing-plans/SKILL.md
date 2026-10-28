---
name: writing-plans
description: Escribe planes de implementación por tareas pequeñas, cada una con archivos, cambios y comando exacto de verificación, incluyendo las restricciones obligatorias de los proyectos org.
---

# Skill: Writing Plans

**Origen:** Adaptado de [obra/superpowers](https://github.com/obra/superpowers) — MIT License  
**Aplica a:** Cualquier feature o cambio que requiera más de 1 archivo o 15 min de trabajo

---

## Para qué sirve

Un plan convierte un objetivo en tareas independientes, verificables y de 2-5 minutos cada una. Elimina la ambigüedad antes de escribir código y permite que subagentes ejecuten con contexto mínimo.

---

## Cuándo crear un plan

- Feature nueva con múltiples capas (DB + backend + frontend)
- Refactor que toca más de 3 archivos
- Migración de datos o esquema
- Integración de servicio externo
- Cualquier cambio donde no es obvio el orden de pasos

---

## Estructura del plan

Guardar en `docs/plans/YYYY-MM-DD-<nombre-feature>.md`:

```markdown
# Plan: [Nombre del Feature]
**Fecha:** YYYY-MM-DD
**Objetivo:** [Una oración de qué se va a construir y por qué]
**Arquitectura:** [Qué capas toca: DB / backend / frontend / infra]
**Stack:** [Python 3.12, FastAPI, Angular 18, PostgreSQL 18, Valkey]
**Restricciones:** [UUID v7, audit triggers, OIDC auth, etc.]

---

## Mapa de archivos

| Archivo | Acción | Propósito |
|---------|--------|-----------|
| `backend/app/models/nuevo.py` | crear | Modelo SQLAlchemy |
| `backend/app/routers/nuevo.py` | crear | Endpoints FastAPI |
| `db/migrations/NNN_nuevo.sql` | crear | Migración |
| `frontend/src/app/nuevo/` | crear | Componente Angular |

---

## Tarea 1: [Nombre corto]
**Archivos:** `backend/app/models/nuevo.py`
**Input:** ninguno
**Output:** clase `NuevoModel` con campos X, Y, Z

**Pasos:**
- [ ] Escribir test: `pytest tests/test_nuevo.py::test_modelo` → FAIL
- [ ] Implementar modelo con UUID v7 PK
- [ ] Verificar: `pytest tests/test_nuevo.py::test_modelo` → PASS
- [ ] Commit: `feat(models): add NuevoModel with uuid v7 pk`

---

## Tarea 2: ...
```

---

## Principios de granularidad

- Cada tarea: **1 unidad de trabajo verificable** (un test que pasa = tarea completa)
- Cada tarea: máximo **2-5 minutos** de implementación
- Cada tarea incluye: **comando exacto de verificación**
- Las tareas son **independientes** o tienen dependencias explícitas

---

## Restricciones mandatorias en planes

Todo plan de un proyecto org contempla (y cada punto tiene su tarea con comando de verificación):
1. **PK `uuid` con `uuidv7()`** y columnas canónicas en tablas nuevas (`database-liquibase-postgresql`).
2. **Auditoría de BD** según el Estándar org: `auditoria.asignar_triggers(...)` y, si se pide bitácora, `habilitar_auditoria` (`postgres-audit`).
3. **`@PreAuthorize`** en cada endpoint nuevo y prueba de 403 por rol (`backend-base-spring`, `backend-pruebas-unitarias`).
4. **Prueba antes del código** (`test-driven-development`); caso que pasa y caso que falla.
5. **Sin secretos** en el diff (`reglas-globales-org`).
6. **Escaneo de Centinela** sobre los archivos tocados y cero hallazgos nuevos, o declarar «no verificado por escáner» (`preflight`, `centinela-developer-standards`).
7. **Verificación de salud** del servicio al final del plan.

---

## Modos de ejecución

Al guardar el plan, proponer al usuario:

**A) Subagent-Driven (recomendado para planes >5 tareas)**  
→ Un subagente fresco por tarea, con review entre tareas  
→ Ver `agents/architect.md` para el workflow

**B) Inline (para planes ≤5 tareas simples)**  
→ El agente ejecuta las tareas en secuencia en la misma sesión  
→ Checkpoint de verificación entre cada tarea

---

## Skills relacionados

- **test-driven-development**: Cada tarea del plan sigue el ciclo RED-GREEN-REFACTOR
- **verification-before-completion**: Verificar antes de marcar cada tarea como completada
- **opsx-propose**: Crear el spec formal antes de escribir el plan
