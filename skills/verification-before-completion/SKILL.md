---
name: verification-before-completion
description: Compuerta antes de declarar algo terminado: ejecutar el comando de verificación, leer la salida real y el diff, y entregar con estado honesto (COMPLETADO/PARCIAL/FALLIDO) y evidencia. Úsala antes de decir «listo», «funciona» o «corregido».
---

# Skill: Verification Before Completion

**Origen:** Adaptado de [obra/superpowers](https://github.com/obra/superpowers) — MIT License  
**Aplica a:** Antes de declarar cualquier tarea como terminada

---

## Regla absoluta

> **SIN EVIDENCIA FRESCA DE VERIFICACIÓN, NINGUNA AFIRMACIÓN DE "LISTO".**

Ejecutar el comando, leer el output, verificar que confirma lo que afirmas — sólo entonces declarar éxito.

---

## El Gate de Verificación (5 pasos)

Antes de decir "listo", "funciona" o "corregido":

1. **Identifica el comando** que prueba la afirmación.
2. **Ejecútalo en este momento** (no confíes en runs anteriores).
3. **Lee el output completo** y revisa el exit code.
4. **Verifica que el output confirma** específicamente tu afirmación.
5. **Sólo entonces declara éxito** — con el output como evidencia.

---

## Verificaciones por contexto

### Backend Python / FastAPI
```bash
# Tests unitarios
pytest tests/ -v --tb=short
# Exit code 0 = OK, cualquier otro = falla

# Servidor corriendo
curl -s http://localhost:8000/health | jq .
# Debe retornar {"status": "ok"}

# Migración aplicada
alembic current
# Debe mostrar el head de la migración
```

### Frontend Angular
```bash
npm run build
# Sin errores de compilación

npm run test -- --watch=false
# Exit code 0
```

### Base de datos
```bash
psql -U admin -d db_resident_knowledge -c "SELECT COUNT(*) FROM memory.lessons;"
# Número esperado de registros

psql -U admin -d db_resident_knowledge -c "\dx" | grep vector
# pgvector instalado
```

### Docker / Infraestructura
```bash
docker compose ps
# Todos los servicios en estado "running"

docker compose logs --tail=20 [servicio]
# Sin errores recientes
```

---

## Estado y formato de la entrega (ver `clean-code-contract/references/honesty.md`)

Toda entrega declara `COMPLETADO` / `PARCIAL` (con % real) / `FALLIDO`, y trae: matriz de veracidad (requisito · estado real · evidencia), la **salida real** de las pruebas y la deuda pendiente. Lo probado solo con mocks se declara «VALIDADO ÚNICAMENTE CON MOCKS EN AISLAMIENTO (0 % EN PRODUCCIÓN)». Si el proyecto usa resident-agent-os, corre también `python verifiers/run.py` y lee el `git diff` real.

## Palabras prohibidas sin evidencia

Nunca usar estas frases sin output de verificación adjunto:

- "Debería funcionar..."
- "Probablemente está bien..."
- "Parece que..."
- "¡Listo!" (sin evidencia)
- "Corregido" (sin test que lo pruebe)

---

## Integración con el Rito de Cierre

Al terminar sesión, antes de actualizar `.agent/STATE.md`:
1. Ejecuta los tests del módulo trabajado.
2. Verifica que el servicio levanta (`docker compose ps`).
3. Confirma que las migraciones están al día (`alembic current`).

Sólo entonces marca las tareas como completadas en STATE.md.

---

## Skills relacionados

- **test-driven-development**: El test que prueba el comportamiento es la evidencia primaria
- **systematic-debugging**: Si la verificación falla, usar debugging sistemático — no adivinar
