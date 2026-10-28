---
name: systematic-debugging
description: Depuración sistemática: reproducir, aislar, formular una hipótesis a la vez, comprobar con evidencia de origen y detenerse tras 3 intentos fallidos para replantear. Úsala ante cualquier error, prueba que falla o comportamiento inesperado.
---

# Skill: Systematic Debugging

**Origen:** Adaptado de [obra/superpowers](https://github.com/obra/superpowers) — MIT License  
**Aplica a:** Cualquier bug, fallo de test o comportamiento inesperado

---

## Ley de Hierro

```
NO FIXES SIN INVESTIGACIÓN DE CAUSA RAÍZ PRIMERO
```

Los parches al síntoma enmascaran el problema real. Los fixes aleatorios crean bugs nuevos.

**Si no completaste la Fase 1, no puedes proponer ningún fix.**

---

## Las 4 Fases (en orden estricto)

### Fase 1 — Investigación de Causa Raíz

**ANTES de cualquier fix:**

1. **Lee el error completo** — no saltes el stack trace; contiene la solución.
2. **Reproduce consistentemente** — si no puedes reproducirlo, recopila más datos.
3. **Revisa cambios recientes** — `git diff`, últimos commits, cambios de config.
4. **En sistemas multi-componente, instrumenta cada capa:**

```python
# Ejemplo: API → Valkey → PostgreSQL
print(f"[DEBUG] Query a Valkey: {query_embedding[:10]}...")
result = cache.get(query_embedding)
print(f"[DEBUG] Cache hit: {result is not None}")
if not result:
    print(f"[DEBUG] Consultando PostgreSQL...")
    result = db.search_lessons(query_embedding)
    print(f"[DEBUG] DB rows: {len(result)}")
```

5. **Rastrea el flujo de datos** hasta encontrar dónde diverge del valor esperado.

### Fase 2 — Análisis de Patrones

1. Encuentra código **similar que sí funciona** en el mismo proyecto.
2. Compara diferencia por diferencia con el código roto.
3. No asumas que "eso no puede importar" — lista todo.

### Fase 3 — Hipótesis y Test

1. Formula **una sola hipótesis**: "Creo que X es la causa porque Y."
2. Haz el **cambio mínimo** para probar esa hipótesis.
3. Verifica si funcionó. Si no: formula **hipótesis nueva** (no acumules fixes).

### Fase 4 — Implementación

1. **Crea el test que reproduce el bug** (ver `skills/test-driven-development/SKILL.md`).
2. **Implementa el fix único** — sólo la causa raíz, sin "ya que estoy aquí".
3. Verifica que el test pasa y que no rompiste otros tests.

---

## Límite ECC: 3 intentos

| Intentos fallidos | Acción |
|-------------------|--------|
| < 3 | Regresar a Fase 1 con la nueva información |
| ≥ 3 | **HALT** — cuestiona la arquitectura, consulta `memory.lessons`, discute con el usuario |

Tres fixes fallidos indican **problema arquitectónico**, no de implementación.

---

## Señales de alerta — regresa a Fase 1

- "Fix rápido y luego investigo"
- "Cambio esto a ver si funciona"
- "Voy a cambiar varias cosas a la vez"
- "Ya sé qué es, no necesito investigar"
- Cada fix revela un nuevo problema en otro lugar

---

## Skills relacionados

- **test-driven-development**: Para crear el test que reproduce el bug (Fase 4)
- **verification-before-completion**: Para confirmar que el fix realmente funciona


---

## Verifica la evidencia cruda, no el registro
Que exista una fila reciente, un archivo o un log de «éxito» no prueba que algo ocurrió. Antes de dar una causa por cierta, comprueba la evidencia de origen (la salida real del comando, el hash, el contenido del archivo). Y un cambio que ya está en el código no demuestra que los datos lo reflejen: vuelve a ejecutar y compara con la fuente. Registra la lección en la memoria del proyecto (STATE.md o equivalente).
