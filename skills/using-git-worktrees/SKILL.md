---
name: using-git-worktrees
description: Trabajo en paralelo con git worktrees: crear un árbol de trabajo aislado por tarea o rama, verificar que la línea base pasa las pruebas antes de cambiar y limpiar al terminar.
---

# Skill: Using Git Worktrees

**Origen:** Adaptado de [obra/superpowers](https://github.com/obra/superpowers) — MIT License  
**Aplica a:** Desarrollo paralelo, features aisladas, experimentos sin riesgo

---

## Para qué sirve

Los git worktrees permiten trabajar en múltiples ramas **en paralelo** sin hacer stash ni cambiar de rama. Cada worktree es un directorio independiente con su propio working tree, pero comparte el objeto `.git`.

Casos de uso:
- Desarrollar un feature mientras se revisa otro en paralelo
- Probar una migración de DB sin afectar el trabajo actual
- Aislar experimentos (nuevo módulo, refactor) del main trunk
- Subagentes trabajando en tareas independientes simultáneamente

---

## Paso 0 — Detección (SIEMPRE primero)

Antes de cualquier acción, verifica si ya estás en un worktree:

```bash
# Si GIT_DIR != GIT_COMMON_DIR estás en un worktree
git rev-parse --git-dir
git rev-parse --git-common-dir
# Si son distintos: ya estás en worktree — NO crees otro anidado
```

---

## Crear un worktree

```bash
# Directorio preferido: .worktrees/ (ya en .gitignore)
git worktree add .worktrees/mi-feature feature/mi-feature

# O desde una nueva rama
git worktree add .worktrees/experimento -b experimento/nuevo-modulo

# Verificar que está ignorado ANTES de crearlo
git check-ignore .worktrees/
```

---

## Flujo de trabajo

```bash
# 1. Crear worktree
git worktree add .worktrees/fix-auth fix/auth-middleware

# 2. Entrar al worktree
cd .worktrees/fix-auth

# 3. Instalar deps si aplica
pip install -r requirements.txt  # o npm install

# 4. Verificar que los tests pasan antes de modificar
pytest tests/ -q

# 5. Desarrollar con TDD normal

# 6. Al terminar, regresar y limpiar
cd /path/al/proyecto
git worktree remove .worktrees/fix-auth
```

---

## Reglas de seguridad

1. **Nunca crear worktrees anidados** (worktree dentro de worktree).
2. **Siempre verificar `git check-ignore`** antes de crear en directorio del proyecto.
3. **Agregar `.worktrees/` al `.gitignore`** (ya está en el `.gitignore` del framework).
4. **Limpiar worktrees al terminar:** `git worktree prune` elimina entradas obsoletas.

---

## Ver worktrees activos

```bash
git worktree list
# salida:
# /path/proyecto      abc1234 [main]
# /path/.worktrees/fix  def5678 [fix/auth-middleware]
```

---

## Integración con subagentes

Cuando se despachan múltiples subagentes en paralelo (ver `skills/subagent-driven-development/`), cada agente debe operar en su propio worktree para evitar conflictos de archivos:

```
Agente principal → crea worktrees → despacha subagentes
Subagente A → .worktrees/feature-a
Subagente B → .worktrees/feature-b
Agente principal → hace merge al terminar
```
