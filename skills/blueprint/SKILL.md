---
name: blueprint
description: Traza un plan de ejecución por componentes antes de modificar código (investigación de contexto, plan con verificación por tarea, aprobación explícita y cierre verificado). Úsala con /plan, «crear un plan de ejecución» o antes de un cambio de varios archivos.
---

# 🗺️ Skill: Architectural Construction Blueprint

Este skill le permite al Agente Residente trazar un mapa de ejecución estructurado antes de realizar modificaciones en el código.

## ⚙️ Trigger
- "crear un plan de ejecución"
- "trazar blueprint"
- `/plan`

## 📋 Proceso de Ejecución (ECC Flow)

1. **Investigación Contextual:**
   - Lee el mapa técnico y el estado del proyecto si existen (`.agent/MAP.md`, `.agent/STATE.md`, `README.md`, ADRs en `DECISIONS/`).
   - Ejecuta `preflight` sobre los archivos que vas a tocar.
   
2. **Generación del Plan:**
   - Divide la tarea compleja en componentes atómicos.
   - Crea un plan de implementación en `implementation_plan.md` con su metadata.
   - Pide aprobación explícita al usuario antes de modificar cualquier archivo de producción.

3. **Verificación Pos-Ejecución:**
   - Valida que el código compile y pase los linters locales.
   - Registra el avance en la bitácora del proyecto (`.agent/STATE.md` o equivalente) y sigue `verification-before-completion`.

## Seguridad y calidad en el plan
Por componente, anota las reglas del catálogo de `prevencion-hallazgos-seguridad-calidad` que aplican y cómo se verificarán.
