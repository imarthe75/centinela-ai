# 🗺️ Skill: Architectural Construction Blueprint

Este skill le permite al Agente Residente trazar un mapa de ejecución estructurado antes de realizar modificaciones en el código.

## ⚙️ Trigger
- "crear un plan de ejecución"
- "trazar blueprint"
- `/plan`

## 📋 Proceso de Ejecución (ECC Flow)

1. **Investigación Contextual:**
   - Lee el mapa técnico actual en `.agent/MAP.md`.
   - Consulta el estado y los pendientes en `.agent/STATE.md`.
   
2. **Generación del Plan:**
   - Divide la tarea compleja en componentes atómicos.
   - Crea un plan de implementación en `implementation_plan.md` con su metadata.
   - Pide aprobación explícita al usuario antes de modificar cualquier archivo de producción.

3. **Verificación Pos-Ejecución:**
   - Valida que el código compile y pase los linters locales.
   - Registra el avance en `task.md`.
