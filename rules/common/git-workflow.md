# 🌿 Git Workflow & Conventions

Estándares comunes para el control de versiones, formato de commits y flujo de trabajo de ramas en el ecosistema.

*Nota de Atribución: Estas directivas se basan en el flujo de trabajo de contribución del proyecto **affaan-m/ECC** (Licencia MIT).*

## 📌 Formato de Commits (Conventional Commits)

Todos los mensajes de commit deben seguir la especificación de commits convencionales:

*   `feat: ...` para nuevas características.
*   `fix: ...` para corrección de errores.
*   `docs: ...` para cambios exclusivos en documentación.
*   `style: ...` para cambios de formato (espacios, punto y coma, etc.) que no afectan la lógica del código.
*   `refactor: ...` para reestructuración de código sin alterar comportamiento.
*   `test: ...` para añadir o corregir pruebas unitarias/e2e.
*   `chore: ...` para tareas de mantenimiento, actualización de dependencias o builds.

## 📌 Gestión de Ramas y PRs

1. **Ramas cortas:** Crea ramas enfocadas en resolver una única tarea (ej. `feat/ws-alerts` o `fix/valkey-connection`).
2. **Sincronización:** Haz rebase o merge constante de la rama principal (`main`) para evitar conflictos de integración tardía.
3. **No contaminar el historial:** Evita subir archivos temporales, logs o carpetas de datos locales (`data/`, `.env`). Usa siempre el `.gitignore` corporativo.
