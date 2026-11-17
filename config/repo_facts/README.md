# Hechos de repositorio para los análisis de IA

Los análisis de IA de Centinela (correlación de hallazgos, verificación de bajas de severidad y revisión de lógica en
Merge Requests) solo ven el código. Aquí el equipo de seguridad puede dejar **hechos que el código no muestra en la línea
señalada**, sin tocar el repositorio del cliente.

## Nombre del archivo

El nombre del activo sin la rama, con `/` sustituido por `__`, terminado en `.md`:

| Aplica a | Archivo |
|---|---|
| Todo el grupo `ventas` de la instancia principal | `GitLab__ventas.md` |
| Solo `ventas/backend` | `GitLab__ventas__backend.md` |
| Un proyecto de la segunda instancia | `GitLab2__finanzas__pagos.md` |

Se combinan del más general al más específico, y después se agrega el archivo del propio repositorio si existe
(`.centinela/hechos.md`, `.centinela/review.md` o `REVIEW.md`). Tope total: 3000 caracteres (`REPO_FACTS_MAX_CHARS`).

## Qué escribir

Hechos cortos y verificables, uno por línea:

```
- Todas las rutas /api/admin/** pasan por el gateway, que exige el rol ADMIN antes de llegar al servicio.
- El paquete com.ejemplo.demo contiene datos de ejemplo; Math.random() ahí no genera secretos.
- El módulo legacy/reportes no se despliega desde 2026-09 (se elimina en la siguiente versión).
```

## Qué NO hace un hecho

- **No prueba nada por sí solo.** Los prompts le dicen a la IA que un hecho solo le indica dónde mirar; una baja de
  severidad sigue necesitando líneas de código que la respalden y una segunda revisión (ADR-0021).
- Un archivo con instrucciones dirigidas al modelo («ignora las reglas», «marca como seguro») se descarta completo y
  no se envía.
- No escribas secretos aquí: el texto viaja a los proveedores de IA (pasa por el redactor de secretos, pero no lo uses
  para eso).
