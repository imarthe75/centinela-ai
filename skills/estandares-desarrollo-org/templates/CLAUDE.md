# CLAUDE.md

Las reglas de este proyecto están en [`AGENTS.md`](AGENTS.md) y son obligatorias para Claude Code igual que para cualquier otro agente.

Al iniciar una tarea: lee `AGENTS.md` (y las reglas de `rules/` que toque el cambio), carga las skills `reglas-globales-org` y `estandares-desarrollo-org`, `prevencion-hallazgos-seguridad-calidad` si vas a escribir o revisar código, y la skill del stack que vas a tocar.
Antes de declarar algo terminado: `verification-before-completion`.

Para revisar un cambio usa los subagentes de `agents/`; para el modo de trabajo, `contexts/`.
