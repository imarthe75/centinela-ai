#!/usr/bin/env python3
"""Arma el kit de agente org descargable (zip).

Estructura del zip:
  kit_agente_org/
    README.md            instalación
    AGENTS.md, CLAUDE.md reglas de raíz (desde skills/estandares-desarrollo-org/templates)
    rules/ agents/ contexts/
    skills/              las skills compartidas (sin las privadas de Centinela)

Uso: python3 scripts/build_agent_kit.py [--out data/reports/kit_agente_org_<fecha>]
"""
import argparse
import datetime
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
TEMPLATES = SKILLS / "estandares-desarrollo-org" / "templates"
# Skills internas: catálogos de triage de clientes y ejemplos que no aplican fuera de Centinela.
PRIVATE = {"consolidacion-auditoria-seguridad.skill", "consolidacion-auditoria-seguridad-v2", "example_mcp_skill.py"}
IGNORE = shutil.ignore_patterns("node_modules", "__pycache__", "*.pyc", ".DS_Store")

README = """# Kit de agente org ({date})

Reglas, subagentes, contextos y skills para que cualquier agente de IA (Claude Code, Codex, Gemini/Antigravity, Copilot) desarrolle con los
estándares org: código real, documentación (código, OpenAPI, base de datos), seguridad verificada por Centinela, base de datos con el
Estándar de auditoría org y evidencia CMMI V3.0 / ISO 27001.

## Instalación en un proyecto
1. Copia a la raíz del repositorio: `AGENTS.md`, `CLAUDE.md`, `rules/`, `agents/`, `contexts/`.
2. Copia `skills/` a `.claude/skills/` (Claude Code) y/o `.agents/skills/` (otros agentes).
3. Llena la sección «Proyecto» de `AGENTS.md` (qué es, stack, cómo se levanta y prueba, servicios externos sin credenciales).
4. Si el proyecto ya tenía `AGENTS.md`/`CLAUDE.md`, conserva lo propio del proyecto y añade las secciones del kit; gana la regla más estricta.

## Contenido
| Ruta | Qué es |
|---|---|
| `AGENTS.md` | Reglas obligatorias resumidas y mapa del resto del kit |
| `CLAUDE.md` | Entrada para Claude Code; remite a `AGENTS.md` |
| `rules/` | Reglas detalladas comunes y por lenguaje |
| `agents/` | Subagentes de revisión de código, de seguridad, arquitecto y planificador |
| `contexts/` | Modos de trabajo: desarrollo, revisión, investigación |
| `skills/` | {n} skills; índice en `skills/README.md` |
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    date = datetime.date.today().isoformat()
    ap.add_argument("--out", default=str(ROOT / "data" / "reports" / f"kit_agente_org_{date}"))
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    kit = out / "kit_agente_org"
    if kit.exists():
        shutil.rmtree(kit)
    kit.mkdir(parents=True)
    for item in ("AGENTS.md", "CLAUDE.md"):
        shutil.copy2(TEMPLATES / item, kit / item)
    for folder in ("rules", "agents", "contexts"):
        shutil.copytree(TEMPLATES / folder, kit / folder, ignore=IGNORE)
    (kit / "skills").mkdir()
    n = 0
    for entry in sorted(SKILLS.iterdir()):
        if entry.name in PRIVATE:
            continue
        if entry.is_dir():
            shutil.copytree(entry, kit / "skills" / entry.name, ignore=IGNORE)
            n += 1
        else:
            shutil.copy2(entry, kit / "skills" / entry.name)
    (kit / "README.md").write_text(README.format(date=date, n=n), encoding="utf-8")
    archive = shutil.make_archive(str(out / f"kit_agente_org_{date}"), "zip", root_dir=out, base_dir="kit_agente_org")
    print(f"{n} skills · zip: {archive}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
