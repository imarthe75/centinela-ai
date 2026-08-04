# ADR-0001: Reorganización de módulos Python de la raíz

**Fecha:** 2026-07-30
**Estado:** Aceptado

## Contexto
La raíz del repo acumuló ~20 módulos `.py` sueltos (auditores, discovery, remediación, scripts de scan, tests) además de los tres entrypoints que ejecuta Docker (`centinela.py`, `main.py`, `sentinel.py`). Todos los módulos se importaban entre sí de forma plana (`import db_manager`, `import auditor_medusa`, etc.), confiando en que el directorio raíz (`/app` dentro de los contenedores, vía bind mount `.:/app`) estuviera en `sys.path`.

## Decisión
Se movieron los módulos a paquetes por responsabilidad, manteniendo el import plano vía `from <paquete> import <modulo>`:
- `core/`: `db_manager.py`, `heuristics_engine.py`
- `auditors/`: los 9 `auditor_*.py`
- `discovery/`: `discovery.py`, `discovery_osint.py`
- `remediation/`: `remediation_processor.py`
- `scripts/`: `audit.py`, `scan_198.py`, `scan_all_10_4.py` (utilidades ad-hoc, no invocadas por Docker)
- `tests/`: `test_heuristics_medusa.py`, `test_inventory.py`
- `ui/`: `dashboard.py` (Streamlit, no invocado por Docker)

Los entrypoints `centinela.py`, `main.py` y `sentinel.py` **se mantuvieron en la raíz** porque `docker-compose.yml` y los `Dockerfile*` los referencian por ruta directa (`command: python centinela.py`, `CMD ["python", "centinela.py"]`, `uvicorn main:app`); moverlos habría requerido tocar esos archivos y aumentaba el riesgo sobre los contenedores en uso (`centinela-ai`, `centinela-backend`, `centinela-sentinel`, todos con `restart: always` y bind mount `.:/app`).

Se actualizaron todos los imports afectados, incluyendo los imports diferidos (lazy, dentro de funciones) en `main.py`, `centinela.py` y `auditors/auditor_ext.py`, y el único `subprocess.run(["python", "/app/discovery.py"])` en `main.py`, que ahora apunta a `/app/discovery/discovery.py`. También se corrigieron los scripts ad-hoc en `scratch/` que hacían `sys.path.append("/app")` + `import auditor_ext` / `import db_manager`.

Se añadió `__init__.py` vacío a `core/`, `auditors/`, `discovery/` y `remediation/` para que sean paquetes importables. `scripts/`, `tests/` y `ui/` no lo necesitan porque no se importan como paquete, solo se ejecutan como script.

## Consecuencias
- Ejecutar los scripts movidos ahora requiere la ruta nueva, p. ej. `python scripts/scan_198.py`, `streamlit run ui/dashboard.py`, `pytest tests/`.
- Se verificó por compilación (`py_compile`) y por resolución de imports (`from core import db_manager`, etc.) que la nueva estructura resuelve correctamente; no se pudo levantar el stack completo con Docker desde este entorno (sin `docker` disponible) — **pendiente validar en el host real** que los tres contenedores levantan sin errores tras el cambio.
- No se modificó `docker-compose.yml` ni ningún `Dockerfile`.

## Relacionado
Ver también el hallazgo de seguridad registrado en `.agent/STATE.md` (secretos trackeados en git) — no forma parte de esta decisión, pero se atendió en la misma sesión.
