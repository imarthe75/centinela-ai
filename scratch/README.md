# scratch/ — área de trabajo NO versionada

Regla del proyecto: **el código del producto va a git; los análisis personalizados no.**

Todo lo que vive en esta carpeta queda fuera del control de versiones
(`scratch/` está en `.gitignore`, con la única excepción de este `README.md`).

## Qué va aquí

- Escaneos y auditorías por cliente / por grupo de GitLab
  (`*_scan_*.json`, `scan_*.py`, `recon_*.py`, `_nmap_*`, `_nuclei_*`, `_recon_*`).
- Scripts de un solo uso: backfills, migraciones ad-hoc, comparativas,
  generadores de reporte (`build_*_report*.py`, `emit_*_pdf*.py`).
- Reportes generados para entrega: `*.html`, `*.pdf`, `*.zip`,
  carpetas `entrega_*/`, `reportes_perproject/`.
- Logs de corridas (`_run_*.log`).

## Qué NO va aquí

- Cambios en el motor: `centinela.py`, `main.py`, `sentinel.py`,
  `core/`, `auditors/`, `discovery/`, `remediation/`, `frontend/` (código),
  `tests/`, `core/schema.py`, migraciones de esquema reutilizables, etc.
  Eso se edita en su lugar y se commitea normalmente.

## Cómo mover algo de scratch/ al producto

Si un script ad-hoc madura y debe formar parte del producto, muévelo a su
paquete real (`scripts/`, `core/`, `auditors/`, …), quítale las rutas
absolutas a `/opt/centinela-ai/scratch/`, agrégale pruebas en `tests/` y
haz commit desde esa ubicación.
