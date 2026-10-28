"""
Análisis de código fuente subido como ZIP (alta de activo tipo "Código fuente (ZIP)").

El ZIP se extrae de forma segura a data/uploaded_sources/<slug>/ (directorio interno, nunca servido
por el frontend) y se audita con el mismo conjunto de motores que el escaneo de repos GitLab, salvo
los que dependen de la API de GitLab (configuración de proyecto, evidencia CMMI de MR/CI).
"""
import os
import re
import shutil
import stat
import threading
import traceback
import zipfile

from core import db_manager

UPLOAD_ROOT = os.getenv("UPLOADED_SOURCES_DIR", "/app/data/uploaded_sources")
MAX_ZIP_BYTES = 300 * 1024 * 1024          # tamaño del ZIP subido
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024  # tope contra zip-bombs
MAX_FILES = 60000
_audit_lock = threading.Lock()  # una auditoría de ZIP a la vez (Semgrep/SonarQube son pesados)


class ZipRejected(ValueError):
    """El ZIP no es seguro o excede los límites."""


def asset_name_for(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", (name or "").strip()).strip("-.")
    if not clean:
        raise ZipRejected("Nombre de activo inválido.")
    return clean if clean.startswith("Local/") else f"Local/{clean}"


def _slug(asset_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "__", asset_name)


def safe_extract(zip_path: str, dest: str) -> int:
    """Extrae `zip_path` en `dest` rechazando zip-slip, enlaces simbólicos, zip-bombs y ZIPs enormes.
    Devuelve el número de archivos extraídos. Lanza ZipRejected ante cualquier problema (no extrae a medias en silencio)."""
    if not zipfile.is_zipfile(zip_path):
        raise ZipRejected("El archivo no es un ZIP válido.")
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ZipRejected(f"El ZIP tiene más de {MAX_FILES} entradas.")
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_BYTES:
            raise ZipRejected("El contenido descomprimido excede 1 GB.")
        count = 0
        for info in infos:
            name = info.filename
            target = os.path.realpath(os.path.join(dest_real, name))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                raise ZipRejected(f"Ruta insegura en el ZIP: {name!r}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ZipRejected(f"El ZIP contiene un enlace simbólico: {name!r}")
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
    return count


def _tree_root(dest: str) -> str:
    """Si el ZIP trae una única carpeta raíz (caso típico de un repo comprimido), audita desde ahí."""
    entries = [e for e in os.listdir(dest) if e not in ("__MACOSX",)]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        return os.path.join(dest, entries[0])
    return dest


def register_asset(asset_name: str, criticality: str, tree: str) -> str:
    with db_manager.get_db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, status)
            VALUES (%s, 'GitLab-Repo', %s, %s, 'monitored')
            ON CONFLICT (asset_name) DO UPDATE SET endpoint = EXCLUDED.endpoint, criticality = EXCLUDED.criticality
            RETURNING id
            """,
            (asset_name, tree, criticality),
        )
        return cur.fetchone()[0]


def run_audit(asset_id, asset_name: str, tree: str) -> dict:
    """Mismos motores que GitLabIntegrator.scan_single_project, sin los que requieren la API de GitLab.
    Cada motor se aísla: uno que falle se registra con traza y no impide los demás."""
    from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies, auditor_compliance_standards,
                          auditor_iac_k8s, auditor_cmmi_v3, auditor_accessibility_wcag, auditor_sonarqube,
                          auditor_semgrep, auditor_authz)
    engines = [
        ("sast", lambda: auditor_master_vulnerabilities.run_master_vulnerability_scan(tree, asset_id=asset_id)),
        ("sca", lambda: auditor_sca_dependencies.run_sca_audit(tree, asset_id=asset_id)),
        ("standards", lambda: auditor_compliance_standards.run_compliance_standards_audit(tree, asset_id=asset_id)),
        ("iac", lambda: auditor_iac_k8s.run_iac_scan(tree, asset_id=asset_id)),
        ("cmmi", lambda: auditor_cmmi_v3.run_cmmi_audit(tree, asset_id=asset_id)),
        ("wcag", lambda: auditor_accessibility_wcag.run_wcag_accessibility_audit(tree, asset_id=asset_id)),
        ("authz", lambda: auditor_authz.run_authz_audit(tree, asset_id=asset_id)),
        ("semgrep", lambda: auditor_semgrep.persist_findings(auditor_semgrep.scan_path(tree, asset_id, asset_name))),
        ("sonarqube", lambda: auditor_sonarqube.run_sonarqube_audit(tree, asset_id=asset_id, repo_display_name=asset_name)),
    ]
    summary = {}
    from core import scan_comparison
    run_id = scan_comparison.open_run(asset_id, "zip-upload")   # baseline for the "última versión vs anterior" comparison
    _audit_lock.acquire()
    for name, fn in engines:
        try:
            res = fn()
            summary[name] = len(res) if hasattr(res, "__len__") else res
        except Exception as e:
            traceback.print_exc()
            print(f"⚠️ [ZipSource] motor '{name}' falló para {asset_name}: {e}")
            summary[name] = f"error: {e}"
    _audit_lock.release()
    with db_manager.get_db_cursor() as cur:
        cur.execute("UPDATE public.infra_inventory SET last_audit = NOW() WHERE id = %s", (asset_id,))
    failed = [k for k, v in summary.items() if isinstance(v, str) and v.startswith("error")]
    scan_comparison.close_run(run_id, True, note=("motores con error: " + ", ".join(failed)) if failed else None)
    print(f"✅ [ZipSource] Auditoría de {asset_name} terminada: {summary}")
    return summary


def ingest_zip(zip_path: str, asset_name: str, criticality: str = "MEDIUM", background: bool = True) -> dict:
    """Extrae el ZIP, registra el activo y lanza la auditoría (en un hilo por defecto: tarda minutos)."""
    asset_name = asset_name_for(asset_name)
    dest = os.path.join(UPLOAD_ROOT, _slug(asset_name))
    if os.path.isdir(dest):
        shutil.rmtree(dest)  # re-subir reemplaza el código anterior
    os.makedirs(dest, exist_ok=True)
    try:
        files = safe_extract(zip_path, dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    if files == 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise ZipRejected("El ZIP no contiene archivos.")
    tree = _tree_root(dest)
    asset_id = register_asset(asset_name, criticality, tree)
    if background:
        threading.Thread(target=run_audit, args=(asset_id, asset_name, tree), daemon=True,
                         name=f"zip-audit-{asset_id}").start()
    return {"asset_name": asset_name, "asset_id": str(asset_id), "files": files, "tree": tree, "background": background}
