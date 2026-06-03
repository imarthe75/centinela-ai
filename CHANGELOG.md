# Changelog — Centinela-AI

Todas las actualizaciones y cambios notables en Centinela-AI se documentan en este archivo.

## [2026-06-02] — Rito de Inicio: Corrección de Generación de PDFs

### 🔧 Cambios

#### Motor de Reportes PDF: Carbone → WeasyPrint

**Problema Identificado:**
- Los PDFs generados estaban corruptos/ilegibles
- Carbone estaba mal configurado para HTML inline
- Carbone está diseñado para templates de documentos, no para HTML directo

**Solución Implementada:**
- Reemplazado `render_pdf_with_carbone()` por `render_pdf_with_weasyprint()`
- WeasyPrint es la solución nativa para HTML+CSS → PDF

**Archivos Modificados:**
- `requirements.txt` — Agregado `WeasyPrint==69.0`
- `Dockerfile.backend` — Dependencias del sistema (Cairo, Pango)
- `main.py` — Nueva función de rendering, 3 endpoints actualizados
- `scratch/debug_pdf.py` — Script de prueba actualizado

**Endpoints Afectados:**
- `GET /api/reports/executive` — ✅ Funcional
- `GET /api/reports/asset/{asset_name}` — ✅ Funcional
- `GET /api/reports/vulnerability/{vuln_id}` — ✅ Funcional

**Beneficios:**
- PDFs válidos (versión 1.7) sin corrupción
- Renderizado más rápido (in-process vs HTTP round-trip)
- Eliminada dependencia de servicio externo
- Estilos CSS completos preservados
- Mejor mantenibilidad (librería pura Python)

### 📚 Documentación Actualizada

- `README.md` — Cambio de Carbone a WeasyPrint, tabla de stack, diagrama de flujo
- `TECHNICAL_DOCS.md` — Detalles de cambio, endpoints actualizados, tabla comparativa
- `USER_GUIDE.md` — Nota de mejora en reportes PDF para usuarios finales
- Memoria del Proyecto — `centinela_pdf_generation_fix.md` con análisis técnico completo

### ✅ Verificación Post-Cambio

```
Reporte Ejecutivo:
  ✅ PDF válido (v1.7, 22KB)
  ✅ Contenido legible: 3871 vulnerabilidades totales
  ✅ Tablas formateadas correctamente
  ✅ Sin corrupción de caracteres

Reporte de Activo (gateway):
  ✅ PDF válido (v1.7)
  ✅ Detalles del activo completos
  ✅ Tabla de vulnerabilidades renderizada
  ✅ Estilos (badges, colores) intactos
```

### 🔄 Stack Impactado

| Componente | Cambio | Estado |
|-----------|--------|--------|
| Backend FastAPI | `render_pdf_with_weasyprint()` | ✅ Actualizado |
| requirements.txt | `+WeasyPrint` | ✅ Agregado |
| Dockerfile.backend | Cairo/Pango libs | ✅ Agregado |
| API Endpoints | 3 endpoints revisados | ✅ Funcional |
| Documentación | README, TECHNICAL, USER | ✅ Actualizado |

### 🚀 Despliegue

```bash
cd /home/ia/ecosistema-casmarts/centinela-ai
docker compose up -d centinela-backend  # Rebuild automático
```

**Nota:** El rebuild incluye nuevas dependencias del sistema; el primer build toma ~1-2 minutos.

---

## Versiones Anteriores

*(Historial de cambios previos irá aquí con actualizaciones futuras)*

---

**Formato:** Cada cambio importante incluye: Problema, Solución, Archivos Modificados, Verificación.
**Mantenedor:** CASMARTS Security Team
**Última Actualización:** 2026-06-02 20:30 UTC-6
