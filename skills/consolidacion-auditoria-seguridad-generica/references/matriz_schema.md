# Esquema de la matriz y parámetros

## Registro (un elemento de matriz.json)

| Campo | Obligatorio | Valores / ejemplo |
| --- | --- | --- |
| ID | Sí | `Y-TRA-B-CRIT-04` (auditoría: módulo, B/F, id original) · `C-BT-02` (Centinela: repo, consecutivo) |
| Origen | Sí | `Auditoría` (o el nombre del auditor), `Centinela`, `Ambos` (cobertura a o c) |
| Fuente | Sí | `BACKmodulos_transversales_inicio.md §2-4 CRIT-04` · `sistema_backend-sistema.pdf` |
| FechaFuente | No | `2026-09-11`, `2026-03`, `s/f` |
| Repositorio, Modulo, Capa | Sí | `backend-sistema`, `Transversales y de Inicio`, `Backend` / `Frontend` / `CI/CD` / `Contenedor` / `Infraestructura` |
| Tipo | Sí | `Seguridad`, `Dependencias (SCA)`, `CI/CD`, `Infraestructura (IaC)` (clase SLA Seguridad) · `Rendimiento`, `Arquitectura`, `Calidad`, `Funcional`, `Accesibilidad` (clase No seguridad) |
| IDorig, Titulo, Ubicacion, Ocurr | Sí | id de la fuente, descripción corta, `Archivo.java:24; ...`, número |
| SevAuditoria, SevCent | No | `Crítica`, `Alta`, `Media`, `Baja` |
| Sev | Sí | consolidada: `Crítica`, `Alta`, `Media`, `Baja`, `Informativa` |
| CWE | No | `CWE-862; CWE-639`. Código propio lleva CWE, no CVE. CVE solo en dependencias |
| Regla, EnCatalogo | No | regla de Centinela; `Sí`, `No`, `Externo (SonarQube/Semgrep)` |
| Cobertura | No | `a`, `b`, `c`, `d` solo para hallazgos de seguridad de la auditoría |
| Relacion | No | evidencia cruzada: regla y archivo:línea en Centinela, o causa probable del (b) |
| Secreto | No | `Sí` si hay credencial expuesta (contención de 1 día) |
| Principal | No | `Sí` por defecto; `No` en duplicados exactos (anotar el principal en Nota) |
| Gerencia, Apoyo | Sí / No | nombre exacto de una gerencia de params.json |
| Estatus | No | por defecto `Abierto`; ver lista en el script |
| Nota | No | ajustes de severidad, truncamiento de ubicaciones, contradicciones |

### Campos adicionales que emite `triage_report.py --matriz`
Un registro por **regla × repositorio × causa raíz** (la misma regla puede ser vulnerabilidad en un archivo y falso positivo en otro). Además del esquema:
`Clasificacion` (Vulnerabilidad / Falso positivo / Calidad / Sin clasificar), `CausaRaiz` (V-01, FP-03, C-07…) y `SevHerramienta` (la severidad cruda del motor).
`build_matrix_xlsx.py` ignora los campos que no conoce, así que se conservan en el JSON para trazabilidad. Convenciones aplicadas: falso positivo → `Sev = Informativa`
y `Estatus = Validar falso positivo`; grupo cuyas ocurrencias son todas duplicadas de otra regla → `Principal = No` (con la regla principal en `Nota`);
`Secreto = Sí` solo para vulnerabilidades de credenciales en claro; `Gerencia`/`Apoyo` salen del responsable del catálogo (si no hay, se asigna por tipo y la `Nota` lo dice).
`EnCatalogo` queda vacío: contrastarlo con REGLAS_PROPIAS_CENTINELA.md es un paso manual del Paso 3.

## Plantilla de params.json

```json
{
  "titulo": "Matriz de seguimiento — Auditoría de seguridad de <SISTEMA>",
  "fecha_base": "2026-10-05",
  "dias_secreto": 1,
  "firma_seguridad": "Director de Tecnología; prepara evidencia: analista de ciberseguridad asignado",
  "firma_no_seguridad": "Gerencia de Análisis / Calidad (QA) — propuesta",
  "leeme": [["Elaborado", "<fecha y fuentes>"]],
  "slas": [
    {"clase": "Seguridad", "severidad": "Crítica", "contencion": 3, "correccion": 15, "fundamento": "Contención Centinela; corrección orden CISA BOD 19-02"},
    {"clase": "Seguridad", "severidad": "Alta", "contencion": 7, "correccion": 30, "fundamento": ""},
    {"clase": "Seguridad", "severidad": "Media", "correccion": 90},
    {"clase": "Seguridad", "severidad": "Baja", "correccion": 180},
    {"clase": "Seguridad", "severidad": "Informativa", "correccion": 30},
    {"clase": "No seguridad", "severidad": "Crítica", "correccion": 30},
    {"clase": "No seguridad", "severidad": "Alta", "correccion": 60},
    {"clase": "No seguridad", "severidad": "Media", "correccion": 120},
    {"clase": "No seguridad", "severidad": "Baja", "correccion": 180},
    {"clase": "No seguridad", "severidad": "Informativa", "correccion": 30}
  ],
  "gerencias": [
    {"gerencia": "Gerencia de Programación", "titular": "<del organigrama>", "n3": "Dirección de Operaciones — <titular>", "direccion": "Dirección de Operaciones"},
    {"gerencia": "Gerencia de Arquitectura y BD", "titular": "<del organigrama>", "n3": "Dirección de Operaciones — <titular>"},
    {"gerencia": "Gerencia de Infraestructura y Telecomunicaciones", "titular": "<del organigrama>", "n3": "Dirección de Tecnología", "nota": "Asignaciones a confirmar"},
    {"gerencia": "Gerencia de Análisis / Calidad", "titular": "<del organigrama>", "n3": "Dirección de Operaciones — <titular>"}
  ]
}
```

Toma titulares y direcciones siempre del skill el organigrama vigente de la organización vigente; no los copies de este ejemplo.

## Hojas extra recomendadas (hojas_extra.json)

- **Cruce Auditoría-Centinela:** ID, módulo, capa, id original, hallazgo, severidad, CWE, clase a/b/c/d, evidencia o causa, fuente. Debajo, el cruce inverso.
- **Cuadre Centinela:** por repositorio, C/A/M/B del reporte general y del PDF, totales y diferencia como fórmulas (`=SUM(...)`, `=K5-F5`), más una fila de control contra lo reportado.
- **Evaluación de analistas:** documento, módulo declarado, módulo real, ¿corresponde?, hallazgos de seguridad del módulo, cubiertos, errores, uso recomendado; total con proporción de cobertura.
- **Infraestructura:** #, punto, fuente, responsable principal, apoyo, registros relacionados, información que falta.
