# Cumplimiento CMMI V3.0 e ISO/IEC 27001:2022: evidencia que produce el trabajo diario

El cumplimiento no se declara: se **produce evidencia** al trabajar y un escáner o una auditoría la verifica. Lo que no se puede medir con
código, repositorio o pipeline se reporta como `NO EVALUADO`, nunca como cumplido (ver `honesty.md` §4).

## Prácticas obligatorias y la evidencia que generan
| Práctica del equipo | Evidencia verificable | CMMI V3.0 | ISO 27001:2022 (Anexo A) |
|---|---|---|---|
| Todo cambio nace de un requisito o ticket con criterio de aceptación; el commit/MR lo referencia | Trazabilidad requisito → commit → MR → prueba | RDM | 8.25 |
| Cambios solo por Merge Request revisado y aprobado por **otra persona**; nada directo a la rama por defecto | MR fusionados con revisor distinto del autor; rama protegida | PR, CM | 8.32, 8.4 |
| Pipeline de CI con pruebas, análisis estático y escaneo de seguridad; la rama no se fusiona en rojo | Último pipeline en verde; pruebas existentes | VV, PI | 8.25, 8.29 |
| Versiones etiquetadas (tags/releases) | Tags por entrega | CM | 8.32 |
| Esquema de base de datos solo por migraciones versionadas | Changelogs Liquibase/Flyway | CM, TS | 8.32 |
| Contrato de API publicado (OpenAPI) | Especificación o springdoc | PI | 8.25 |
| Decisiones técnicas en ADR | `DECISIONS/` | DAR | 5.8 |
| Documento de arquitectura/diseño en `docs/` | Documentos versionados | TS | 8.27 |
| Codificación segura: cero hallazgos nuevos del escáner por cambio | Reporte del escáner por MR | VV | 8.28, 8.8 |
| Secretos fuera del código; configuración por ambiente | Escáner de secretos limpio | — | 8.9, 8.24 |
| Autenticación y autorización en cada endpoint; auditoría de cambios de datos | Pruebas 401/403; triggers de auditoría | — | 8.5, 8.15 |
| Lecciones aprendidas registradas tras un defecto relevante | Bitácora/ADR con causa raíz | CAR | 5.27 |

## Reglas
- Un MR sin revisión de otra persona no cuenta como revisado aunque se haya fusionado.
- Las áreas que dependen de documentos de gestión (planeación, estimación, riesgos, capacitación, gobierno) solo se acreditan con el
  documento real; el agente no los inventa ni los llena con texto genérico.
- Un porcentaje de cumplimiento se calcula solo sobre controles verificados; nunca se ajusta el denominador para mejorar la cifra.
