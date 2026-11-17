# SLAs, cierre, escalamiento y marcos de control

## SLAs en dos tiempos (propuesta de referencia)
| Severidad | Contención (seguridad) | Corrección seguridad | Corrección no seguridad |
| --- | --- | --- | --- |
| Secreto expuesto | 1 día (rotar) | 15 días (retirar del repo e historial) | — |
| Crítica | 3 días | 15 | 30 |
| Alta | 7 días | 30 | 60 |
| Media | — | 90 | 120 |
| Baja | — | 180 | 180 |
| Informativa (FP) | — | 30 (validar) | 30 |

Justificación: Centinela fija 24 h / 7 / 30 / 90 días (REGLAS §3.17). Con decenas de
críticos de un mismo patrón, 24 h vence el primer día y deja de servir para gestionar;
se conservan como contención y la corrección sigue el orden de 15/30 días que CISA fijó
para sistemas federales expuestos (BOD 19-02). Ajusta si el volumen es bajo.

## Criterios de cierre
- Código: MR con revisor ≠ autor y `centinela/security` en verde; re-escaneo con huella
  RESOLVED; prueba autenticada multirol (rol sin privilegio → 403).
- Secreto: rotación, retiro, purga del historial, escaneo de secretos limpio, credencial
  anterior inválida.
- SCA: lockfile actualizado + re-escaneo. CI/CD: exportación de configuración por API.
- Infraestructura: configuración documentada en inventario + verificación directa o motor
  de host/BD de Centinela.
- FP o riesgo aceptado: justificación + fecha de revisión + aprobación del Director de Tecnología.
- Firma: Director de Tecnología. Prepara: analista de ciberseguridad. Quien corrige no valida.

## Escalamiento (verificar titulares con el organigrama vigente)
1. Consultor o personal asignado. 2. Gerente responsable (contención vencida o corrección
al 50% sin MR). 3. Director: Operaciones para código y BD; Tecnología para infraestructura
y CI/CD (corrección vencida). 4. Dirección General (crítico vencido > 15 días o desacuerdo
sobre aceptar un riesgo).

## Cadencia
Semanal 30 min (analista + gerentes): vencidos, bloqueos, cierres por validar. Quincenal:
re-escaneo de Centinela y conciliación por huella. Mensual: reporte ejecutivo de una
página (abiertos por severidad y gerencia vs mes anterior, vencidos, % cierres validados,
top 5 riesgos en lenguaje de negocio, riesgos aceptados, decisiones solicitadas).

## Funciones del manual (Dirección de Tecnología, "Ciberseguridad y Cumplimiento")
Políticas y gestión de vulnerabilidades e incidentes · IAM · DRP/BCP · seguridad en el
ciclo de vida · coordinar auditorías y presentar resultados · cumplimiento normativo ·
endpoints. Además, en Gestión de Infraestructura: administrar repositorios y pipelines
CI/CD (los hallazgos de GitLab son de la propia Dirección).

## Controles de referencia
- ISO 27001:2022: A.5.2 roles · A.5.3 segregación · A.5.9 inventario · A.5.17 información
  de autenticación · A.5.34 privacidad/PII · A.5.35 revisión independiente · A.8.4 acceso al
  código fuente · A.8.8 vulnerabilidades técnicas · A.8.9 configuración · A.8.24
  criptografía · A.8.25/8.28/8.29 desarrollo, codificación y pruebas seguras · A.8.32 cambios.
- NIST CSF 2.0: GV.RR · ID.AM · ID.RA · PR.AA · PR.DS · PR.PS · DE.CM · RS.MA.
- CIS v8: 1 y 2 inventarios · 3 datos · 4 configuración segura · 5 y 6 cuentas y acceso ·
  7 vulnerabilidades · 8 bitácoras · 16 seguridad de aplicaciones · 18 pruebas de penetración.
Evalúa siempre: independencia del auditor, formalidad del rol de ciberseguridad e
inventario de infraestructura.
