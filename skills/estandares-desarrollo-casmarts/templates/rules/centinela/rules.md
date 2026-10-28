# Reglas de trabajo con Centinela

Centinela es el escáner de seguridad y cumplimiento de la empresa. Escanea cada repositorio de GitLab por rama (activo
`GitLab/<ruta>@<rama>`), cada servidor y cada URL registrada, y publica hallazgos con su análisis y fecha límite. Estas reglas dicen cómo
debe trabajar un proyecto para cumplirlo. La corrección de cada regla está en la skill `centinela-developer-standards`; las reglas de
seguridad, en `rules/common/security.md`.

## 1. Antes de cambiar código
1. Consulta los hallazgos abiertos de los archivos que vas a tocar (skill `preflight`). Si el cambio toca un archivo con un hallazgo
   abierto, corrígelo en el mismo cambio o dilo en el MR.
2. Lee la regla en `centinela-developer-standards` antes de corregir: el detector dice exactamente qué patrón busca y qué cuenta como
   corregido (p. ej. `@PreAuthorize` en el método, no un guard en el frontend).

## 2. Criterio de aceptación de un Merge Request
1. **Cero hallazgos nuevos de severidad alta o crítica** en las líneas que agrega el MR. La revisión de MR de Centinela comenta en línea y
   deja el estado `centinela/security`; con `failed` el MR no se integra.
2. Hallazgos nuevos medios y bajos: corregidos o justificados en el MR.
3. Un MR no aumenta la deuda de la rama: el escaneo siguiente no debe mostrar más hallazgos abiertos que antes en los archivos tocados.

## 3. Cómo leer lo que reporta
1. **Severidad efectiva** = la que Centinela fijó tras analizar el caso (`real_severity`) o, si no hay, la de la herramienta. La IA puede
   bajarla con justificación, nunca subirla; un humano puede revertir esa decisión.
2. **Vulnerabilidad** e **informativo** (calidad, deuda, convenciones) se cuentan por separado. La accesibilidad WCAG cuenta como
   cumplimiento obligatorio en proyectos de gobierno.
3. **Fechas límite (SLA)** con la severidad efectiva: crítico 24 h, alto 7 días, medio 30 días, bajo 90 días.
4. Un análisis «a nivel de patrón» explica la regla una vez para todas sus ocurrencias del activo; no revisó cada línea: revísalas.
5. Un hallazgo **reabierto** es una regresión: algo que ya se había corregido volvió.

## 4. Cuándo un hallazgo no se corrige
1. Si es falso positivo o riesgo aceptado, se clasifica en el triage con la causa escrita y quién lo decide (skill `triage-findings`).
   La supresión es por hallazgo concreto (huella), no por regla completa.
2. Prohibido cambiar el código solo para que el detector deje de verlo (renombrar, partir una línea, mover a un archivo excluido) sin
   corregir el riesgo.
3. Prohibido aplicar un parche que Centinela no validó contra el código real; un parche sugerido sin validar se toma como guía, no se pega.

## 5. Lo que Centinela verifica (resumen por capa)
| Capa | Motores | Ejemplos de reglas |
|---|---|---|
| Autorización | authz estático y dinámico | `AUTHZ-NO-METHOD-AUTHZ`, `POTENTIAL-IDOR-NO-OWNERSHIP-CHECK`, `BACKDOOR-SANDBOX-CONTROLLER` |
| Código | SAST propio, Semgrep, SonarQube | `SQL-INJECTION-*`, `ANGULAR-BYPASS-SECURITY-TRUST`, `WEAK-CRYPTOGRAPHY`, `STACK-TRACE-EXPOSURE` |
| Secretos | patrones, historial de git | `HARDCODED-SECRET`, `CONFIG-SECRET-LITERAL` |
| Dependencias | SCA (OSV, CVSS, alcanzabilidad), licencias | `SCA-CVE-*`, `SUPPLY-CHAIN-NO-LOCKFILE` |
| Arquitectura y estándares | reglas Spring/Angular, estándares | `REQUESTBODY-WITHOUT-VALID`, `ENTITY-RETURNED-FROM-CONTROLLER`, `API-ENDPOINT-UNDOCUMENTED`, `JPA-ENTITY-MISSING-VERSION` |
| Base de datos | reglas SQL del estándar | `SQL-PK-NOT-UUID`, `SQL-TABLE-WITHOUT-AUDIT-COLUMNS`, `SQL-TIMESTAMP-WITHOUT-TIMEZONE` |
| Contenedores e IaC | Trivy config, Checkov | `DOCKER-MISSING-NON-ROOT-USER`, `TRIVY-*` |
| Accesibilidad | WCAG estático y renderizado | `WCAG-*` |
| Aplicación desplegada | WSTG perimetral, ZAP, TLS, pruebas funcionales | `WSTG-*`, `ZAP-*`, `SMART-TESTS-*` |
| Servidores | CIS, parches del SO | `CIS-*`, parches pendientes |
| Proceso | GitLab, evidencia CMMI | ramas protegidas, variables de CI, revisión de MR |

## 6. Cumplimiento
- Los porcentajes de ISO 27001 / CMMI / OWASP / WCAG que muestra Centinela miden solo lo que tiene detector; lo que no se puede medir
  aparece como **NO EVALUADO**, no como cumplido. Para subir un porcentaje se corrige el hallazgo o se produce la evidencia, nunca se
  reclasifica para que deje de contar (`rules/common/compliance.md`).
- Las pruebas funcionales de centinela-smart-tests (autorización por rol, reglas de negocio, heurísticas, accesibilidad tras el login)
  reportan a Centinela; un fallo de control de acceso ahí es un hallazgo de seguridad del proyecto.
