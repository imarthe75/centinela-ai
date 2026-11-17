# Checklist para evaluar análisis de segundo nivel (p. ej. "notas" sobre una auditoría)

## Utilidad (¿aporta algo sobre la auditoría original?)
Evalúa uno por uno: priorización (CVSS, explotabilidad, exposición), agrupación con IDs
consistentes, mapeo CWE/CVE correcto, plan de mitigación viable, responsables asignados,
ventanas de mantenimiento con sustento, cobertura de los hallazgos de seguridad del módulo.
Calcula la cobertura: hallazgos de seguridad de la auditoría tratados / total del módulo.

## Exactitud técnica
- **Módulo correcto:** compara encabezado vs contenido de tablas; busca copias con `diff`
  (en un proyecto, 3 de 9 análisis eran copias de otro módulo y un PDF y un DOCX con el mismo
  nombre analizaban módulos distintos).
- **Fidelidad:** líneas, archivos, conteos y severidades contra la auditoría. Señala líneas
  inventadas ("aprox. 15-45" donde el original no da líneas) y severidades cambiadas sin
  justificar.
- **Omisiones:** hallazgos de seguridad de la auditoría que no aparecen.
- **CVE:** verifica cada uno con fuente (OSV, NVD, Debian security tracker) y cita la URL.
  Un CVE describe un producto de terceros; asignarlo a código propio es un error.
  En un proyecto aparecieron CVE de jsoup, Pandoc, systeminformation, OpenSSL, sudo, SonicWall.
- **CWE:** comprueba el significado (p. ej. CWE-601 es redirección abierta, CWE-674 recursión,
  CWE-404 liberación de recursos). Detecta CWE con nombre inventado.
- **Reglas SonarQube:** S5122 es CORS, S2259 nulos, S5145 inyección en logs, S1874 API obsoleta.
- **ISO 27001:** numerales A.9.x, A.12.x, A.13.x, A.14.x son de la versión 2013. En 2022:
  A.5.x organizacionales, A.8.x tecnológicos (A.8.6 capacidad, A.8.9 configuración,
  A.8.24 criptografía, A.8.32 cambios, A.8.14 redundancia).
- **NIST 800-53:** SC-13 es protección criptográfica, SC-2 separación de funciones.
- **Cifras sin medición** ("95% de cumplimiento", "CMMI nivel 4"): sin sustento.
- **Supuestos de infraestructura:** márcalos "no verificados" si no hay inventario.
  Contrasta con lo que sí muestran los archivos (manifiestos k8s, Dockerfiles, hosts en
  los reportes de Centinela). Si el supuesto implica sistemas sin soporte, dilo.
- **Plantillas sin depurar:** ejemplos ajenos, encabezados de otro módulo, enlaces con
  `utm_source=<asistente>` (indicio de generación asistida sin revisión).

## Mitigaciones
Correctas si atacan la causa y son viables con el stack documentado. Problemáticas:
roles genéricos (`hasAnyRole('ADMIN')`) que rompen mínimo privilegio, pasos de sistema
operativo para cambios de aplicación, ventanas sin arquitectura conocida, heurísticas
frágiles copiadas sin cuestionar.

## Rol
Distingue gestión y validación (asignar, dar seguimiento, exigir evidencia, verificar)
de corrección (instrucciones de código, ventanas de mantenimiento, operaciones de
servidor), que corresponden a las gerencias. Señala títulos que no existen en el
organigrama.
