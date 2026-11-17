---
name: consolidacion-auditoria-seguridad-generica
description: Método y scripts para consolidar las auditorías de seguridad de un sistema con varios repositorios (auditoría manual de código, análisis de segundo nivel y reportes PDF de Centinela u otro escáner con el mismo formato) en un informe con dictamen, un libro de triage por causa raíz (vulnerabilidad / falso positivo / calidad) con plan de trabajo en horas, y una matriz de seguimiento en Excel con SLA, responsables, criterios de cierre y escalamiento. Funciona solo con los PDF (no necesita acceso al escáner). Úsalo al revisar o consolidar una auditoría, cruzar hallazgos de varias fuentes, separar vulnerabilidades reales de falsos positivos y calidad, estimar esfuerzo de corrección, definir SLA o criterios de cierre, verificar el cierre entre dos corridas, o evaluar contra ISO 27001, NIST CSF o CIS Controls. El catálogo de decisiones empieza vacío en cada proyecto.
---

# Consolidación de auditorías de seguridad (versión genérica)

Convierte varios insumos de seguridad que se contradicen o se repiten (auditoría manual,
análisis de segundo nivel, escaneos de Centinela) en entregables verificables:

1. **Informe** con dictamen por pregunta, todo citado a archivo y sección.
2. **Libro de triage** (.xlsx): cada ocurrencia del escáner clasificada como Vulnerabilidad,
   Falso positivo o Calidad por causa raíz, con plan de trabajo en horas y jornadas.
3. **Matriz de seguimiento** (.xlsx) con un registro por hallazgo, responsable, SLA,
   evidencia de cierre, firma de validación y resumen calculado con fórmulas.

Skills que se combinan con esta: `triage-findings` (el método de clasificación en corto), `xlsx` (formato y recálculo) y
la de documentos de tu agente para el informe. Responsables y escalamiento salen del organigrama vigente de la organización.

**El catálogo de decisiones es de cada proyecto.** `assets/catalogo_ejemplo.json` es un ejemplo ilustrativo (causas genéricas
y un falso positivo acotado a un archivo); no contiene decisiones de ningún proyecto real. Un falso positivo se decide por
repositorio y archivo, nunca se hereda como regla general.

Probado con reportes reales de dos sistemas (1,020 ocurrencias en el primero, con las mismas cifras que el análisis manual
de referencia celda por celda; el segundo no se usó para construirlo y sirvió para corregir dos defectos del parser).

## Principios que no se negocian

- **Todo citado.** Cada afirmación relevante lleva archivo y sección. Marca `[V]` lo
  verificado en documentos e `[I]` lo inferido u opinado. Si un dato no está, se dice.
- **Nunca reproducir secretos.** Las auditorías y los PDFs de Centinela suelen traer
  tokens y contraseñas en claro. No los copies al informe ni a la matriz; reporta que
  existen, dónde, y recomienda rotar y restringir la distribución del documento fuente.
- **Quien corrige no valida.** La firma de cierre es del Director de Tecnología; el
  analista de ciberseguridad asignado prepara la evidencia. Si el auditor es también
  gerente del área que corrige, señálalo como falta de independencia (ISO 27001 A.5.3, A.5.35).
- **Verifica las premisas del encargo.** En un caso real, las fechas que dio el usuario
  y el módulo de varios archivos no coincidían con el contenido. Corrige con evidencia
  antes de construir encima.
- **La clasificación es del analista, no tuya.** Vulnerabilidad / falso positivo / calidad es un
  juicio con consecuencias (un falso positivo mal cerrado deja un hueco abierto). Aplica el catálogo
  que exista, deja `SIN CLASIFICAR` lo que no cubra, **propón** la causa raíz con su evidencia y
  regístrala solo con aprobación. Un falso positivo nunca es el valor por defecto de una regla.
- **Medido ≠ supuesto.** En el plan de trabajo solo la columna «Según Centinela» (SonarQube) es una
  estimación de la herramienta; minutos por unidad, trabajo adicional y reparto entre áreas son supuestos
  del analista y se rotulan así. Nunca presentes horas inventadas como medición.
- **Trabajo en dos fases** cuando el usuario lo pida: Fase 1 inventario y cruce, detenerse
  y mostrar resumen; Fase 2 respuestas y entregables.

## Flujo de trabajo

### Paso 1. Extraer los insumos (scripts/extract_inputs.py)

Los archivos del proyecto pueden no ser lo que dice su extensión: en un proyecto los `.pdf`
eran ZIP con una imagen y un `.txt` por página, y los `.docx` eran texto plano.
Ejecuta `python scripts/extract_inputs.py <carpeta_insumos> <carpeta_txt>`, que detecta el
tipo real, extrae el texto completo y deja un `.txt` por archivo. Revisa el inventario
que imprime antes de seguir.

### Paso 2. Inventario por módulo y repositorio

Arma la tabla módulo × insumo (auditoría backend, auditoría frontend, análisis de
segundo nivel, Centinela) con fecha real de cada documento. Identifica el módulo de
cada análisis **por contenido**, no por nombre de archivo: compara encabezados contra
tablas y busca duplicados (`diff` entre archivos, `md5sum`). Lista los huecos:
módulos sin auditoría de una capa y repositorios que solo cubre Centinela.
Un proyecto de Centinela son **varios repositorios** (p. ej. backend, frontend y librerías):
inclúyelos todos y avisa cuál falta; el PDF no puede decir qué repositorios del grupo no se escanearon.

### Paso 3. Parsear Centinela (scripts/parse_centinela.py)

`python scripts/parse_centinela.py <dir_txt> centinela.json [prefijo_]` produce una fila por regla × repositorio
con severidad efectiva y de la herramienta, ocurrencias, motor, **todas las ubicaciones (archivo + líneas)**, CWE,
esfuerzo de SonarQube, paquete/versión/alcanzabilidad en SCA y la marca «SIN RIESGO REAL».

- **Primero el cuadre automático:** por cada PDF imprime `cuadre_con_encabezado=OK/ALERTA` (suma de ocurrencias parseadas vs.
  «Se encontraron N hallazgos» del propio PDF) y las reglas cuyas ubicaciones el PDF recortó («Se muestran 60 de 81 archivos»).
  Con una ALERTA no sigas: se perdió o se duplicó un encabezado.
- **Cuadra cifras** del reporte general contra cada PDF. En un proyecto las diferencias coincidían con los
  «resueltos por SOAR» que el PDF incluye y el general no.
- **Detecta defectos del reporte** (lista completa en `references/centinela.md`): reglas que marcan «sin riesgo» y «Alta»
  sobre las mismas líneas; SCA leído de `package.json` y no del lockfile; rutas no productivas escaneadas; ubicaciones recortadas.
- **Compara contra el catálogo de reglas del escáner** (`prevencion-hallazgos-seguridad-calidad/references/catalogo-reglas.md`): reglas del reporte que no están en el catálogo y diferencias de severidad.

### Paso 3b. Triage por causa raíz (scripts/triage_report.py, references/triage_catalogo.md)

`python scripts/triage_report.py centinela.json catalogo.json libro_triage.xlsx --matriz matriz_centinela.json --pendientes pendientes.json --titulo SISTEMA`

Clasifica cada ocurrencia con el catálogo de causas raíz del analista (parte de `assets/catalogo_ejemplo.json`:
las causas genéricas —accesibilidad, `@Version` JPA, Dockerfile sin `USER`, secretos en `application*.properties`, autorización por método— se reutilizan) y genera
el libro: **Resumen** (por clasificación, repositorio y severidad), **Cobertura**, **Plan de trabajo** (horas, jornadas, semanas por área con
supuestos editables en amarillo), **Vulnerabilidades**, **Falsos positivos** (cada uno con su fundamento y cuándo reabrirlo), **Calidad**,
**Versiones desactualizadas** (por CVE y por paquete: una actualización cierra varias) y **Detalle** (cada ocurrencia, con su causa raíz editable).
También deduplica el mismo hallazgo reportado por varios motores en la misma línea.

Después de la corrida:
- Lee `pendientes.json` (los grupos `SIN CLASIFICAR`, con evidencia, ubicaciones de muestra y cómo se clasificó **esa misma regla** en otros lugares: un indicio, no una decisión). Para cada grupo (repositorio × regla) revisa la evidencia, aplica las cuatro preguntas de
  `references/triage_catalogo.md`, **propón** causa raíz y certeza al analista y agrégala al catálogo solo si la aprueba. Vuelve a correr.
- Verifica que las ocurrencias totales coincidan con las que declaran los PDF (el script lo imprime) y que `SIN CLASIFICAR` quede en 0 o explícitamente pendiente.
- Dilo en el informe: lo medido (conteos, severidades, ubicaciones) vs. el criterio del analista (clasificación, fundamentos, horas).

### Paso 4. Parsear la auditoría (scripts/parse_auditoria_md.py)

`python scripts/parse_auditoria_md.py <dir_md> auditoria.json` extrae hallazgos de
reportes Markdown con encabezados `### CRIT-01 …` / `MED-` / `MEN-` / `MIN-` (backend)
y secciones "Clasificación de hallazgos" o "### Hallazgo N" (frontend). Revisa también
las secciones de "Riesgos de seguridad" y "Seguridad": suelen traer riesgos sin
número propio que hay que registrar como hallazgos adicionales.

Clasifica cada hallazgo por **tipo**: Seguridad, Rendimiento, Arquitectura, Calidad,
Funcional (y en Centinela además Dependencias, CI/CD, IaC, Accesibilidad). Solo los de
seguridad se cruzan contra Centinela.

### Paso 5. Cruce auditoría ↔ Centinela

Para cada hallazgo de seguridad asigna:

| Clase | Significado | Cómo se decide |
| --- | --- | --- |
| a | Centinela lo detectó | Misma regla y archivo/línea en el PDF |
| b | Hay regla aplicable pero no aparece | La regla existe en el catálogo; el archivo no está entre las ubicaciones listadas |
| c | Lo detectó un motor externo integrado | SonarQube, Semgrep, Trivy, ZAP |
| d | Sin cobertura | Ninguna regla aplica |

Para los (b), argumenta la causa (ya corregido, cambió el código o falso negativo). Una
señal útil: si muchas líneas citadas por la auditoría coinciden exactamente con las de
Centinela semanas después, el código cambió poco y el (b) es probablemente falso
negativo. Con el parser v2 las ubicaciones están completas salvo las que el PDF declara recortadas
(`truncado`); solo esas impiden descartar un (b).

Haz el **cruce inverso**: críticos y altos de Centinela sin equivalente en la auditoría.
Separa seguridad de calidad, rendimiento y arquitectura (el triage ya lo hace por causa raíz).
Concluye con las reglas que le faltan a Centinela.

### Paso 6. Evaluar análisis de segundo nivel

Usa `references/checklist_analisis.md`. Lo esencial: módulo correcto, fidelidad de
líneas/conteos/severidades, omisiones, CVE verificados con fuente (los hallazgos de
código propio llevan CWE, no CVE), CWE y controles ISO de la versión correcta
(2022, no 2013), mitigaciones viables, supuestos de infraestructura marcados como no
verificados, y si el autor se quedó en gestión y validación o definió correcciones que
corresponden a las gerencias.

### Paso 7. Construir la matriz (scripts/build_matrix_xlsx.py)

1. Une auditoría y Centinela en un JSON con el esquema de `references/matriz_schema.md`.
   Los registros de Centinela salen ya hechos de `triage_report.py --matriz` (uno por regla × repositorio × causa raíz,
   IDs `C-<repo>-<nn>`); los de la auditoría llevan `Y-<módulo>-<B|F>-<id original>`.
2. Marca `Origen` = Ambos cuando la clase es a o c. `Principal = No` solo en duplicados exactos
   (mismo defecto, mismo componente): el triage ya marca los que Centinela reporta con varios motores; revisa los de la auditoría.
3. Severidad consolidada = la mayor de las fuentes, salvo ajustes justificados en Notas
   (falso positivo declarado → Informativa, como ya hace el triage; MD5 usado como checksum, etc.).
4. Asigna gerencia con el organigrama vigente de la organización: el triage propone la del catálogo; revísala. Código → Programación;
   consultas, índices, restricciones y pool → Arquitectura y BD; GitLab, pipelines, servidores, secretos en servidores,
   respaldos, monitoreo, Kubernetes → Infraestructura y Telecomunicaciones (marcar "confirmar"). Usa `Apoyo` para lo compartido.
5. Prepara `params.json` (fecha base, SLAs, gerencias y escalamiento, firmas). Plantilla en `references/matriz_schema.md`.
6. Ejecuta `python scripts/build_matrix_xlsx.py matriz.json params.json salida.xlsx [hojas_extra.json]` y luego el
   `recalc.py` del skill `xlsx`. Debe dar cero errores. (El libro de triage ya trae sus valores calculados.)
7. Verifica con `load_workbook(data_only=True)` que los totales del Resumen coinciden con las cifras que pondrás en el informe.

### Paso 8. Modelo de seguimiento (SLAs, cierre, escalamiento)

Parte de `assets/params_plantilla.json` (SLAs en dos tiempos ya cargados; los titulares los llenas desde el organigrama vigente de la organización).
**Verificar un cierre** con solo PDF: `python scripts/comparar_corridas.py antes.json despues.json --salida cierre.json` clasifica cada ocurrencia (repositorio, regla, archivo, línea) como
resuelta, nueva o persistente. Concluye solo donde las ubicaciones están completas en ambas corridas; si el código se editó y las líneas se movieron, lo marca *posible desplazamiento*
(mirar el código) y lo recortado por el PDF como *no concluyente*. Es la evidencia del «re-escaneo sin la huella», no sustituye la prueba funcional multirol.

Usa los SLAs en dos tiempos de `references/marcos_y_slas.md` (contención corta tomada de
Centinela, corrección en 15/30/90/180 días) y justifica cualquier cambio. Criterios de
cierre por tipo: MR con revisor distinto del autor + re-escaneo de Centinela + prueba
autenticada multirol; para secretos, rotación + purga del historial + prueba de que la
credencial anterior ya no autentica. Escalamiento por organigrama: el Director de
Tecnología no tiene autoridad jerárquica sobre Operaciones, así que el código escala por
el Director de Operaciones.

### Paso 9. Infraestructura y cumplimiento

- Extrae todo lo que toca servidores, contenedores, BD, caché, red, secretos, CI/CD,
  respaldos y monitoreo; separa de código; asigna responsable principal y de apoyo; lista
  la información de inventario que falta para validarlo.
- Compara contra las funciones de "Ciberseguridad y Cumplimiento" del manual operativo y
  contra ISO 27001:2022, NIST CSF 2.0 y CIS v8 (`references/marcos_y_slas.md`). Evalúa
  siempre independencia de la auditoría, formalidad del rol de ciberseguridad y existencia
  de inventario de infraestructura.

### Paso 10. Entregables

- **Informe** (documento): resumen ejecutivo con tabla de dictamen por pregunta y
  acciones inmediatas; una sección por pregunta; anexo de insumos y fuentes externas.
- **Libro de triage** (Paso 3b) y **Excel de matriz:** hojas Léeme, Resumen, Matriz, Cruce, Cuadre de Centinela,
  Evaluación de analistas, Infraestructura y Parámetros. Las celdas editables van en amarillo.
- Cierra con 2–4 líneas: qué se entregó y qué queda abierto (incluye siempre cuántas ocurrencias quedaron `SIN CLASIFICAR`
  y qué cobertura no se pudo verificar). Sin repetir el informe.

## Con acceso directo a Centinela (opcional)

Si el proyecto tiene acceso a la API, `GET /api/triage/report.xlsx?instance=&group=<ruta del grupo>` y `GET /api/triage/matrix` entregan lo mismo sin parsear PDF,
con todas las ocurrencias, los informativos y la lista de subproyectos contrastada con GitLab («Sin escanear» no es «limpio»). Es el camino preferente cuando exista;
el flujo por PDF es el respaldo y da el mismo resultado en lo que los PDF listan (comprobado en un proyecto real).

## Dependencias

`pdftotext` (poppler) y `pandoc` para extraer; `openpyxl` para la matriz; `xlsxwriter` para el libro de triage (`pip install xlsxwriter`).
Todos los scripts se ejecutan desde la carpeta del skill (`python scripts/…`); `scripts/core/` es código compartido con Centinela, no lo edites aquí.

## Errores frecuentes que este skill evita

- Confiar en el nombre de archivo para saber qué módulo analiza.
- Tomar el total del reporte general de Centinela como "vulnerabilidades reales": incluye
  accesibilidad WCAG y concurrencia JPA. (El triage los separa; en un proyecto real solo 406 de 1,020 eran vulnerabilidades.)
- Parsear solo la primera línea de un encabezado de Centinela: el PDF los parte (`Motor: sast-` / `native`) y se pierden hallazgos en silencio;
  por eso el cuadre contra el total declarado es obligatorio.
- Contar «ubicaciones» como archivos: son pares archivo:línea.
- Dar por resuelto lo que «desapareció» del PDF cuando el PDF recortó su lista, o cuando el código solo movió las líneas.
- Cerrar como falso positivo por regla completa en vez de por archivo/condición.
- Adoptar SLAs de 24 h para críticos cuando hay decenas concentrados en un mismo patrón:
  vencen el primer día y dejan de servir para gestionar.
- Dejar que el área que corrige firme su propio cierre.
- Asignar CVE a defectos de código propio, o citar controles ISO 27001:2013 como 2022.
