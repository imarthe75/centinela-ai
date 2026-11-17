# Kit de agente org ({date})

Reglas, subagentes, contextos y {n} skills para que cualquier agente de IA (Claude Code, Codex, Gemini/Antigravity, Copilot) trabaje
con los estándares de la organización. Funciona sin tener acceso a Centinela. Como el código nace siguiendo sus reglas, el análisis
posterior arroja el mínimo de hallazgos.

**Cómo leer esta guía:** primero la instalación (una vez por proyecto), luego la sección de tu rol. Cada sección dice qué cargar, cómo
pedirle las cosas al agente y qué revisar tú, porque el agente propone y una persona valida.

---

## 1. Instalación en un proyecto (una vez; la hace el líder técnico)
1. Copia a la raíz del repositorio: `AGENTS.md`, `CLAUDE.md`, `rules/`, `agents/`, `contexts/`.
2. Copia `skills/` a `.claude/skills/` (Claude Code) y/o `.agents/skills/` (otros agentes).
3. Llena la sección «Proyecto» de `AGENTS.md`: qué es, stack y versiones, cómo se levanta y se prueba, servicios externos (sin credenciales).
4. Si el proyecto ya tenía `AGENTS.md`/`CLAUDE.md`, conserva lo propio y añade las secciones del kit; gana la regla más estricta.
5. Haz commit en una rama y fusiónalo por Merge Request como cualquier cambio. Así queda versionado y revisado.

Para comprobarlo, abre el agente en el repositorio y pregúntale: «¿qué reglas obligatorias tienes para este proyecto?». Debe
responder con las de `AGENTS.md` (código real, sin secretos, documentación, autorización, pruebas, entrega honesta).

**Qué hay en el kit**
| Ruta | Qué es |
|---|---|
| `AGENTS.md` | Reglas obligatorias resumidas y mapa del resto del kit |
| `CLAUDE.md` | Entrada para Claude Code; remite a `AGENTS.md` |
| `rules/` | Reglas detalladas comunes y por lenguaje (Java/Spring Boot, Angular, TypeScript, Python, PostgreSQL) |
| `agents/` | Subagentes: revisor de código, revisor de seguridad, arquitecto, planificador |
| `contexts/` | Modos de trabajo: desarrollo, revisión, investigación |
| `skills/` | Skills por tema; índice en `skills/README.md` |

---

## 2. Desarrolladores (backend, frontend, base de datos, DevOps)

**Carga siempre:** `reglas-globales-org`, `estandares-desarrollo-org` y, antes de escribir o revisar código,
`prevencion-hallazgos-seguridad-calidad`. Esta última contiene el catálogo de cada regla que revisa el escáner, con cómo escribir el
código para no provocarla, y la lista de chequeo de entrega.

**Qué skill según lo que vas a hacer**
| Tarea | Skills |
|---|---|
| Módulo o endpoint Spring Boot | `backend-base-spring`, `backend-modulo-crud` o `backend-endpoint-paginado`, `backend-soporte-api`, `backend-persistencia-jpa`, `backend-seguridad` |
| Pantalla Angular | `primeng21-expert` (te dice qué más cargar), `generacion-componentes-ts`/`-html`, `generacion-servicios`, `frontend-auth-oidc`, `frontend-heuristicas-usabilidad` |
| Migración o modelo de datos | `database-liquibase-postgresql`, `postgres-audit` |
| Proyecto nuevo, Dockerfile, pipeline | `backend-proyecto-gradle`, `backend-pruebas-unitarias` |
| Módulo del CORE/Starter (usuarios, roles, folios, bitácora…) | `reglas-negocio-core-starter` |
| Documentar | `documentacion-codigo-y-api`, `generacion-documentacion` |
| Algo falla | `systematic-debugging` |
| Cambio grande | `blueprint` o `writing-plans` antes de tocar código |

**Flujo de un cambio**
1. **Parte de un requisito** (`RF-xxx`, ticket o caso de uso). Sin requisito no hay trazabilidad.
2. **Plan corto:** pídele al agente qué archivos tocará, qué reglas del catálogo aplican y cómo se verificará.
3. **Prueba primero** (`test-driven-development`): un caso que debe pasar y otro que debe fallar. En la API, el 401/403/409.
4. **Código y documentación juntos:**
   - `@Operation`/`@ApiResponses` con ejemplos en cada endpoint y Javadoc en los servicios;
   - TSDoc en servicios y componentes;
   - `COMMENT ON` en cada tabla y columna nueva;
   - README del módulo y ADR si tomaste una decisión de arquitectura.
5. **Antes del Merge Request:** recorre la lista de chequeo de `prevencion-hallazgos-seguridad-calidad`, ejecuta las pruebas y, si
   tienes escáner, córrelo sobre tus cambios. Pide al subagente `code-reviewer` o `security-reviewer` una revisión.
6. **Merge Request** con descripción, requisito ligado, salida real de las pruebas y revisor distinto del autor. CI en verde.

**Pídeselo así al agente (ejemplos)**
- «Genera el CRUD de Sedes con permiso base `CATALOGO_SEDES`, siguiendo `backend-modulo-crud`. Incluye pruebas de 403 y OpenAPI completo.»
- «Revisa este controlador contra el catálogo de `prevencion-hallazgos-seguridad-calidad` y dime qué reglas provocaría.»
- «El reporte de seguridad marca `AUTHZ-NO-METHOD-AUTHZ` y `JPA-ENTITY-MISSING-VERSION` en estos archivos: corrígelos con su prueba.»
- «Escribe la migración de la tabla `cita` con el estándar de auditoría y sus `COMMENT ON`.»

**No negociable**
- Nunca escribas credenciales en el código, la configuración, las pruebas ni el chat. Si una llegó a git, avisa: hay que rotarla.
- Nada de datos simulados, `TODO` ni funciones vacías en el código de la aplicación. Los mocks van solo en las pruebas.
- El agente entrega con estado honesto (COMPLETADO / PARCIAL / FALLIDO) y con la salida real de las pruebas. Exígelo.

---

## 3. Líderes de proyecto y PM

No necesitas escribir código para aprovechar el kit. Úsalo para que el trabajo del equipo y de los agentes deje **evidencia
verificable** y siga la metodología.

**Carga:** `metodologia-ca` (cómo se trabaja cada etapa y cada ticket de soporte), `generador-entregables-ca` (único medio para
generar un artefacto `.docx`), `cumplimiento-cmmi-iso` (qué evidencia CMMI V3.0 / ISO 27001 produce el trabajo diario) y
`triage-findings` (cómo leer un reporte de seguridad).

**Al iniciar el proyecto**
- Confirma que el kit está instalado y que `AGENTS.md` tiene la sección «Proyecto» llena.
- Decide y registra en el tailoring (0A-2b) si el contrato permite cargar el código del cliente a herramientas de IA. Si lo prohíbe, el
  agente no debe leerlo ni enviarlo, y el equipo debe saberlo.
- Define con el equipo quién revisa los Merge Request (siempre alguien distinto del autor) y que el CI debe estar en verde para fusionar.

**Durante el proyecto**
- **Requerimientos:** pide al agente que revise cada requerimiento contra los seis campos y los síntomas de la Guía de Análisis
  (fragmentación, colapso, criterios no comprobables…). La decisión final es del analista.
- **Artefactos:** genéralos con `generador-entregables-ca`. Todo lo que propone la IA lleva «Revisó / Fecha». Firmas, fechas de sesión,
  decisiones y montos los llena una persona, nunca el agente.
- **Control de cambios:** lo nuevo que el cliente pide en una sesión va a Control de Cambios; no se acepta en silencio.
- **Seguridad:** al recibir un reporte del escáner, separa vulnerabilidades de calidad y cumplimiento (`triage-findings`). Para un
  sistema con varios repositorios usa `consolidacion-auditoria-seguridad-generica`: arma el libro de triage, el plan de trabajo en horas
  y la matriz de seguimiento con SLA, y verifica el cierre comparando dos corridas.

**Al cerrar una etapa**
Recorre el checklist 0A-4 (ART-MC-02). Los puntos de seguridad y pruebas se respaldan con evidencia real (reporte del escáner, salida de
pruebas, Merge Requests revisados), nunca con texto de relleno.

**Qué exigir al equipo (y al agente)**
| Pide | Por qué |
|---|---|
| Cada cambio ligado a un requisito y fusionado por Merge Request revisado | Trazabilidad y revisión por pares (CMMI PR, RDM) |
| Pruebas ejecutadas con su salida real | Verificación (CMMI VV); «pasó» sin evidencia no cuenta |
| Cero hallazgos nuevos del escáner por Merge Request, o su justificación | Codificación segura (ISO 27001 8.28) |
| Versiones etiquetadas y ADR por decisión técnica | Gestión de configuración (CMMI CM, DAR) |
| Lo no verificado declarado como tal | Un porcentaje inflado es peor que un pendiente honesto |

---

## 4. Testers y QA

**Carga:** `metodologia-ca` (Guía de Pruebas: cómo se diseñan los casos, cómo se reporta un hallazgo, UAT), `bdd-spec-driven-development`
y `bdd-frontend-playwright` (de regla de negocio a escenario y prueba automatizada), `frontend-heuristicas-usabilidad` (qué revisar en
pantalla) y `prevencion-hallazgos-seguridad-calidad` (sección 9: comprobaciones en ejecución).

**Diseño de casos**
- Primero lo crítico para el negocio. Cada camino alterno y cada regla de negocio tienen su caso.
- Cada caso se prueba con el **usuario del actor**, nunca con un administrador que todo lo puede.
- Pide al agente: «A partir del requerimiento RF-012, propón los casos de prueba: camino principal, cada alterno y cada regla, con el rol
  que ejecuta cada uno». Revisa que cada caso tenga un criterio comprobable.
- No pruebes lo que no está listo: sin revisión, sin pruebas en verde o sin desplegar.

**Comprobaciones de seguridad y calidad que sí te tocan**
| Qué probar | Cómo | Regla relacionada |
|---|---|---|
| Un rol sin permiso no ve ni ejecuta la función | Entrar con ese rol: la opción no aparece y la API responde 403 | `SMART-TESTS-ACCESS-CONTROL-FAILURE`, `AUTHZ-NO-METHOD-AUTHZ` |
| Un perfil no ve datos de otros | Con dos usuarios de distinta unidad, comparar lo que recibe cada uno | `RUNTIME-PII-IN-RESPONSE`, `POTENTIAL-IDOR-NO-OWNERSHIP-CHECK` |
| El formulario no se envía con datos inválidos y marca cada campo | Enviar vacíos, formatos incorrectos, límites | `SMART-TESTS-FORM-INVALID-SUBMITTED`, `SMART-TESTS-FORM-NO-FIELD-ERROR` |
| Ninguna pantalla normal provoca un error 500 | Recorrer el flujo con la consola del navegador abierta | `RUNTIME-SERVER-ERRORS` |
| El token no aparece en la consola ni en la URL | Herramientas del navegador: consola y red | `RUNTIME-TOKEN-IN-CONSOLE`, `FRONTEND-TOKEN-IN-URL` |
| Borrar o revocar pide confirmación | Ejecutar la acción destructiva | `DESTRUCTIVE-ACTION-NO-CONFIRM` |
| Accesibilidad básica | Navegar solo con teclado; lector de pantalla en formularios; foco visible | `WCAG-*` |

El escáner no puede verificar el contraste, el orden de lectura, las trampas de teclado ni las reglas de negocio que solo se ven al
usar la aplicación: eso es tuyo. Las pruebas de carga o de fuerza bruta no se hacen contra ambientes compartidos sin autorización escrita.

**Reportar un hallazgo**
- Reproducible: pasos, datos de prueba, usuario y rol, evidencia (captura recortada, sin datos reales de personas).
- Antes de reportarlo, confirma que no sea una regla intencional del cliente. La referencia siempre es algo firmado.
- Al revalidar, prueba la corrección **y** lo que la rodea. Si falla, reabre el **mismo** defecto, no abras otro.

**UAT**
El usuario ejecuta y registra; no se le quita el teclado ni se discute el resultado. Clasificación: si contradice un criterio firmado es
**defecto**; si pide algo que ningún criterio cubre es **cambio**. Una zona gris la resuelven el líder de proyecto y el cliente.

---

## 5. Seguridad y quien consolida auditorías

**Carga:** `triage-findings`, `consolidacion-auditoria-seguridad-generica` y `prevencion-hallazgos-seguridad-calidad`.
- La clasificación (vulnerabilidad / falso positivo / calidad) es del analista: el agente propone con evidencia y aplica solo lo aprobado.
- Un falso positivo se decide por repositorio y archivo, nunca como regla general. El catálogo de ejemplo de la skill no trae decisiones
  de ningún proyecto.
- Nunca reproduzcas secretos de un reporte en el informe ni en la matriz: di dónde están y recomienda rotarlos.
- Quien corrige no valida su propio cierre.

---

## 6. Preguntas frecuentes
- **¿Necesito acceso a Centinela?** No. Las skills dicen cómo escribir el código. Si el proyecto tiene acceso al escáner, `preflight`
  consulta los hallazgos abiertos antes de editar.
- **¿Qué hago si una regla del kit choca con lo que pide el cliente?** Gana la más estricta y se registra la decisión (ADR o Control de Cambios).
- **¿Puedo modificar el kit en mi proyecto?** Sí, en tu copia. Si la mejora sirve para todos, propónla al equipo de arquitectura para
  la siguiente versión del kit.
- **¿El agente puede firmar o aprobar algo?** No. Propone; una persona revisa, decide y firma.
