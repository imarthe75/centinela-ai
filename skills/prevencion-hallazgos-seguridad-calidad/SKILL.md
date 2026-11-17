---
name: prevencion-hallazgos-seguridad-calidad
description: Cómo escribir código, configuración, migraciones, contenedores y pipelines que nazcan sin vulnerabilidades ni incidencias de calidad, con trazabilidad a las reglas que reporta el escáner de la organización (Centinela) y a ISO 27001 / CMMI V3.0. Úsala siempre que escribas o revises código backend (Spring Boot, Python), frontend (Angular, React, TypeScript), SQL, Dockerfile, Kubernetes, Terraform o CI; antes de entregar un cambio; y cuando un reporte de seguridad cite un identificador de regla (AUTHZ-*, CONFIG-*, JPA-*, WCAG-*, SQL-*, SCA-*, WSTG-*…) y haya que saber cómo corregirlo. No hace falta tener ni conocer el escáner.
---

# Código sin hallazgos: seguridad y calidad desde la primera línea

El escáner de la organización revisa cada repositorio y reporta cada problema con un **identificador de regla estable**
(`AUTHZ-NO-METHOD-AUTHZ`, `CONFIG-SECRET-LITERAL`, `WCAG-1.1.1-IMG-MISSING-ALT`…). Esta skill reúne todas esas reglas en
`references/catalogo-reglas.md` con lo que hay que escribir para no provocarlas. Un análisis posterior de un código escrito así
arroja el mínimo de hallazgos, y lo que quede es una decisión consciente, no un descuido.

## Cómo usarla
1. **Antes de escribir**, ubica la capa que vas a tocar y aplica su sección del catálogo:

   | Vas a escribir… | Sección del catálogo | Skill con el detalle |
   |---|---|---|
   | Controlador, servicio o entidad Spring | 1 y 2 | `backend-base-spring`, `backend-seguridad`, `backend-persistencia-jpa`, `backend-modulo-crud` |
   | Componente, servicio o ruta Angular/React | 3 | `primeng21-expert`, `generacion-componentes-ts`, `generacion-servicios`, `frontend-auth-oidc` |
   | Plantilla HTML o estilos | 3.3 | `generacion-componentes-html`, `generacion-estilos` |
   | Migración SQL o modelo de datos | 4 | `database-liquibase-postgresql`, `postgres-audit` |
   | `application*.properties`, `.env`, `environment.ts` | 5 | `reglas-globales-org` |
   | `pom.xml`, `build.gradle`, `package.json`, `requirements.txt` | 6 | `backend-proyecto-gradle` |
   | Dockerfile, Kubernetes, Terraform, `.gitlab-ci.yml` | 7 | `backend-proyecto-gradle`, `backend-pruebas-unitarias` |
   | Endpoint nuevo o cambio de contrato | 8 | `documentacion-codigo-y-api` |
   | Configuración del servidor, proxy o dominio | 10 | `postgres-audit` (BD) |
   | Llamadas a un modelo de IA | 11 | `reglas-globales-org` |

2. **Mientras escribes**, cumple las prácticas obligatorias de abajo; son las que más hallazgos evitan.
3. **Antes de entregar**, recorre la lista de chequeo del final. Si tienes un escáner disponible (el de la organización, Semgrep,
   SonarQube, Trivy), córrelo sobre tus cambios y corrige hasta cero hallazgos nuevos; si no, declara «no verificado por escáner».
4. **Si un reporte cita una regla**, búscala por su identificador en el catálogo: la fila dice el riesgo y la corrección.

## Prácticas obligatorias

**Control de acceso.** Cada endpoint que modifica datos, toca identidad o devuelve datos de personas lleva autorización por método
(`@PreAuthorize`) con un permiso del catálogo de roles y una prueba que verifica el 403. La propiedad del recurso se comprueba en el
servidor con el usuario del token. Ocultar un botón no es autorización. Nada de controladores de prueba ni logins alternos en `src/main`.

**Entrada y salida.** DTO de entrada con `@Valid` y Bean Validation; DTO de respuesta con los campos mínimos; nunca la entidad JPA en
el contrato. Errores con un manejador global: respuesta genérica al cliente, traza solo al log. Ninguna excepción atrapada en silencio.

**Secretos.** Cero credenciales, llaves o secretos de firma en el código, en `application*.properties|yml`, en `environment*.ts` ni en
el pipeline: variables de entorno o gestor de secretos. Un secreto que llegó a git se rota (sigue en el historial). Nunca lo copies
en un chat, ticket, log o commit.

**Datos.** Consultas parametrizadas siempre. `@Version` en entidades que editan varios usuarios; `@Transactional` en el servicio
cuando hay varias escrituras; paginación con límite en todo listado; sin consultas dentro de bucles. Migraciones con llave primaria
`uuid DEFAULT uuidv7()`, `timestamptz`, `jsonb`, `numeric` para montos, columnas de auditoría y `COMMENT ON`. `ddl-auto=none`.

**Criptografía y sesión.** AES-GCM, SHA-256 o superior, bcrypt/Argon2 para contraseñas, `SecureRandom` para tokens, comparación en
tiempo constante. Token solo en `Authorization: Bearer`, nunca en la URL ni en la consola. Cookies `Secure; HttpOnly; SameSite`. CORS
con orígenes explícitos. Verificación TLS siempre activa.

**Frontend.** Sin `bypassSecurityTrust*`/`innerHTML` con datos externos sin sanitizar. Suscripciones con limpieza
(`takeUntilDestroyed`), sin `subscribe` anidados, botón de envío bloqueado mientras la petición está en curso, confirmación con el
diálogo estándar antes de borrar. Accesibilidad WCAG 2.1 AA en cada plantilla: etiquetas, `alt`, nombres en botones de icono, `lang`,
ids únicos, foco visible. Es un requisito legal en proyectos de gobierno.

**Dependencias y contenedores.** Versiones exactas con lockfile, sin dependencias muertas ni con CVE conocidas, licencias permisivas
o documentadas. Imágenes con versión fija y `USER` sin privilegios; Kubernetes sin `privileged` y con sistema de archivos de solo
lectura; nada de `curl | sh`.

**Documentación (cuando aplique, en el mismo cambio).** Javadoc/TSDoc/docstring en la API pública; `@Operation` + `@ApiResponses`
con ejemplos en cada endpoint y el contrato OpenAPI versionado; `COMMENT ON` en cada tabla y columna nueva; README por módulo; ADR
por cada decisión de arquitectura. Detalle en `documentacion-codigo-y-api`. Un endpoint sin contrato es un hallazgo (`API-*`).

**Pruebas.** La prueba primero (`test-driven-development`): un caso que debe fallar y otro que debe pasar, en especial para
autorización y validación. Ninguna prueba omitida sin motivo. Pipeline que falla de verdad: sin `allow_failure` en pruebas,
lint ni seguridad.

## Lo que el escáner no puede verificar (no lo des por cumplido)
- Que el permiso usado exista en el catálogo de roles y que un endpoint público lo sea a propósito: revisión humana.
- Contraste de color, reflujo, orden lógico de lectura y trampas de teclado: navegador y revisión humana.
- Reglas de negocio que solo se ven ejecutando la aplicación (límites, estados, flujos): pruebas funcionales.
- Pruebas de fuerza bruta y carga: no se hacen contra ambientes compartidos sin autorización.
- Un «0 hallazgos» solo vale donde el motor correspondiente corrió y cubre ese lenguaje.

## Cómo aporta al cumplimiento
Trabajar así produce evidencia para ISO/IEC 27001:2022 (8.25 ciclo de desarrollo seguro, 8.26 requisitos de seguridad, 8.28
codificación segura, 8.29 pruebas de seguridad, 8.9 configuración, 8.24 criptografía, 5.17 autenticación, 8.8 vulnerabilidades
técnicas) y para CMMI V3.0 (PR revisión por pares, VV verificación, CM gestión de configuración, TS/PI diseño e integración). Cómo se
mide y qué artefactos lo respaldan: `cumplimiento-cmmi-iso` y `metodologia-ca`.

## Lista de chequeo antes de entregar
- [ ] Cada endpoint que muta o toca identidad tiene `@PreAuthorize` activo; los públicos están declarados a propósito.
- [ ] Sin controladores de prueba en `src/main` ni rutas demo en el router de producción.
- [ ] Cero secretos literales en código, configuración, `environment*` y pipeline.
- [ ] DTO con `@Valid` a la entrada y DTO a la salida; errores genéricos al cliente.
- [ ] Consultas parametrizadas; `@Version`, `@Transactional` y paginación donde aplican.
- [ ] Criptografía y tokens según la sección 1.5 del catálogo; cookies y CORS correctos.
- [ ] Frontend: sin HTML sin sanitizar, sin tokens en URL/consola/`localStorage` con secretos, accesibilidad completa.
- [ ] Migraciones con el estándar de BD, `COMMENT ON` y sin `ddl-auto`.
- [ ] Dependencias con versión exacta, lockfile y sin CVE conocidas; imagen con `USER` y versión fija.
- [ ] Documentación de código, OpenAPI y README actualizados en el mismo cambio.
- [ ] Pruebas nuevas ejecutadas con su salida real; escáner corrido sobre los cambios o «no verificado por escáner».
