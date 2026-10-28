# Reglas de seguridad

Obligatorias en todo proyecto. Base: OWASP Top 10 (2021), OWASP API Security Top 10 (2023), ASVS 4.0 y CIS. Cada regla indica, cuando
existe, el detector de Centinela que la verifica (`rules/centinela/rules.md`); la corrección regla por regla está en la skill
`centinela-developer-standards`. Ocultar algo en la interfaz nunca cuenta como control.

## 1. Secretos
1. Ninguna contraseña, token, llave, `client-secret` ni cadena de conexión con credenciales en código, `application*.properties`/`.yml`,
   `environment*.ts`, SQL, pruebas, documentación, CI ni commits (`HARDCODED-SECRET`, `CONFIG-SECRET-LITERAL`, `CONFIG-JWT-SECRET-LITERAL`,
   secretos en el historial). Van en variables de entorno o gestor de secretos (Vault), **sin valor por omisión**.
2. Un secreto que llegó a un repositorio se **rota**; borrarlo del archivo no basta (sigue en el historial).
3. Nunca variables públicas de frontend (`VITE_*`, `NEXT_PUBLIC_*`) con credenciales (`FRONTEND-EXPOSED-DB-CREDENTIAL`).
4. `.env` fuera del repositorio (`.gitignore`) y con permisos restringidos en el servidor.

## 2. Autenticación y sesión
1. Autenticación delegada a Authentik (OIDC): Authorization Code + PKCE en el frontend, Resource Server en el backend. Nada de formularios
   propios de usuario/contraseña contra la API ni implicit flow (skills `frontend-auth-oidc`, `backend-seguridad`).
2. `requireHttps` y validación estricta del discovery en `true` fuera de local (`FRONTEND-OIDC-INSECURE-CONFIG`).
3. Tokens solo en `Authorization: Bearer`; nunca en la URL (`JWT-IN-URL-PARAM`, `FRONTEND-TOKEN-IN-URL`), en logs ni en `localStorage` sin
   justificación (`FRONTEND-JWT-LOCALSTORAGE`, `FRONTEND-SENSITIVE-STORAGE`).
4. Cookies `Secure` + `HttpOnly` + `SameSite` (`INSECURE-COOKIE-FLAGS`); fijación de sesión activa (`SESSION-FIXATION-DISABLED`).
5. Endpoints de login con límite de intentos (`AUTH-ENDPOINT-NO-RATE-LIMIT`); política de contraseñas validada en el servidor
   (`PASSWORD-POLICY-NOT-ENFORCED`); secretos y firmas comparados en tiempo constante (`TIMING-UNSAFE-SECRET-COMPARISON`).

## 3. Autorización
1. **Cada método de controlador** lleva su permiso (`@PreAuthorize("hasAuthority('…')")` o a nivel de clase): `AUTHZ-NO-METHOD-AUTHZ`,
   `AUTHZ-PREAUTHORIZE-COMMENTED-OUT`, `AUTHZ-PUBLIC-SENSITIVE-READ`. Un `permitAll` sobre escrituras es un hallazgo.
2. **Propiedad del recurso** (IDOR/BOLA): un id recibido del cliente se verifica contra el usuario o la unidad que lo pide
   (`POTENTIAL-IDOR-NO-OWNERSHIP-CHECK`). La lectura también se autoriza por rol, no solo la escritura.
3. Sin controladores de prueba, demo o «sandbox» en `src/main` ni rutas de prueba en el router de producción
   (`BACKDOOR-SANDBOX-CONTROLLER`, `AUTHZ-TEST-ENDPOINT-EXPOSED`, `FRONTEND-TEST-ROUTE-EXPOSED`).
4. Guards y `*appIfPermiso` del frontend solo ocultan; el backend valida el mismo permiso (`AUTHZ-CLIENT-SIDE-*`).
5. Sin asignación masiva: los DTOs de entrada no son entidades y no traen `id`, rol, dueño ni estado (`MASS-ASSIGNMENT-ENTITY-BINDING`).

## 4. Entrada y salida
1. Todo DTO de entrada con `@Valid` y restricciones (`REQUESTBODY-WITHOUT-VALID`); lista blanca de valores en `ORDER BY` y filtros.
2. Consultas parametrizadas siempre: nada concatenado en SQL, JPQL, LDAP, XPath, plantillas ni comandos del sistema (`SQL-INJECTION-*`,
   `XPATH-INJECTION-CONCAT`, `LDAP-INJECTION-CONCAT`, `SSTI-TEMPLATE-FROM-INPUT`, inyección de comandos).
3. Sin XSS: nada de `bypassSecurityTrust*`/`[innerHTML]` con datos externos sin `DOMPurify` (`ANGULAR-BYPASS-SECURITY-TRUST`);
   redirecciones solo a destinos de una lista blanca (`CLIENT-SIDE-REDIRECT`); `postMessage` con origen verificado (`POSTMESSAGE-*`).
4. Sin SSRF: el destino de una petición saliente nunca sale de la entrada del usuario sin validar contra una lista blanca.
5. Subida de archivos: tamaño máximo, lista blanca de extensiones, tipo real del contenido, nombre generado por el servidor, fuera de la
   ruta pública (`FILE-UPLOAD-NO-VALIDATION`); lectura en streaming, no en `byte[]` (`OOM-BYTE-ARRAY-STREAMING`).
6. Respuestas de la API: DTO de salida, nunca la entidad (`ENTITY-RETURNED-FROM-CONTROLLER`); sin datos personales de más.

## 5. Errores, registro y bitácora
1. Errores al cliente sin trazas, SQL ni mensajes internos (`STACK-TRACE-EXPOSURE`); un `GlobalExceptionHandler` traduce.
2. Ningún error silenciado (`SWALLOWED-ERROR`, `rules/common/error-handling.md`).
3. Las operaciones que modifican datos dejan rastro (usuario, acción, recurso, fecha) sin contraseñas, tokens ni datos personales en el
   log (`STD-STRIDE-MISSING-AUDIT-LOG`, `STD-STRIDE-LOG-SENSITIVE-DATA`). La auditoría de base de datos sigue `rules/postgres/rules.md`.

## 6. Criptografía y transporte
1. Sin algoritmos débiles (MD5, SHA-1 para firma, DES, RC4, AES sin modo, ECB) ni CBC sin autenticación (`WEAK-CRYPTOGRAPHY`,
   `CRYPTO-CBC-NO-AUTHENTICATION`); usar AES-GCM y bibliotecas estándar. Aleatorio criptográfico para tokens (`INSECURE-RANDOM-FOR-SECRET`).
2. TLS 1.2+ en todo servicio expuesto, certificado válido, sin desactivar la verificación de certificados (`JVM-GLOBAL-SSL-BYPASS`);
   WebSocket con `wss://` (`INSECURE-WEBSOCKET`).
3. CORS sin `*` cuando hay credenciales (`CORS-WILDCARD-ORIGIN`); cabeceras de seguridad (HSTS, CSP, `X-Content-Type-Options`,
   `frame-ancestors`) en el proxy.

## 7. Configuración del framework
- `spring.jpa.hibernate.ddl-auto=none` (`SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE`); sin DevTools remoto ni actuator/Swagger UI abiertos sin
  autenticación en producción; GraphQL sin introspección en producción (`GRAPHQL-INTROSPECTION-ENABLED`).

## 8. Dependencias y cadena de suministro
1. Sin dependencias con CVE conocido sin plan (SCA); lockfile versionado y versiones fijadas (`SUPPLY-CHAIN-NO-LOCKFILE`,
   `SUPPLY-CHAIN-UNPINNED-DEPENDENCY`); versiones vigentes al crear el proyecto (`rules/common/versions.md`).
2. Nada de `curl | sh` en Dockerfile ni CI (`DOCKER-CURL-PIPE-SHELL`); imágenes con etiqueta fija, no `:latest`.
3. Licencias compatibles con el proyecto (auditor de licencias).

## 9. Contenedores, infraestructura y servidores
1. Dockerfile con `USER` no root (`DOCKER-MISSING-NON-ROOT-USER`); sin `privileged`, `hostPath` ni `0.0.0.0/0` de entrada; puertos de
   servicios internos ligados a `127.0.0.1` detrás del proxy.
2. Servidores con el subconjunto CIS que mide Centinela: sin login de root por SSH, sin autenticación por contraseña, firewall y `auditd`
   activos, parches de seguridad al día.
3. Ramas por defecto protegidas, sin force-push, variables de CI enmascaradas (configuración de GitLab).
4. Reportes, `.docx`, `.pdf` y `.zip` nunca en carpetas públicas del frontend.

## 10. Webhooks e integraciones
- Fail-closed: sin secreto configurado → rechazo; secreto incorrecto → 401/403; comparación en tiempo constante. Nunca usar una URL tomada
  del payload para clonar o llamar con credenciales.
- Las pruebas de seguridad (DAST, fuzzing) solo contra ambientes autorizados y nunca con fuerza bruta.
