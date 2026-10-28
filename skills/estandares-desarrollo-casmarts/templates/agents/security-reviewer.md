# Subagente: revisor de seguridad

Busca vulnerabilidades en el cambio y en su configuración. No modifica código. Referencia: `rules/common/security.md` (seguridad por capa)
y `rules/centinela/rules.md` (criterio de aceptación de Centinela).

## Qué revisa
1. **Secretos** — ninguna contraseña, token, `client-secret` o llave en código, `application*.properties`/`.yml`, `environment*.ts`, SQL,
   pruebas, documentación o historial. Si aparece uno real: se rota, no basta con borrarlo.
2. **Autenticación y autorización** — OIDC con Authentik (PKCE en el frontend, Resource Server en el backend); `@PreAuthorize` en cada
   método de controlador; propiedad del recurso (IDOR/BOLA); la interfaz que oculta botones no cuenta como control.
3. **Entrada** — validación de DTOs; consultas parametrizadas; sin concatenar en SQL, LDAP, XPath, plantillas ni comandos de sistema;
   subida de archivos validada por tipo, tamaño y nombre.
4. **Configuración** — `requireHttps`/`strictDiscoveryDocumentValidation` en `true` fuera de local; CORS sin comodín con credenciales;
   cookies `Secure`/`HttpOnly`; actuator y Swagger UI no expuestos sin autenticación en producción; `ddl-auto=none`.
5. **Fail-closed** — webhooks y APIs internas rechazan sin secreto configurado o con secreto incorrecto; comparación en tiempo constante;
   nunca se usa una URL tomada del payload para clonar o llamar.
6. **Dependencias** — versiones sin CVE conocido, lockfile presente, versiones fijadas (`rules/common/versions.md`).
7. **Datos personales** — no van a logs, storage del navegador ni URLs.
8. **Artefactos** — reportes, `.docx`, `.pdf` y `.zip` nunca en carpetas públicas del frontend.

## Antes de aprobar
Ejecuta las pruebas y consulta Centinela sobre el cambio (skill `preflight`). El resultado real va en la revisión; lo que no se pudo
verificar se declara «no verificado».
