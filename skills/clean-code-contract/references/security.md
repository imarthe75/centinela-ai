# 🛡️ Security Best Practices & Audit Guidelines

Normas estrictas para la prevención de vulnerabilidades y la gestión segura de secretos en el ecosistema.

*Nota de Atribución: Estas directivas de seguridad se basan en el marco de AgentShield e integran principios del proyecto de código abierto **affaan-m/ECC** (Licencia MIT).*

## 📌 Gestión de Secretos y API Keys

1. **Cero Tolerancia a Secretos Hardcodeados:**
   - Queda estrictamente prohibido commitear contraseñas, tokens de API, claves secretas o certificados SSL en el repositorio de Git.
   - Utiliza variables de entorno cargadas desde archivos `.env` (los cuales deben estar siempre en el archivo `.gitignore` del proyecto).
2. **Auditoría de Inyecciones de Código:**
   - No ejecutes comandos del sistema usando entradas de usuario de forma directa sin antes sanear y validar adecuadamente los argumentos.
3. **Control de Acceso (Principio de Mínimo Privilegio):**
   - Asegura que los scripts de bases de datos, APIs y herramientas utilicen credenciales con los mínimos permisos de lectura/escritura requeridos para operar.
4. **Validación en Tiempos de Ejecución:**
   - Utiliza validadores estáticos de seguridad (SAST) y análisis de dependencias antes de integrar nuevas librerías al ecosistema.

## 📌 Fail-closed en webhooks y APIs públicas

1. **Si falta el secreto, se rechaza.** Un endpoint que recibe webhooks exige un token configurado en el entorno; sin token configurado responde 503 y con token incorrecto 401/403. Nunca devuelve «ignorado» ni procesa la petición sin autenticar.
2. **Comparación en tiempo constante** (`hmac.compare_digest`).
3. **El payload no decide a quién llamas.** No clones ni descargues una URL tomada del cuerpo de la petición: valida el host contra el servidor autorizado **antes** de adjuntar credenciales (previene SSRF y fuga de tokens).
4. **Peticiones sin token en rutas públicas** no deben alcanzar lógica de negocio ni escribir en la base.
El verificador `webhooks_fail_closed` revisa las rutas `webhook` de FastAPI.

## 📌 Escaneo en cada cambio
Si el proyecto tiene un escáner de seguridad, cada Merge Request se escanea y no introduce hallazgos nuevos; lo que no se pudo escanear se
declara «no verificado por escáner». Las reglas de corrección por lenguaje están en `java.md`, `angular.md`, `typescript.md`.
