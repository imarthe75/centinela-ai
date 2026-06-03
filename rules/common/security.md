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
