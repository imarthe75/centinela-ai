# 🛡️ ECC Agent Workflow Rules (RULES.md)

Este archivo define las reglas de desarrollo y hooks de sistema inspirados en **affaan-m/ECC** para asegurar la calidad de código, triaje y control del arnés del agente.

## 📌 Flujo de Trabajo (Harness Workflow)

1. **Investigación y Contexto Primero:**
   - Queda prohibido modificar código sin antes listar el mapa técnico local en `.agent/MAP.md`.
   - Si no existe el archivo `.agent/STATE.md`, se debe invocar la inicialización automática del proyecto (`npm run init-project`).

2. **Higiene de Contexto y Token Saving:**
   - Al ejecutar comandos o búsquedas, limita el output y la cantidad de líneas devueltas (ej. `head -n 20`).
   - Evita lecturas completas de archivos binarios o bases de datos sin filtros.

3. **Caché de Respuestas y Memoria:**
   - Integración nativa con Valkey. La lógica de control debe verificar la caché semántica local en Valkey (`6379`) antes de enviar consultas redundantes al modelo.

4. **Soberanía y Seguridad de Datos:**
   - Ninguna credencial, token (PAT) o credencial de base de datos puede ser subida a repositorios públicos o expuesta en logs.
   - Las carpetas `./data` y los archivos `.env` deben estar permanentemente en el `.gitignore`.
