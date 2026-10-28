# 🧪 Testing & Verification Loop Guidelines

Reglas y metodologías de prueba para asegurar que cada desarrollo funcione de forma determinista antes de su despliegue.

*Nota de Atribución: Estas directivas de pruebas unitarias y TDD están alineadas con las prácticas de **affaan-m/ECC** (Licencia MIT).*

## 📌 Desarrollo Orientado a Pruebas (TDD)

1. **Ciclo Rojo-Verde-Refactor:**
   - Escribe una prueba unitaria que falle (Rojo).
   - Escribe el código mínimo necesario para hacer pasar la prueba (Verde).
   - Limpia y optimiza el código manteniendo las pruebas en verde (Refactor).
2. **Cobertura Mínima:**
   - Todo nuevo servicio, utilidad o componente crítico de negocio debe contar con al menos un **80% de cobertura de código**.
3. **Mocks de Integración Externa y Límite de Alcance:**
   - Las pruebas unitarias pueden usar mocks para aislar servicios externos (OpenAI, Anthropic, endpoints de terceros).
   - **Prohibición de Teatro de Verificación:** Que una prueba unitaria pase con mocks NO SIGNIFICA que la integración funcione en producción. Queda estrictamente PROHIBIDO declarar una funcionalidad como "100% completada" o "probada en producción" si la evidencia proviene únicamente de mocks. Debe reportarse honestamente como "VALIDADO ÚNICAMENTE CON MOCKS (0% EN PRODUCCIÓN)".
4. **Verificación Automatizada y Validación Real de Entorno:**
   - Utiliza scripts locales de test automatizados antes de realizar cualquier commit o push de Git.
   - Toda función con efectos colaterales (persistencia, integraciones, comandos de sistema) debe verificarse en el entorno real mediante consultas SQL de comprobación (`SELECT`) o inspección de comandos ejecutados en el host.
5. **Aislamiento e Inviolabilidad de Datos de Producción:**
   - Queda estrictamente prohibido que las suites de pruebas o scripts de verificación contaminen tablas de producción con datos simulados, usuarios o servidores ficticios.
   - Las pruebas deben ejecutarse con transacciones revertidas (`ROLLBACK`), bases de datos de prueba aisladas o fixtures limpiadas automáticamente tras la ejecución.

