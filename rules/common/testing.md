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
3. **Mocks de Integración Externa:**
   - Las pruebas unitarias no deben realizar llamadas de red reales a APIs externas. Mockea servicios como OpenAI, Anthropic o endpoints externos de terceros.
4. **Verificación Automatizada:**
   - Utiliza scripts locales de test automatizados antes de realizar cualquier commit o push de Git.
