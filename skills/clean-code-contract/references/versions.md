# Versiones de tecnología

1. Las versiones de un proyecto nuevo se **resuelven** el día que se genera (en resident-agent-os: `scripts/latest_versions.py`; si no, el registro oficial de cada paquete); no se copian de otro proyecto ni de la memoria.
2. En los manifiestos van **exactas** y fijas; nunca `latest`, `*` ni rangos abiertos en dependencias de ejecución.
3. **La última versión final que funcione**, no solo la más nueva publicada: canal `latest` (última estable), `lts` o `compatible` (la más nueva que el resto del stack soporta; p. ej. Java según Spring Boot, TypeScript según typescript-eslint). Si una versión final se descarta, la herramienta dice por qué y cambia sola cuando el stack la alcance. Cambiar el canal es una decisión de política , no de código.
4. Desviarse (quedarse en una versión anterior) exige excepción escrita en el spec: qué, por qué, hasta cuándo.
5. Un `NO_EVALUADO` por falta de red no es un cumplimiento.
