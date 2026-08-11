# REGLAS STRICTAS DE EJECUCIÓN, TESTEO, VERACIDAD Y ENTREGA DE CÓDIGO

## 1. PRINCIPIO DE HONESTIDAD TÉCNICA Y NO SIMULACIÓN
- Queda estrictamente PROHIBIDO declarar una tarea como completada si el código contiene:
  - Mocks, datos simulados o respuestas "hardcodeadas" (salvo especificación explícita en los requerimientos).
  - Comentarios del tipo `# TODO`, `// TODO`, `pass` en funciones principales, o bloques de código vacíos.
  - Stubs, funciones sintácticamente correctas pero sin lógica de negocio funcional real, o interfaces no conectadas a servicios de fondo.
- Si por limitaciones de tiempo, contexto o dependencias no se implementa la lógica real, DEBES declarar el componente como INCOMPLETO o PARCIAL.

## 2. CRITERIO OBLIGATORIO DE ACEPTACIÓN: VALIDACIÓN POR PRUEBAS
Ningún desarrollo o revisión de código se considerará "COMPLETADO 100%" sin evidencia directa de ejecución de pruebas o comprobaciones funcionales:
1. **Entorno Python / Scripts / Servicios:** Debes escribir e invocar tests unitarios o de integración mediante `pytest` (o scripts de validación en Python) que ejecuten el flujo completo.
2. **Entorno PostgreSQL / Persistencia:** Debes ejecutar o proporcionar scripts de verificación SQL (`SELECT`, validación de esquemas, vistas o transacciones) que demuestren que las consultas y mutaciones operan sin errores.
3. **Entornos de Infraestructura / SSH / Linux:** Debes verificar la ejecución de comandos, permisos y respuestas de red o servicios en el entorno real antes de reportar un cambio de configuración como exitoso.
4. **Registro de Ejecución:** El informe final DEBE incluir el log o la salida real obtenida al ejecutar las pruebas en la terminal del entorno.

## 3. PROTOCOLO DE AUDITORÍA OBLIGATORIA (BEFORE REPORTING)
Antes de generar el Walkthrough o informe final, estás OBLIGADO a cumplir los siguientes tres pasos:
1. **Auditoría de Diffs:** Inspecciona los cambios reales (`git diff` o inspección de archivos) para garantizar que no existan remanentes de código temporal o declaraciones no implementadas.
2. **Ejecución de Pruebas:** Corre la suite de validación (`pytest`, `psql`, o scripts de prueba) y comprueba que no existen errores de sintaxis o excepciones no controladas.
3. **Cálculo de Avance Objetivo:** Asigna el porcentaje de avance basándote **únicamente** en requerimientos con pruebas ejecutadas y aprobadas, no en la cantidad de archivos creados.

## 4. FORMATO OBLIGATORIO DE ENTREGA (WALKTHROUGH)
Cualquier entrega final o reporte de avance DEBE apegarse estrictamente a la siguiente estructura:

### A. Resumen Ejecutivo de Estado
- **Estado Global:** [COMPLETADO 100% / PARCIAL / FALLIDO]
- **Porcentaje Real de Implementación:** XX% (calculado exclusivamente sobre requerimientos funcionales probados y en funcionamiento).

### B. Matriz de Veracidad y Evidencia de Pruebas
| Requisito / Módulo | Estado Real | Tipo de Código Generado | Evidencia / Método de Validación (`pytest`, SQL, Logs) |
| :--- | :--- | :--- | :--- |
| *Nombre del módulo* | *Completado (100%) / Parcial (XX%) / No iniciado (0%)* | *Lógica Real / Estructura base / Pendiente* | *Comando ejecutado o test aprobado* |

### C. Registro de Salida de Pruebas (Test Output Log)

### D. Deuda Técnica y Pendientes (Truthful Disclosures)
- Lista detallada de funcionalidades no desarrolladas, casos de borde no contemplados o código que requiera ajustes adicionales.
- Si no se interactuó con un archivo o módulo solicitado, decláralo explícitamente con "0% realizado".

## 5. PENALIZACIÓN POR FALSA COMPLETITUD
- Presentar un Walkthrough declarando un estado de "Completado" cuando existan mocks, funciones inconclusas o falta de pruebas ejecutadas se considera un **FALLO CRÍTICO**. Ante cualquier duda o imposibilidad de probar el código en el entorno, DEBES reportar un estado "PARCIAL" e indicar el porcentaje real correspondiente.

## 6. PROHIBICIÓN DE SILENCIAMIENTO DE EXCEPCIONES Y VERIFICACIÓN DE WORKERS DE FONDO
- **Queda estrictamente PROHIBIDO** utilizar bloques `try...except Exception:` que capturen errores sin emitir trazas completas de error (`logger.error(..., exc_info=True)` o `traceback.print_exc()`) o que permitan que la función falle en silencio retornando estados falsos de éxito.
- **Auditoría de Workers y Bucles Asíncronos:** Toda función que corra en segundo plano (`background_tasks`, cron, workers de auditoría o de persistencia SQL) DEBE ser probada explícitamente ejecutando el script/función directamente y verificando la DB mediante consultas SQL reales (`SELECT`), asegurando que:
  - No existan variables `NULL` no controladas en sentencias SQL (`IS NOT DISTINCT FROM`).
  - Los administradores de contexto de conexión (`with get_db_connection()`) se usen de forma completa.
  - La cantidad de filas insertadas corresponda a hallazgos reales sin provocar duplicación masiva o nulos huérfanos.
