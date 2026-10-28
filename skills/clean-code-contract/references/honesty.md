# Honestidad técnica y estado real de la entrega

Un resultado que parece terminado y no lo está es peor que uno declarado incompleto: nadie lo vuelve a mirar.

## 1. Qué NO es «terminado»
Una tarea no se declara completada si el código contiene:
- datos simulados, respuestas escritas a mano o mocks presentados como funcionamiento real (salvo que el requisito pida un simulador);
- `TODO`/`FIXME`, funciones con solo `pass`/`...`/`NotImplementedError`, bloques vacíos;
- funciones que compilan pero no hacen el trabajo, o interfaces sin conexión a un servicio real;
- una acción «automática» que devuelve éxito sin haber ejecutado nada comprobable (si no se ejecutó, el estado es `not_executed` o `manual_action_required`).

El verificador `no_stubs` revisa lo mecánico; el resto es responsabilidad de quien entrega.

## 1.1 Durante el desarrollo, no solo al entregar
Desde el primer commit se escribe la funcionalidad real. En el código de la aplicación (cualquier rama) no van datos simulados, respuestas
fijas, pantallas maqueta con botones que no hacen nada ni código comentado «para después». Los mocks solo viven en pruebas (declarados) o en
un simulador explícito de ambiente local que el build de producción no incluye. Si falta una dependencia, se programa contra su contrato
real y la tarea queda `PARCIAL — bloqueada por X`. Detalle en la skill `reglas-globales-org` §2.1.

## 2. Estados permitidos
`COMPLETADO` (todo probado en el entorno real) · `PARCIAL` (con el porcentaje real) · `FALLIDO`.
El porcentaje se calcula **solo sobre requisitos con prueba ejecutada y aprobada**, nunca por cantidad de archivos. Ante la duda, `PARCIAL`.

## 3. Lo que solo se probó con mocks
Una suite verde con mocks demuestra la lógica en aislamiento, no el funcionamiento real. Se declara literalmente:
**«VALIDADO ÚNICAMENTE CON MOCKS EN AISLAMIENTO (0 % EN PRODUCCIÓN)»**.

## 4. Lo que no se puede medir
Un control o requisito que no se puede evaluar con código, configuración o sondeo se declara `NO EVALUADO` / `N/A`. No se inventan denominadores ni porcentajes para que la cifra «se vea realista».

## 5. Formato de entrega (obligatorio)
1. **Resumen ejecutivo de estado** — `COMPLETADO / PARCIAL / FALLIDO` y el porcentaje real.
2. **Matriz de veracidad** — tabla: requisito · estado real · tipo de código (lógica real / estructura base / pendiente) · evidencia (comando ejecutado).
3. **Registro de salida de pruebas** — la salida real, copiada, no resumida.
4. **Deuda técnica y pendientes** — lo no hecho, lo no probado, lo que no se tocó («0 % realizado»).

## 6. Parches y diffs
Un parche solo se presenta si pasó `git apply --check` contra el código real (`scripts/patch_validator.py`). Si no pasa, se declara «requiere remediación manual»: nunca se entrega un diff con contexto inventado.

## 7. Auditoría antes de reportar
Antes de entregar: lee el `git diff` real (¿quedó código temporal?), corre las pruebas y los verificadores, y calcula el avance. Si no pudiste ejecutarlo, dilo.

## 8. Agentes y automatizaciones
Una automatización o un agente que depende de un modelo, un servicio o una herramienta externa **nunca devuelve éxito sin haberlos usado**. Si el modelo no responde, no hay credenciales o la herramienta falló, el resultado es `unavailable` o `failed` con el motivo; jamás «ejecutado correctamente». Una acción de respuesta que no se ejecutó se registra como `not_executed` o `manual_action_required`.

## 9. Entregables: el análisis final, no el historial de intentos
Un reporte o resumen entregado presenta el **resultado final y su estado actual**; no cuenta lo que se intentó y no funcionó ni los errores intermedios ya corregidos. Esto no oculta límites: lo no logrado o no verificado se declara como estado actual («no verificado», «PARCIAL», «pendiente: requiere X») con su causa en una frase, sin el recorrido. El historial de un intento fallido solo se guarda donde sirve de lección (un ADR o el mensaje de commit), nunca en el entregable.
