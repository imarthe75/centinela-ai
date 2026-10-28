# Pruebas y bucle de verificación

Las pruebas existen para demostrar que algo funciona, no para ponerse en verde.

## 1. Desarrollo guiado por pruebas
1. **Rojo**: escribe la prueba que falla. 2. **Verde**: el código mínimo que la pasa. 3. **Refactor** con todo en verde.
Cada regla, validación o función con lógica de decisión lleva **un caso que debe fallar y otro que debe pasar**: una regla sin caso negativo termina marcando lo que no debe.

## 2. Qué cuenta como evidencia
- La prueba que ejercita el comportamiento real (base de datos de prueba, servicio levantado, archivo real) es la evidencia principal.
- Los mocks sirven para aislar lógica y para dependencias de pago o de terceros que no se pueden llamar. **Un resultado probado solo con mocks se declara así** (ver `honesty.md` §3); nunca cuenta como «funciona en producción».
- Se prefiere una dependencia real desechable (contenedor, base temporal, servidor HTTP local) a un mock de red.
- La cobertura de líneas es una señal, no un criterio de «listo»: 80 % de cobertura con mocks puede no probar nada.

## 3. Aislamiento (ver `test-isolation.md`)
Una prueba nunca toca datos reales ni hereda su destino del entorno de la aplicación.

## 4. Antes de cada commit
Corre las pruebas y los verificadores (y `python verifiers/run.py` si el proyecto usa resident-agent-os). Pega la salida real en la entrega.

## 5. Pruebas omitidas
Una prueba `skip` lleva un motivo escrito y un responsable; sin motivo es una prueba borrada en silencio.
