# Escalera de eficiencia

Antes de escribir código nuevo, el agente recorre estos peldaños en orden y se detiene en el primero que resuelve el problema.
La escalera se aplica **después** de entender el problema, nunca en su lugar: en un bug, primero la causa raíz.

| Peldaño | Pregunta | Si aplica |
|---------|----------|-----------|
| **1. Necesidad** | ¿Hace falta este código? | No escribirlo; decirlo en una línea |
| **2. Ya existe** | ¿El proyecto ya tiene algo que lo hace? (buscar antes de escribir) | Reutilizarlo; si casi sirve, extenderlo en su sitio |
| **3. Biblioteca estándar** | ¿Lo resuelve la librería estándar del lenguaje? | Usarla |
| **4. Capacidad nativa** | ¿Lo resuelve el framework, la base de datos o la plataforma? (restricción de BD en vez de validación en código, CSS en vez de JS, `<input type>` en vez de un control propio) | Configurar en lugar de programar |
| **5. Dependencia ya instalada** | ¿Una librería que ya está en el proyecto lo hace? | Usarla; no agregar una dependencia para unas pocas líneas |
| **6. Solución mínima** | ¿Cabe en pocas líneas sin abstracciones? | Escribirlo directo, sin clases ni utilidades nuevas |
| **7. Implementación propia** | Nada de lo anterior aplica | Implementar lo mínimo que funcione y decir por qué |

## Antes de escribir: el alcance

Leer la tarea y el código que toca, y anotar cada lugar al que el cambio debe llegar: quién llama a lo que se modifica, pruebas, datos de prueba, configuración, exportaciones. Revisar también qué podría romper para los usuarios: datos que destruiría o expondría, llamadas que dejarían de funcionar. Eso es el alcance; las funciones extra no lo son.

## Mínimo en la solución, completo en el cambio

- La solución es la más pequeña que funciona; el cambio se termina entero, incluidas las llamadas, pruebas y datos de prueba que rompe.
- Entre dos opciones del mismo tamaño, la que es correcta en los casos límite.
- Una línea que hay que descifrar no es corta: el diff más corto gana solo si se lee de un vistazo.
- Respetar la estructura que ya tiene el código (capas, interfaces, convenciones); no reorganizar de paso.
- Código que se mueve o se une conserva su manejo de errores y su validación.
- En un bug, buscar antes todas las llamadas a la función y corregir la causa una sola vez en el código compartido.
- **Lógica nueva sin su comprobación está inconclusa:** una rama, un ciclo, un parser, cálculo de dinero o de seguridad, o un script nuevo dejan al menos una prueba pequeña. Un cambio trivial no la necesita.

## Lo que nunca se omite

La escalera reduce código innecesario, no protecciones. Nunca justifica quitar:

- validación de entradas en los límites de confianza (API, formularios, archivos, mensajes de otros sistemas);
- manejo de errores que evita pérdida o corrupción de datos;
- controles de seguridad (autorización, cifrado, manejo de secretos) y de accesibilidad;
- documentación obligatoria (`rules/common/documentation.md`) ni pruebas exigidas (`rules/common/testing.md`);
- cualquier cosa que el requerimiento pida explícitamente. Si el usuario insiste en la versión completa, se construye sin volver a discutirlo.

## Al salir de la escalera

La respuesta termina con una o dos líneas: qué se omitió o no se comprobó, y el riesgo que el usuario debe conocer.

Un atajo con un límite conocido se marca en el código con el formato `shortcut: <el límite>, <cuándo mejorarlo>` para rastrearlo con `git grep -nE '(#|//|/[*]|--) ?(shortcut|ponytail):'` (el marcador antiguo `ponytail:` también se reconoce). Un atajo sin condición de mejora es el que se queda para siempre:

```python
# shortcut: lista en memoria, hasta ~10k registros; pasar a consulta paginada si crece
```

```typescript
// shortcut: solo valida formato de RFC, no dígito verificador; agregarlo antes de facturar
```

## Señales de sobre-construcción

Una abstracción con una sola implementación, una opción de configuración que nunca cambia, código "para después" sin quien lo llame, una utilidad que reimplementa la biblioteca estándar, una dependencia nueva para lo que ya hace otra instalada. El revisor de código (`agents/code-reviewer.md`) las busca en cada diff.

## Beneficio esperado

Menos código significa menos que revisar, probar y mantener, y menos superficie de ataque. Este proyecto **no ha medido** cuánto ahorra la escalera; no se citan porcentajes hasta medirlo con un método reproducible (pruebas calificadas automáticamente, sin un modelo juez, publicando también los casos en que pierde).

## Integración con el límite de intentos

Se aplica antes del límite de 3 intentos (ver `systematic-debugging`). Si un intento usa un peldaño equivocado, el siguiente sube de peldaño antes de detenerse.

*Ideas del proyecto Ponytail (DietrichGebert, MIT: escalera, alcance, marcador `shortcut:`) y de Chisle (JayPokale, MIT). Texto propio.*
