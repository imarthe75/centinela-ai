# Dieta de contexto

Todo lo que entra al contexto se vuelve a cobrar en cada turno siguiente. Leer menos ahorra más que escribir menos.

## Leer

- Buscar primero (grep del símbolo, lista del directorio) y luego leer solo el rango que hace falta. El archivo completo solo cuando el archivo completo es la tarea.
- No volver a leer un archivo que no cambió desde la última lectura.
- Leer siempre el fragmento que se va a editar: editar sin haberlo visto produce cambios contra texto inexistente.
- Acotar en el origen: `git log --oneline -10`, `ls <dir>`, `| tail -50`, filtros de la propia herramienta (`--quiet`, `-q`, `--format`).

## Comandos largos

- De compilaciones, instalaciones y pruebas interesan los fallos y el resumen final. Pedirlos así cuando la herramienta lo permite (`pytest -q`, `mvn -q`, `npm ci --silent`).
- **Excepción obligatoria:** la evidencia que exigen `rules/common/testing.md` y `rules/common/honesty.md` (salida real de las pruebas en el informe) se conserva completa en un archivo de log; el contexto solo necesita el resumen y los fallos.
- Si el entorno del proyecto tiene un hook que recorta salidas largas, debe conservar las líneas de error y el resumen de pruebas, y guardar el original completo; nunca debe actuar sobre la lectura o edición de archivos.

## Razonar

- El razonamiento oculto también se cobra. No reescribir la petición, no redactar la respuesta dos veces, no repasar estas reglas en voz baja.
- Si falta un dato menor (versión, librería por defecto), elegir la opción más común, nombrarla en una línea y seguir. Las preguntas al usuario son para decisiones que de verdad le corresponden.

## Responder

- La respuesta va primero; nada de preámbulos ni resúmenes de lo que ya se dijo.
- Estructura (títulos, tablas, viñetas) solo cuando la respuesta la necesita.
- Se escribe completo, sin abreviar, cuando hay advertencias de seguridad, acciones irreversibles, pasos en orden estricto o algo que la brevedad volvería ambiguo.
- Código, comandos, rutas y mensajes de error se citan exactos.
- Esta brevedad aplica a las respuestas en la conversación. Los entregables (documentos, reportes, mensajes de commit, descripciones de MR) siguen sus propias reglas de audiencia.

*Ideas tomadas de Chisle (JayPokale, MIT) y Caveman (Julius Brussee, Apache-2.0). Texto propio; no se usa el nombre ni el estilo de marca de ninguno.*
