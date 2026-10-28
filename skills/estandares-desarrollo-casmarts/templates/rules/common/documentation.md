# Documentación obligatoria

Código, API y base de datos sin documentar no se entregan. La documentación vive junto al código y se actualiza en el mismo cambio.

## 1. Código
- **Toda API pública** (clase, método público de servicio/controlador, función exportada, componente) lleva su comentario de documentación:
  Javadoc en Java, TSDoc/JSDoc en TypeScript, docstring en Python. Dice **qué hace, qué recibe, qué devuelve, qué errores lanza** y
  cualquier regla de negocio no evidente.
- Los comentarios explican el **por qué** (decisión, restricción, incidente), no repiten el qué del código.
- Sin código comentado «por si acaso»: se borra; el historial de git lo conserva.

## 2. API (OpenAPI / Swagger)
- **Toda API HTTP publica su contrato OpenAPI** (springdoc en Spring Boot, `@nestjs/swagger`, FastAPI…).
- **Cada endpoint** lleva resumen, descripción, parámetros, cuerpo y **todas sus respuestas** (2xx, 400, 401, 403, 404, 409, 500) con un
  ejemplo realista; la respuesta de error documenta su estructura.
- El contrato se versiona o se publica en el pipeline; un cambio incompatible sube la versión de la API.
- En producción la interfaz Swagger UI se deshabilita o queda detrás de autenticación; el contrato sigue disponible para los consumidores.

## 3. Base de datos
- Cada tabla, columna, restricción y función lleva `COMMENT ON` en la migración que la crea o la cambia.
- El diccionario de datos se genera a partir de esos comentarios; no se escribe a mano por separado.

## 4. Proyecto y módulos
- `README.md` en la raíz (qué es, cómo se levanta, cómo se prueba, variables de entorno **sin valores**) y uno por módulo o feature
  con su propósito, dependencias y decisiones locales.
- Cada decisión técnica que cambia la arquitectura, una dependencia o un estándar queda en un ADR (`DECISIONS/NNNN-*.md`).
- Mensajes de commit que dicen qué cambió y por qué, con referencia al requisito o ticket.

## 5. Estilo
Los documentos se redactan como versión vigente (no como historial de cambios), con fechas y fuentes en las cifras. Ver `honesty.md` y la
skill `reglas-globales-org`.
