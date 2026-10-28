# Reglas Java / Spring Boot — cómo escribir el código para no generar el hallazgo

Cada regla dice qué evitar, por qué importa y la forma correcta. Son criterios de revisión de uso común (JPA/Spring), no una política de una organización.

1. **Carga perezosa por defecto.** No declares `FetchType.EAGER` en relaciones. Una colección `EAGER` trae sus filas siempre, aunque la consulta no las use.
   Usa `LAZY` y trae lo necesario con `JOIN FETCH` o `@EntityGraph` en la consulta que lo requiere.
2. **Nada de `findAll()` sin paginar.** En controladores y servicios usa `Pageable`. Un `findAll()` seguido de un filtro en memoria carga la tabla completa.
3. **Sin consultas dentro de bucles (N+1).** Un `repository.findX(...)` dentro de un `for`/`forEach` ejecuta una consulta por elemento.
   Cambia a una consulta por lote (`findAllById`, `IN`, `JOIN FETCH`) fuera del bucle.
4. **Valida la entrada.** Todo `@RequestBody` lleva `@Valid`/`@Validated` y el DTO declara sus restricciones (`@NotNull`, `@Size`, `@Pattern`).
5. **Devuelve DTOs, no entidades.** Una entidad JPA en la respuesta expone columnas internas y dispara cargas perezosas durante la serialización.
6. **Capas.** El controlador llama a un servicio; el servicio al repositorio. Un controlador que inyecta un repositorio salta la lógica de negocio y las transacciones.
7. **Escrituras múltiples en una transacción.** Un método con dos o más `save`/`delete` va con `@Transactional` (en el método o en la clase) para que sea todo o nada.
8. **Concurrencia optimista.** Las entidades que varios usuarios editan llevan `@Version`; sin ella, la última escritura pisa a la anterior sin aviso.
9. **Autorización por método.** Si el proyecto usa seguridad por método, cada endpoint que muta datos lleva su `@PreAuthorize`; un permiso comentado equivale a no tenerlo.
10. **Errores.** No devuelvas `e.printStackTrace()` ni trazas al cliente; registra con el logger y responde con un mensaje de error controlado.
11. **Secretos.** Ningún secreto literal en `application*.properties|yml`; usa variables de entorno o un gestor de secretos.
12. **Subida de archivos.** Valida tamaño, tipo real (no solo la extensión) y nombre antes de guardar.
13. **OpenAPI en cada endpoint.** `@Tag` en el controlador y `@Operation` + `@ApiResponses` (con ejemplos de 2xx y de error) en cada
    método; el proyecto publica su contrato con springdoc. Un endpoint sin documentar no se fusiona (`documentation.md` §2).
14. **Javadoc** en clases y métodos públicos de servicios y controladores: qué hace, parámetros, retorno, excepciones y regla de negocio.
15. **`@PreAuthorize` en todos los endpoints** (no solo los que mutan) cuando el proyecto usa seguridad por método; lo público se declara
    explícitamente y con motivo. El servicio valida además la propiedad del recurso cuando el id viene del cliente.
16. **Esquema solo por migraciones.** `spring.jpa.hibernate.ddl-auto=none` (o `validate`); `spring.jpa.open-in-view=false`.
17. **Autenticación delegada.** OAuth2 Resource Server contra el proveedor OIDC (issuer/JWKS por variable); sin filtros JWT propios ni
    secretos de firma en la aplicación.
18. **Errores sin fuga.** El manejador global responde 401/403/404/409/500 con mensaje controlado; nunca `e.getMessage()` ni trazas al
    cliente (`server.error.include-*=never`). Sin `@Autowired` en campos; `@Transactional` solo en servicios.
