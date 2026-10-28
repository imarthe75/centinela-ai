# Aislamiento de pruebas

**Incidente real:** una prueba de caché heredó `VALKEY_HOST` del entorno de la aplicación y su `setUp` llamó a `flushdb()`: vació la base de producción.

1. **Destino explícito y exclusivo de prueba.** Las pruebas que escriben o borran leen su destino de variables dedicadas (`APP_TEST_DB_HOST`, `ROS_TEST_VALKEY_HOST`…) y **se niegan a correr** si faltan. Nunca caen en `DB_HOST`/`REDIS_URL` de la aplicación.
2. **Nada de operaciones globales.** Prohibido `flushdb`/`flushall`, `DROP`, `TRUNCATE` sobre una instancia compartida; borra solo lo que la prueba creó (prefijo único).
3. **Base desechable.** Persistencia → base de prueba dedicada, esquema temporal o transacción con `ROLLBACK` obligatorio.
4. **Datos ficticios no contaminan.** Nombres e IPs inventados nunca llegan a tablas de inventario o auditoría reales.
5. **El contenedor de la aplicación lleva variables de producción.** Ejecutar pruebas dentro de él (`docker exec`) hereda esas variables: usa un runner que levante su propia base y fije las variables de prueba.

