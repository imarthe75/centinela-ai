# Estándar de auditoría — instalador único e inteligente

**Archivo:** `auditoria_estandar_completo.sql`. Un solo script que **diagnostica la base antes de cambiar nada** y elige la acción: instalar de cero, no hacer nada, reparar, actualizar una versión anterior o negarse si la auditoría existente es de otro origen. Todo va en una transacción: o termina completo o no cambia nada.

## Requisitos

- **PostgreSQL 18 o superior** (versión mínima soportada; incluye `uuidv7()`). El script lo verifica y se detiene si es menor.
- Cliente `psql` 13 o superior (usa `\if` y `\gset`); se recomienda el de la versión 18.
- Superusuario (los event triggers lo exigen).
- Roles: `migrator` (dueño del esquema), `auditor`, `role_dev_dml` y `app_web_user`. Los que falten se crean **sin LOGIN**: asígnales LOGIN y contraseña. Si tu proyecto usa otros nombres, reemplázalos en todo el archivo antes de ejecutarlo.

## Uso

```bash
psql -d <base> -v ON_ERROR_STOP=1 -f auditoria_estandar_completo.sql
```

| Opción | Efecto |
|---|---|
| `-v solo_diagnostico=si` | Muestra el diagnóstico y la acción que tomaría, sin cambiar nada. **Úsalo primero en bases con auditoría previa.** |
| `-v ajena=renombrar` | Si la auditoría existente es de otro origen, la conserva renombrándola (`auditoria_previa_<fecha>`) e instala el estándar de cero. Por defecto el script se detiene. |

## Qué decide el script

Compara la base con la huella de esta versión (estructura de la bitácora, las 23 funciones, los 3 event triggers, el esquema de control y el dueño).

| Diagnóstico | Qué encontró | Qué hace |
|---|---|---|
| **nueva** | No hay auditoría. | Instala todo. |
| **vigente** | Esta versión, completa y sin cambios. | No cambia nada. |
| **reparar** | Esta versión con piezas faltantes o modificadas (funciones, event triggers, control, dueño del esquema). | Restituye las piezas. No toca los datos de la bitácora. |
| **anterior** | Una versión previa del mismo estándar: bitácora sin particionar, sin columnas de contexto, con tipos antiguos, o instalación incompleta. | La actualiza conservando todos los registros. Si el número de registros no coincide al terminar, revierte todo. |
| **ajena** | Otra auditoría: bitácora con otra estructura, objetos desconocidos en el esquema `auditoria`, o event triggers de otro origen con los mismos nombres. | Se detiene sin cambiar nada y explica qué encontró. Con `-v ajena=renombrar` conserva lo ajeno y continúa. |

Si el esquema es del estándar pero tiene tablas o funciones adicionales de otros, las conserva y las informa. Las funciones se reemplazan en su lugar, así que los triggers `audit_biu` / `audit_aiud` que ya existen en las tablas de negocio pasan a usar el código nuevo sin volver a crearlos.

## Qué incluye

- **Bitácora `auditoria.log_auditoria`:** solo inserción, particionada por mes, con hash SHA‑256 encadenado y contexto de sesión. Rechaza UPDATE, DELETE y TRUNCATE, incluso al dueño.
- **Triggers por tabla:** `audit_biu` (habilitado), y `audit_aiud` y `audit_truncate` (deshabilitados hasta habilitarlos por tabla).
- **Utilidades:** `habilitar_auditoria`, `deshabilitar_auditoria`, `asignar_triggers`, `bloqueo_optimista`, `reporte_cobertura`, `fn_verificar_cadena`, `fn_reconciliar_tabla`, `fn_crear_particiones`, `fn_monitorear_slots`.
- **Event triggers:** `et_grant_on_create`, `et_auditoria_ddl` y `et_auditoria_drop`.
- **Esquema `auditoria_control`** (dueño `postgres`): ancla de solo inserción y `fn_verificar_y_anclar()`.

## Uso diario

```sql
SELECT auditoria.habilitar_auditoria('<esquema>.<tabla>');   -- lo ejecuta el dueño de la tabla
SELECT * FROM auditoria.reporte_cobertura();
SELECT * FROM auditoria.fn_verificar_cadena();               -- sin filas = cadena íntegra
SELECT auditoria_control.fn_verificar_y_anclar();            -- verificación y ancla (diaria con pg_cron)
```

- Las tablas creadas por `migrator` reciben `audit_biu` automáticamente; las de otro usuario necesitan `auditoria.asignar_triggers('<esquema>.<tabla>')`.
- Con PgBouncer en modo transacción: `SELECT set_config('app.current_user', '<usuario>', true);` dentro de cada transacción.
- Verificación diaria con pg_cron (en la base `postgres`): `SELECT cron.schedule_in_database('auditoria_verificar_<base>', '30 2 * * *', 'SELECT auditoria_control.fn_verificar_y_anclar()', '<base>');`

## Qué se verificó (2026-10-14, PostgreSQL 18.4)

- **Nueva:** instalación completa y segunda ejecución → «vigente», sin cambiar ningún objeto.
- **Reparar:** con una función borrada, dos modificadas, un event trigger faltante y el dueño del esquema cambiado, las restituyó. Los registros de la bitácora y la cadena quedaron intactos, y la ejecución siguiente dio «vigente».
- **Anterior (v2.1 con datos):** conservó los 5 registros con sus hashes originales, particionó la bitácora y la cadena siguió íntegra mezclando fórmulas. La base quedó idéntica a una instalación nueva (funciones, columnas, índices, triggers, event triggers, dueños y permisos), y los registros nuevos usan la fórmula vigente.
- **Anterior (muy antigua):** tipos `char` y `timestamp` sin zona y dueño distinto: convirtió los tipos y conservó sus 7 registros en la partición de su fecha.
- **Instalación incompleta:** con 2 funciones sueltas y sin bitácora, la completó y recreó una función cuyo tipo de retorno había cambiado.
- **Ajena (tres casos):** bitácora con otra estructura, objetos de otra herramienta y event trigger de otro origen con el mismo nombre. Por defecto se detuvo sin cambiar nada (código de salida 3). Con `ajena=renombrar` conservó lo ajeno (los 3 registros siguieron en el esquema renombrado) e instaló el estándar.
- **Otros:** `solo_diagnostico=si` no creó nada; una opción inválida se rechaza; el control de versión mínima se comprobó forzando un umbral inexistente y no creó objetos.
- **Funcional:** `app_web_user` hizo INSERT, UPDATE y DELETE y quedaron registrados con su usuario. La cadena fue íntegra, el ancla se registró, y la bitácora rechazó UPDATE, DELETE y TRUNCATE al dueño. `auditor` la lee y `role_dev_dml` no.

## Límites y avisos

- **No se probó** en otro cluster real, en versiones anteriores a PostgreSQL 18, sin los roles `migrator` o `auditor` en el destino, con el job de `pg_cron` ni con una bitácora grande (la actualización copia todos los registros con la tabla bloqueada; planifícalo en una ventana).
- Si la bitácora anterior no tenía hash (versiones muy antiguas), `fn_verificar_cadena()` marcará esos registros: el script avisa con un `WARNING` y no los modifica.
- Con `ajena=renombrar`, las tablas de negocio que tuvieran triggers de la auditoría ajena **siguen escribiendo en el esquema renombrado**: hay que migrarlas al estándar nuevo con `auditoria.asignar_triggers(...)`. No se probó ese caso.
- El instalador desactiva los event triggers **dentro de su transacción** (parámetro `event_triggers`, disponible desde PostgreSQL 17) para no disparar los de permisos ni de registro de DDL mientras trabaja. Los del estándar se recrean al final.
- Instalado solo, `auditoria` otorga `USAGE` a `role_dev_dml`, `app_web_user` y `auditor`; el dueño de la bitácora (`migrator`) puede hacer INSERT directo (no UPDATE ni DELETE), y un registro falso rompería la cadena, que `fn_verificar_y_anclar()` detecta.
