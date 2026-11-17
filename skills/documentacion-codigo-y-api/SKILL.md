---
name: documentacion-codigo-y-api
description: Documentación obligatoria al escribir código — Javadoc/TSDoc/docstrings en la API pública, contrato OpenAPI/Swagger completo en cada endpoint (springdoc), COMMENT ON en la base de datos, README por módulo y ADR por decisión. Úsala al crear o modificar un endpoint, un servicio, un componente, una migración o un módulo.
---

# Documentación de código, API y base de datos

Regla: lo que se entrega sin documentar no está terminado. La documentación se escribe en el mismo cambio que el código (`clean-code-contract/references/documentation.md`).

## 1. Java / Spring Boot
```java
/**
 * Administra el catálogo de sedes.
 * <p>Una sede inactiva no puede recibir citas nuevas; inactivarla exige que no tenga citas futuras.</p>
 */
@Service
@RequiredArgsConstructor
public class SedeService {

    /**
     * Inactiva una sede.
     *
     * @param id identificador de la sede
     * @param rowVersion versión que vio el usuario (concurrencia optimista)
     * @return la sede actualizada
     * @throws GenericErrorException 404 si no existe; 409 si tiene citas futuras o la versión cambió
     */
    @Transactional
    public SedeResponse inactivar(UUID id, Integer rowVersion) { ... }
}
```

```java
@Tag(name = "Sedes", description = "Catálogo de sedes de atención")
@RestController
@RequestMapping("/sedes")
public class SedeController {

    @Operation(summary = "Inactivar sede", description = "Inactiva la sede si no tiene citas futuras.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Sede inactivada",
            content = @Content(schema = @Schema(implementation = SedeResponseEnvelopeDoc.class),
                examples = @ExampleObject(value = "{\"responseCode\":\"200\",\"responseMessage\":\"Actualización exitosa\",\"data\":{\"id\":\"0192f0c4-...\",\"activo\":false,\"rowVersion\":3},\"errorList\":[]}"))),
        @ApiResponse(responseCode = "403", description = "Sin permiso", content = @Content(schema = @Schema(implementation = ErrorEnvelopeDoc.class))),
        @ApiResponse(responseCode = "404", description = "No existe", content = @Content(schema = @Schema(implementation = ErrorEnvelopeDoc.class))),
        @ApiResponse(responseCode = "409", description = "Tiene citas futuras o la versión cambió", content = @Content(schema = @Schema(implementation = ErrorEnvelopeDoc.class)))
    })
    @PreAuthorize("hasAuthority('SEDES_EDITAR')")
    @PatchMapping("/{id}/inactivar")
    public ResponseEntity<ResponseDto<SedeResponse>> inactivar(@PathVariable UUID id, @Valid @RequestBody VersionRequest body) { ... }
}
```
- DTOs con `@Schema(description = ..., example = ...)` en cada campo.
- springdoc publica `/v3/api-docs`; el pipeline puede exportarlo y versionarlo. En producción: `springdoc.swagger-ui.enabled=false` o UI
  detrás de autenticación.
- Respuestas de error: un esquema propio (`ErrorEnvelopeDoc`) con `data = null` y `errorList`.

## 2. TypeScript / Angular
```ts
/**
 * Servicio del catálogo de sedes.
 * Todas las llamadas pasan por ApiService; los errores los muestra el interceptor global.
 */
@Injectable({ providedIn: 'root' })
export class SedeService {
  /**
   * Inactiva una sede.
   * @param id identificador de la sede
   * @param rowVersion versión mostrada al usuario
   * @returns la sede actualizada
   */
  inactivar(id: string, rowVersion: number): Observable<ResponseDto<Sede>> { ... }
}
```
- README del feature (`features/<modulo>/README.md`): propósito, pantallas, servicios, permisos que usa (skill `generacion-documentacion`).

## 3. Base de datos
```sql
COMMENT ON TABLE public.ct_sedes IS 'Catálogo de sedes de atención.';
COMMENT ON COLUMN public.ct_sedes.activo IS 'false: la sede no recibe citas nuevas.';
COMMENT ON CONSTRAINT uq_ct_sedes_nombre ON public.ct_sedes IS 'Nombre único entre sedes no borradas.';
```
Cada migración que crea o cambia un objeto lleva su `COMMENT ON`; el diccionario de datos se genera de ahí.

## 4. Proyecto
- `README.md` raíz: propósito, arquitectura breve, cómo levantar y probar, variables de entorno (solo nombres), enlaces al contrato OpenAPI.
- ADR (`DECISIONS/NNNN-titulo.md`): contexto, decisión, alternativas descartadas, consecuencias. Uno por decisión que cambie arquitectura,
  dependencia o estándar.
- Documentos redactados como versión vigente, con fecha y fuente en las cifras (skill `reglas-globales-org` §3).

## Checklist
- [ ] API pública con Javadoc/TSDoc (qué hace, parámetros, retorno, errores, regla de negocio).
- [ ] Cada endpoint: `@Operation` + `@ApiResponses` con ejemplos de éxito y de cada error; DTOs con `@Schema`.
- [ ] Migración con `COMMENT ON` de tabla, columnas y restricciones.
- [ ] README del módulo y ADR actualizados si aplica.

Detectores de Centinela relacionados: `API-NO-CONTRACT` (repositorio con rutas y sin contrato OpenAPI), `API-ENDPOINT-UNDOCUMENTED` (controlador con endpoints sin `@Operation`).

Corrección de cada regla y el resto del catálogo: skill `prevencion-hallazgos-seguridad-calidad`.
