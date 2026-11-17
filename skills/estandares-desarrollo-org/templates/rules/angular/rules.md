# Reglas Angular — cómo escribir el código para no generar el hallazgo

Criterios de revisión de uso común (RxJS/señales/PrimeNG), no una política de una organización.

1. **Sin `subscribe` anidado.** Un `subscribe` dentro de otro crea fugas y orden impredecible. Usa `switchMap`/`concatMap`/`forkJoin`.
2. **Cierra las suscripciones de larga vida.** `valueChanges`, `interval`, WebSockets y similares: `takeUntilDestroyed()`, el pipe `async` o `ngOnDestroy`.
   Las llamadas HTTP de una sola emisión se completan solas.
3. **`debounceTime` en búsquedas.** Un `valueChanges` que consulta al backend sin `debounceTime` + `distinctUntilChanged` lanza una petición por tecla.
4. **No hagas HTTP dentro de `effect()`** ni un `effect()` que lea y escriba la misma señal (bucle). Usa `computed`, `toSignal` o un método explícito.
5. **No mutes la señal en sitio.** `signal.update(a => [...a, x])`, no `a.push(x)`.
6. **Una sola carga inicial.** No llames al mismo método en `ngOnInit` y en un `effect`; con tablas PrimeNG `(onLazyLoad)` no cargues además en `ngOnInit`.
7. **Sin métodos con argumentos en plantillas** (`*ngFor="let x of getItems(a)"`): se ejecutan en cada ciclo de detección. Calcula antes (`computed`) o usa `async`.
8. **No hagas una petición HTTP por elemento de una lista**; pide el lote.
9. **Evita los parches de ciclo de detección** (`setTimeout` para "arreglar" un error de valor cambiado): corrige el origen del cambio.
10. **Botones que guardan o eliminan** se deshabilitan (`[disabled]`/`[loading]`) mientras la operación está en curso, y las eliminaciones piden confirmación.
11. **Tipado.** Evita `any`; define interfaces para las respuestas del backend.
12. **No guardes tokens ni datos sensibles en `localStorage`/`sessionStorage`** ni en la URL; un token en la URL queda en historiales y registros.
13. **Autenticación OIDC por ambiente.** Authorization Code + PKCE; `requireHttps` y `strictDiscoveryDocumentValidation` en `true` fuera
    del ambiente local; el token lo administra la librería OIDC, ningún componente lo lee del storage.
14. **TSDoc** en servicios, componentes de página y utilidades exportadas: qué hacen, entradas y salidas.
15. **URLs desde configuración.** Servicios con `environment` + constantes de endpoints; nunca `http(s)://` escrito en un servicio.
16. **Accesibilidad.** Cada control con etiqueta asociada (`for`/`inputId` o `aria-label`), botones de icono con nombre accesible,
    `autocomplete` en datos personales, ids únicos, foco visible (`common/accessibility.md`).
