# Verificaciones sobre los reportes de Centinela

## Formato del PDF desde oct-2026 (lo que `parse_centinela.py` v2 entiende)
- Encabezado del hallazgo: `SEVERIDAD [(HERRAMIENTA: SEV)] [· SIN RIESGO REAL] regla (N Ocurrencias) Motor: x`. La primera severidad es la **efectiva** de Centinela;
  `HERRAMIENTA` es la cruda del motor. Si dice «SIN RIESGO REAL», Centinela la cuenta como Informativa en el reporte general.
- `UBICACIÓN EN CÓDIGO (N ubicaciones en M archivo(s))`: N cuenta pares **archivo:línea**, M archivos. Ahora se listan **todas** (ya no 10), con la forma `📁 ruta  líneas 4, 36`.
  Cuando el PDF recorta dice «Se muestran 60 de 81 archivos afectados»: el parser lo deja en `truncado` y esas ocurrencias se clasifican solo por reglas genéricas.
- El PDF parte los encabezados y las rutas largas en varias líneas (`Motor: sast-` / `native`, `entity/` / `Archivo.java`). El parser trabaja sobre texto colapsado y reconstruye.
- **Cuadre automático:** cada PDF declara «Se encontraron N hallazgos»; el parser imprime `cuadre_con_encabezado=OK/ALERTA` por repositorio. Una ALERTA significa que se perdió o se
  duplicó un encabezado: no sigas hasta resolverla.
- El esfuerzo («Esfuerzo estimado: 1h») solo lo trae SonarQube y aparece una vez por regla; el plan lo aplica a cada ocurrencia de esa regla (supuesto declarado en el libro).
- Casos que rompieron versiones anteriores del parser: nombres de motor partidos alrededor de «(N Ocurrencias)» (`accessibility-` … `wcag`) y ubicaciones seguidas de un bloque «💡 SOLUCIÓN RECOMENDADA».
  Si un PDF nuevo trae otro formato, el cuadre contra el encabezado y `reglas_con_ubicaciones_incompletas` lo delatan: no lo ignores.
- Los PDF **no** traen: los informativos (solo el general), la lista real de subproyectos del grupo en GitLab, ni las ocurrencias recortadas. El libro lo dice en vez de suponerlo.

## Con acceso a Centinela (opcional)
Si hay acceso a la API (`/api/triage/report.xlsx?instance=&group=`, `/api/triage/matrix`, `/api/triage/summary`) no hace falta parsear PDF: devuelve lo mismo con todas las
ocurrencias, la lista de subproyectos contrastada con GitLab («Sin escanear» ≠ limpio) y los informativos. El catálogo de causas raíz vive en Centinela con autor y fecha.
Verificado en un proyecto real: el camino por PDF y el camino por API dan el mismo Resumen y el mismo plan, celda por celda.

## Cuadre de cifras
- Suma C/A/M/B por repositorio en el reporte general y compárala con la página 1 de cada PDF
  (tabla "Panorama por motor", incluida la fila de Contenedores/Trivy si existe).
- En un proyecto los PDF incluían en su total los "resueltos por SOAR" y el general no;
  la columna "Resueltos" del general no coincidía con la del PDF. Reportarlo si se repite.
- El Top 10 del general se calcula sobre abiertos; puede no coincidir con la suma de PDFs.
- Los informativos solo aparecen en el general: no son verificables.

## Defectos conocidos del reporte (buscarlos siempre)
- Ubicaciones truncadas: máximo 10 por regla y el texto "…y 5 ubicaciones adicionales"
  aunque falten más. Consecuencia: un (b) puede ser (a) no visible.
- Contradicciones: la misma línea marcada "SIN RIESGO REAL" en una regla y Alta en otra;
  texto de riesgo que no coincide con la evidencia (p. ej. "localhost" con host real).
- SCA sobre `package.json` en vez del lockfile ("versión instalada: 21"); hallazgos
  UNREACHABLE contados como Alta/Media. Agrupar por paquete: varias CVE se cierran con una
  sola actualización.
- Rutas no productivas escaneadas (`.agents/`, specs, demos de plantillas).
- Hallazgos de "claude-code-manual-review": no los detectó ninguna regla; cuentan como hueco.
- El total "vulnerabilidades reales" mezcla accesibilidad WCAG y `@Version` de JPA.

## Catálogo REGLAS_PROPIAS_CENTINELA
- Lista las reglas del reporte que no están en el catálogo (en un proyecto de referencia fueron 15 familias:
  JPA-ENTITY-MISSING-VERSION, FILE-UPLOAD-NO-VALIDATION, REDIS-JDK-SERIALIZATION,
  AUTH-ENDPOINT-NO-RATE-LIMIT, BLOCKING-THREAD-SLEEP, JPA-MULTI-WRITE-NO-TRANSACTIONAL,
  POTENTIAL-IDOR-NO-OWNERSHIP-CHECK, JWT-HARDCODED-SECRET-NO-OVERRIDE, GITLAB-PROJECT-*,
  CICD-NO-PIPELINE, SCA-CVE-*, WCAG-1.3.1-FORM-CONTROL-NO-LABEL,
  WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT, ACCESSIBILITY-WCAG-MISSING-LABEL).
- Severidades distintas entre catálogo y reporte (WCAG Baja vs Media) y reglas duplicadas
  (AUTHZ-CSRF-DISABLED Media vs SPRINGBOOT-CSRF-DISABLED Alta).
- Motores declarados que no aparecen en la tabla de motores del PDF (authz-dast, CIS,
  db-hardening, ITDR): sin evidencia de ejecución.

## Reglas que le faltaban a Centinela en un proyecto de referencia (ya implementadas; punto de partida para revisar nuevos sistemas)
1. Falso negativo de AUTHZ-ONLY-AUTHENTICATED-WRITE con `anyRequest().authenticated()` +
   `@EnableMethodSecurity`; detectar `@PreAuthorize` comentado.
2. GET con `permitAll` que expone usuarios, roles o PII.
3. Endpoints de prueba por nombre ("prueba", "test") o sin `@Profile`.
4. Secretos en `application*.properties/yml` y en historial git; secreto JWT literal.
5. Comparación de secretos en tiempo no constante.
6. Política de contraseñas en DTO; rate limiting fuera del login.
7. Auditoría de lecturas masivas; PII sin enmascarar.
8. Frontend: tokens en URL (EventSource, window.open), rutas de prueba, divulgación de stack.
9. SCA sobre lockfile con severidad por alcanzabilidad.
10. Exclusión de rutas no productivas.
