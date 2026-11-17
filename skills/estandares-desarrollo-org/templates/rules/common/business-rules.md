# Reglas de negocio y metodología the organization en el trabajo del agente

## Reglas de negocio de los módulos CORE/Starter
Fuente: skill `reglas-negocio-core-starter` (catálogo RN-xx-yyy, 165 reglas de 15 módulos). Aplica al tocar usuarios, roles, privilegios,
menús, geográficos, oficinas, catálogos dinámicos, variables, manuales, folios, bitácora, auditorías, citas o correos.
- Lee el módulo del catálogo **antes** de cambiarlo; cita el `RN` en el commit o MR cuando el cambio implementa o modifica una regla.
- Solo las reglas **Explícitas** son requisito. Una **Inferida** o **Propuesta** se implementa cuando el dueño funcional la confirma; si no,
  queda como pendiente declarado (en ART-F2-08, `por_confirmar`). No conviertas una propuesta en requisito ni inventes la longitud, el
  catálogo o el patrón que el catálogo deja «por definir».
- Cada regla vive en el servidor (DTO con `@Valid`, autorización con `@PreAuthorize`, `UNIQUE` en la base) y además en la interfaz; validar
  solo en el cliente no cuenta.
- Códigos inmutables tras el alta no se aceptan en el DTO de edición; CP y claves geográficas son texto; bitácora y auditoría son de solo
  agregar; contraseñas de al menos 10 caracteres con mayúscula, número y símbolo; la recuperación de contraseña no revela si la cuenta existe.
- Centinela detecta en código una parte (ver la tabla de la skill); el resto se prueba ejecutando la aplicación. «0 hallazgos» no prueba que
  el módulo cumpla el catálogo.

## Metodología the organization (Manual v3.7)
Cómo se trabaja cada etapa y cada ticket: skill `metodologia-ca` (resumen operativo + texto del manual y de las guías de Análisis, Diseño
Funcional y Pruebas).
- **Soporte:** «¿the organization cambia el sistema?» decide el tipo del ticket. En una **atención sin cambio** (consulta, diagnóstico, asesoría,
  capacitación, documentación) el agente no toca código, configuración, datos ni despliegue; si hace falta un cambio, se abre un incidente
  ligado. Un cambio **mediano** (requiere una decisión de diseño) lleva mini-diseño ART-SOP-04 con evidencia de pruebas del componente y VoBo
  del especialista de BD si toca el esquema; uno **grande** (arquitectura o funcionalidad nueva) sale a la Etapa 1 (ART-SOP-06).
- **Pruebas:** cada caso con el usuario de su actor, nunca con un administrador; una corrección fallida reabre el mismo defecto; sin acuerdo
  firmado que lo respalde, un hallazgo es observación, no defecto.
- **Código del cliente y herramientas de IA:** si el registro de tailoring del proyecto (0A-2b) dice que el contrato **prohíbe** cargar a
  herramientas de IA el código que the organization entrega (`codigo_cliente = lo_prohibe`), el agente no lee, pega ni envía ese código a un modelo; se
  detiene y lo informa. Si no hay 0A-2b o no lo dice, se pregunta al LP; no se deduce.
- **Contenido propuesto por IA** en un artefacto lleva la marca visible «Revisó (the organization) / Fecha» para que una persona lo valide; la IA nunca
  llena firmas, fechas de sesión, decisiones, montos ni campos `humano-declarado`.
- **Entregables:** se generan solo con `generador-entregables-ca` (`payload.json` validado contra su esquema → `render.js` → `.docx`); nunca
  un `.docx` hecho a mano o con otra librería. Si no se puede ejecutar `render.js`, se entrega el payload validado y se declara que el
  documento no se generó.
- **Cierre de etapa:** se verifica con el checklist 0A-4 (ART-MC-02). Lo que Centinela aporta (`/api/checklist-evidence/{activo}`) es
  evidencia de los puntos 3.10, 3.7 y 5.8, no una firma.
- **Códigos de artefacto:** ART-F3-08 está retirado (se usa ART-MC-02); ART-SOP-07 = ART-F5-01 y ART-SOP-08 = ART-F5-03. No se reutiliza un
  número retirado.
