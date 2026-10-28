---
name: triage-findings
description: Método para cruzar varios insumos de seguridad (auditoría manual, análisis de segundo nivel, escáneres) y clasificar cada hallazgo como vulnerabilidad, falso positivo o riesgo aceptado, con evidencia.
---

# Triage de hallazgos de seguridad

**Cuándo aplicar:** cuando hay reportes que se repiten o se contradicen y hay que decidir qué corregir.

## Método
1. **Inventario.** Une todos los insumos en una sola lista; cada hallazgo conserva su fuente.
2. **Agrupa por causa, no por ocurrencia.** Un patrón repetido 300 veces es una decisión, no 300 tickets. Anota cuántas ocurrencias y en qué archivos.
3. **Clasifica cada grupo con evidencia** (abre el código, no confíes en el título):
   - **Vulnerabilidad** — el código es alcanzable y el impacto es real. Registra archivo y línea.
   - **Falso positivo** — el detector coincidió con algo inofensivo (texto, prueba, código muerto, valor controlado). Explica por qué en una frase y guarda el caso para ajustar el detector.
   - **Riesgo aceptado** — es real pero se decide no corregir; requiere responsable, motivo y fecha de revisión.
   - **No evaluado** — no se pudo comprobar. Nunca se reporta como «limpio».
4. **Severidad efectiva.** Conserva la severidad de la herramienta y anota la real si difiere, con la razón en la primera frase («Aunque se reporta como ALTA, el riesgo real es BAJO porque…»). La IA o la herramienta nunca sube la severidad por sí sola.
5. **Verifica por muestreo.** Revisa a mano una muestra de cada clase, sobre todo de los falsos positivos y de lo descartado.
6. **Salida.** Un informe con dictamen por grupo citado a archivo y sección, y una tabla (xlsx/csv) con una fila por ocurrencia: clasificación, evidencia, responsable.

## Reglas
- Lo descartado por una IA lo confirma una persona antes de suprimirse.
- Cada decisión humana se guarda con quién y cuándo; no se pisa en una segunda corrida.
- Ninguna cifra de «cumplimiento» o «resueltos» se publica sin las ocurrencias abiertas que la sustentan.
