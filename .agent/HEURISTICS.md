# 🧠 Heurística Cognitiva y Aplicada en Software (HEURISTICS.md)

Este documento define las directrices heurísticas tanto para el comportamiento del agente de IA como para el diseño y lógica de las aplicaciones construidas a partir de este framework. El sustento teórico de estas reglas se basa en los **10 Principios Heurísticos de Usabilidad e Interacción de Jakob Nielsen (1994)** y la **Teoría de la Carga Mental de John Sweller**.

Para un desglose detallado de su implementación científica e impacto en la suite del ecosistema, consulta la [Guía Maestra de Heurísticas](file:///home/ia/ecosistema-casmarts/resident-agent-framework/HEURISTICAS_MASTER_GUIDE.md).

---

## 🛠️ 1. Heurística Aplicada en el Código y Software (Mandato de Diseño)

Todo desarrollo generado a partir de este framework debe incorporar de forma obligatoria o como sugerencia de alta prioridad **lógica heurística** en el código de la aplicación:

- **10 Heurísticas de Usabilidad de Nielsen:** El frontend y la UX del sistema deben priorizar la visibilidad del estado del sistema, consistencia de diseño (estilo Cívika), prevención de errores, y reconocimiento antes que recuerdo (mostrar previsualización de documentos al lado de metadatos extraídos).
- **Algoritmos Heurísticos en Lógica de Negocio:** En lugar de depender exclusivamente de condicionales estáticas o modelos pesados de IA, implementa heurísticas rápidas (reglas de puntuación, filtrado conceptual, proximidad semántica) para optimizar la toma de decisiones interna del software.
- **Estrategias de Fallback (Graceful Degradation):** Si una base de datos o API externa falla, el sistema debe aplicar heurísticas de contingencia locales (ej. usar datos previamente cacheados en Valkey o aproximaciones semánticas locales) para asegurar la continuidad del servicio.

---

## 🔄 2. Heurística de Autocorrección (Loop Prevention)
El agente de IA debe aplicar control cognitivo para evitar bucles repetitivos de corrección de código:
- **Límite de Intentos:** Si una corrección de código (linter o test unitario) falla más de **3 veces consecutivas**, la IA debe detenerse inmediatamente.
- **Higiene de Errores:** En lugar de reintentar el mismo cambio, debe extraer el log de error completo, compararlo semánticamente contra las lecciones aprendidas en `memory.lessons` (PostgreSQL) y replantear el enfoque de diseño.

---

## 📉 3. Heurística de Ahorro y Degradación de Contexto (Context Saving)
Para evitar la degradación del razonamiento del modelo por saturación de contexto:
- **Summarization Proactiva:** Al interactuar con el sistema de archivos, la IA debe resumir el contenido en lugar de leer archivos masivos.
- **Búsqueda Semántica Eficiente:** Usar el `SemanticCache` de Valkey como filtro de entrada principal para interceptar consultas redundantes e idénticas en menos de 5ms.

---

## 🏛️ 4. Criterios de IA para la Creación de ADRs
La IA debe registrar de forma autónoma una decisión arquitectónica en `DECISIONS/` cuando:
1. Se introduzcan nuevas dependencias o librerías al arnés (`requirements.txt`).
2. Se altere la configuración de puertos o mapeo de volúmenes de datos locales en `docker-compose.yml`.
3. Se modifique una ley o regla fundamental de `.agent/AGENT.md` o `.agent/RULES.md`.
