# 🌌 Guía Maestra de Heurísticas en el Ecosistema del Agente Residente

Este documento define las bases teóricas, la justificación científica y la guía práctica para aplicar **heurísticas cognitivas y de interacción** en el Agente Residente y en todas las aplicaciones de software que se construyan a partir de este framework (como la familia de productos `smart`).

---

## 📚 1. Sustento Científico y Metodológico

La incorporación de heurísticas en el desarrollo de software y en los arneses de IA se fundamenta en dos teorías científicas principales:

### A. Teoría de la Carga Mental (Cognitive Load Theory) - John Sweller
El cerebro humano (y de manera análoga, la ventana de contexto de un LLM) tiene límites estrictos de memoria de trabajo. El diseño de software debe orientarse a **minimizar la carga cognitiva superflua** (el esfuerzo de entender una interfaz o depurar un error redundante) para liberar capacidad mental para la **carga relevante** (resolver el problema de negocio).

### B. Los 10 Principios de Usabilidad e Interacción - Jakob Nielsen (1994)
Es el marco estándar de oro de la Interacción Hombre-Máquina (HCI). Al cumplir estas heurísticas, se garantiza que el software sea predecible, intuitivo y libre de fricciones operativas.

---

## 🛠️ 2. Las 10 Heurísticas de Nielsen Aplicadas al Desarrollo Smart

En la suite de proyectos (como `consulta-smart` e `idp-smart`), la IA y los desarrolladores deben implementar estas heurísticas de forma obligatoria:

| # | Heurística Nielsen | Aplicación en el Código / UI | Justificación y Beneficio |
|---|---|---|---|
| **1** | **Visibilidad del Estado** | Indicadores de carga, loaders dinámicos y estados de progreso (ej. procesando PDFs con Docling). | Evita la incertidumbre del usuario. |
| **2** | **Relación con el Mundo Real** | Metáforas de archivadores físicos, expedientes e índices familiares para el analista legal. | Reduce la curva de aprendizaje. |
| **3** | **Control y Libertad** | Botones de cancelar, deshacer cargas y flujos de edición libres. | El usuario siente seguridad al interactuar. |
| **4** | **Consistencia y Estándares** | Uso del sistema de diseño Cívika (colores de severidad y tipografía Outfit/Inter). | Evita la confusión y unifica la experiencia. |
| **5** | **Prevención de Errores** | Validación de tipos de archivos permitidos y deshabilitación dinámica de botones inválidos. | Evita fallas antes de enviar peticiones a la DB/API. |
| **6** | **Reconocimiento vs Recuerdo** | Vista previa de PDF paralela a los metadatos extraídos por la IA en la misma pantalla. | Minimiza la carga de memoria a corto plazo del usuario. |
| **7** | **Flexibilidad y Eficiencia** | Shortcuts de teclado y opciones de autocompletado para usuarios expertos. | Incrementa la velocidad operativa (menor MTTR). |
| **8** | **Diseño Minimalista** | Dashboards limpios con widgets enfocados y exclusión de ruido visual. | Maximiza la legibilidad del contenido crítico. |
| **9** | **Recuperación de Errores** | Mensajes de error amigables e indicaciones explícitas de cómo corregirlos. | El usuario sabe exactamente qué falló y cómo solucionarlo. |
| **10**| **Ayuda y Documentación** | Tooltips y guías integradas en el flujo de trabajo. | Ayuda contextual enfocada en la tarea inmediata. |

---

## 🧠 3. Heurística de Autocorrección del Agente (ECC Harness)

Para evitar la degradación del razonamiento de la IA del Agente Residente, el arnés de desarrollo incorpora las siguientes directrices heurísticas:
- **Heurística de Loop Limit:** El agente tiene un límite máximo de **3 intentos** para corregir el código. Si falla, el arnés detiene la ejecución para prevenir loops de tokens e investiga el log de errores comparándolo con lecciones previas en PostgreSQL (`pgvector`).
- **Semantic Caching:** Buscar consultas similares en Valkey antes de ejecutar requests al LLM para optimizar los tiempos de respuesta y ahorrar recursos del host.
