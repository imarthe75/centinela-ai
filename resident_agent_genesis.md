# 🌌 The Resident Agent Genesis: Master Edition (Abril 2026)
Este documento es el Manual Maestro de Operaciones. Su objetivo es transformar al Agente en un Operador Residente con memoria persistente y capacidad de ejecución autónoma bajo un Entorno Autorregulado. 

*Nota de Atribución: Este framework incorpora y adapta las mejores prácticas, ideas de diseño de subagentes, estructuras de hooks y arnés de optimización del proyecto de código abierto **affaan-m/ECC** (bajo Licencia MIT).*

🛠️ FASE 1: El Prompt Semilla (Inicialización y OS Cognitivo)
"Actúa como Principal AI Solutions Architect. Tu primera misión es construir tu propio Sistema Cognitivo antes de escribir código. Implementa la estructura bajo `.agent/` siguiendo estos pilares:
1. Memoria Estática (.agent/): AGENT.md (Reglas), CONTEXT.md (Propósito), MAP.md (Arquitectura técnica), HEURISTICS.md (Heurísticas Cognitivas y Aplicadas), SPECS.md (OpenSpec Layer) y SYSTEM_PROMPT.md (Instrucciones de Agente Residente v3).
2. Historial de Decisiones: Carpeta DECISIONS/ para ADRs numerados.
3. Persistencia Local Obligatoria: Todos los servicios (Postgres, Valkey, SeaweedFS, Redpanda) deben configurarse para usar carpetas locales del host.
4. Memoria Operativa (Valkey/AMS): Integra el Agent Memory Server con Valkey para caché y estados (Semantic Caching).
5. Conocimiento Semántico (PostgreSQL + pgvector): Centraliza la búsqueda semántica local. Prohibido VectorDBs externas.
6. Capacidad de Acción (MCP): Configura `.mcp/config.json` para permisos de sistema."

📈 FASE 2: La Triple Capa de Memoria y Heurística de Código
1. Capa Documental: .agent/AGENT.md (La Ley: tipado estricto, UUID v7) y el Mandato de Soberanía: "Los datos residen en el host".
2. Capa Operativa (Valkey): Gestión de estados de sesión y colas de tareas asíncronas. Implementa Semantic Caching.
3. Capa Semántica (Postgres): Long-term Memory y almacenamiento de embeddings de lecciones aprendidas.
4. Heurística de Aplicación: Todo desarrollo generado a partir de este framework debe incorporar de forma obligatoria lógica heurística en su propia estructura de código para optimizar recursos y flujos de fallback locales.

🔄 FASE 3: Ciclo de Vida y Mantenimiento (Ritos Obligatorios)
- Rito de Inicio (Bootstrapping): "Lee tu estado en .agent/STATE.md, consulta tus heurísticas en .agent/HEURISTICS.md, sincroniza con el AMS y verifica que los montajes de las carpetas locales de datos sean correctos. Confirma cuando estés listo."
- Rito de Cierre (Higiene de Memoria): 
    1. Ejecuta Summarization: Condensa la actividad y lecciones del día.
    2. Actualiza .agent/STATE.md: Resume archivos tocados, errores resueltos y próximos pasos.
    3. Registra Decisiones: Crea un nuevo ADR en DECISIONS/ si hubo cambios estructurales.
    4. Persistencia Vectorial: Almacena las lecciones del día en Postgres vía pgvector.

📁 SOBERANÍA DE DATOS Y PERSISTENCIA LOCAL
- Mapeo de Volúmenes: Los docker-compose.yml deben usar rutas relativas al host (ej. `./data/postgres:/var/lib/postgresql/data`).
- Independencia: Los datos deben sobrevivir a un `docker compose down -v`.
- Servicios Incluidos: Postgres, SeaweedFS, Redpanda, Valkey, Keycloak, Netdata, Grafana.

🔒 Seguridad (.gitignore)
Añadir siempre: data/, postgres_data/, seaweedfs_data/, redpanda_data/, valkey_data/, .agent/brain/, .env.