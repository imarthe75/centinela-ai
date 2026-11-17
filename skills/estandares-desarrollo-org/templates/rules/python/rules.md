# 🐍 Python Specific Rules

Estándares de desarrollo para proyectos basados en Python en el ecosistema.

*Nota de Atribución: Estas pautas específicas se adaptan de los estándares de Python del proyecto **affaan-m/ECC** (Licencia MIT).*

## 📌 Guías del Lenguaje

1. **Tipado Estático con MyPy:**
   - Define anotaciones de tipo (`Type Hints`) en todas las firmas de funciones y métodos públicos.
2. **Higiene de Dependencias:**
   - Prefiere el uso de un entorno virtual estructurado (`.venv`) y gestiona dependencias mediante `requirements.txt` o `pyproject.toml` bien especificados.
3. **Manejo de Conexiones (base de datos, caché, colas):**
   - Siempre maneja la apertura y cierre de conexiones a base de datos usando administradores de contexto (`with` statements).
   - Pool de conexiones con tamaño y tiempo de espera explícitos; una conexión muerta se descarta, no se devuelve al pool.
4. **Formateo y Estilo:**
   - Adhiérete a la guía de estilo PEP 8. Usa formateadores como Black, Ruff o Flake8 para asegurar la homogeneidad del código.
5. **Cero Silenciamiento de Excepciones:**
   - Queda estrictamente PROHIBIDO usar bloques `try...except Exception:` que silencien fallos con `pass` o retornen respuestas de éxito falsas. Toda excepción no esperada debe loguearse con traza completa: `logger.error("Descripción del error", exc_info=True)`.
6. **Parches generados por IA:**
   - Un parche se presenta solo si pasó `git apply --check` contra el archivo real del repositorio; si no aplica, se descarta y se declara «requiere corrección manual».
   - Prohibidos los scripts de relleno masivo que escriban diffs o datos no verificados en una base de datos.
7. **Consultas SQL Seguras e Idempotentes:**
   - Usar siempre consultas parametrizadas. Nunca concatenar cadenas en sentencias SQL.
   - En comparaciones de campos que puedan ser `NULL`, usar `IS NOT DISTINCT FROM` para evitar falsos negativos o duplicaciones accidentales.

