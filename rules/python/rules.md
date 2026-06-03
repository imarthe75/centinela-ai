# 🐍 Python Specific Rules

Estándares de desarrollo para proyectos basados en Python en el ecosistema.

*Nota de Atribución: Estas pautas específicas se adaptan de los estándares de Python del proyecto **affaan-m/ECC** (Licencia MIT).*

## 📌 Guías del Lenguaje

1. **Tipado Estático con MyPy:**
   - Define anotaciones de tipo (`Type Hints`) en todas las firmas de funciones y métodos públicos.
2. **Higiene de Dependencias:**
   - Prefiere el uso de un entorno virtual estructurado (`.venv`) y gestiona dependencias mediante `requirements.txt` o `pyproject.toml` bien especificados.
3. **Manejo de Conexiones (Valkey / Postgres):**
   - Siempre maneja la apertura y cierre de conexiones a base de datos usando administradores de contexto (`with` statements).
   - Utiliza la clase `SemanticCache` para almacenar respuestas repetitivas en Valkey de forma eficiente.
4. **Formateo y Estilo:**
   - Adhiérete a la guía de estilo PEP 8. Usa formateadores como Black, Ruff o Flake8 para asegurar la homogeneidad del código.
