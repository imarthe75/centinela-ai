# 🎨 Coding Style Guidelines

Estándares comunes de estilo de programación y organización de archivos en el ecosistema.

*Nota de Atribución: Estas pautas se adaptan del sistema de reglas del proyecto **affaan-m/ECC** (Licencia MIT).*

## 📌 Principios Generales

1. **Inmutabilidad por Defecto:**
   - Prefiere el uso de variables inmutables y estructuras de datos de solo lectura donde sea posible. Esto reduce los efectos secundarios y facilita la depuración.
2. **Organización de Archivos Clara:**
   - Los archivos deben tener una única responsabilidad. Separa de forma explícita la lógica de presentación (UI), la lógica de negocio (servicios/heurística) y la capa de acceso a datos.
3. **Legibilidad y Carga Mental (Sweller):**
   - Mantén las funciones pequeñas (idealmente menos de 50 líneas).
   - Divide la lógica compleja en subfunciones autoexplicativas para evitar la fatiga cognitiva de los desarrolladores y de los agentes de IA.
4. **Tipado Estricto:**
   - Siempre que el lenguaje de desarrollo lo permita, utiliza tipado estático o anotaciones de tipo robustas.
