# Accesibilidad de la interfaz (solo proyectos con interfaz)

Son el piso técnico verificable en código; la revisión con lector de
pantalla y el contraste real siguen siendo revisión humana.

- Toda imagen informativa lleva texto alternativo; la decorativa, `alt=""`.
- Todo control de formulario tiene etiqueta asociada (`<label for>` o `aria-label`); un placeholder no es una etiqueta.
- Todo botón o enlace tiene nombre accesible (texto visible o `aria-label`); un icono solo no basta.
- Lo que se puede hacer con el ratón se puede hacer con el teclado; nada de `tabindex` positivo; el foco siempre es visible.
- `<html lang>` declarado; un único `<h1>`; los niveles de encabezado no saltan.
- La información no depende solo del color; contraste de texto ≥ 4.5:1 (3:1 para texto grande).
- Los errores de formulario dicen qué falló y cómo corregirlo, en lenguaje llano.
