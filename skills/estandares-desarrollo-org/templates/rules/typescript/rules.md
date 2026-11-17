# 🟦 TypeScript/JavaScript Specific Rules

Estándares de desarrollo para proyectos basados en TypeScript y Node.js en el ecosistema.

*Nota de Atribución: Estas pautas específicas se adaptan de los estándares de TypeScript/JavaScript del proyecto **affaan-m/ECC** (Licencia MIT).*

## 📌 Guías del Lenguaje

1. **Tipado Estricto (`tsconfig.json`):**
   - Configura `strict: true` en TypeScript. Evita a toda costa el tipo `any` y declara interfaces claras para todas las respuestas de API.
2. **Ciclos de Vida Asíncronos:**
   - Evita el uso de `async/await` sin bloques `try/catch` para prevenir el colapso del servidor debido a promesas rechazadas no controladas.
3. **Gestión de Paquetes:**
   - El framework detecta y prefiere el uso de `pnpm` o `npm` según se defina en el entorno local. Asegura que el `package-lock.json` o `pnpm-lock.yaml` se mantenga sincronizado.
4. **Higiene de Dependencias:**
   - No instales librerías duplicadas ni utilices módulos deprecados del ecosistema npm.
