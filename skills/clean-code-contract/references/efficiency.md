# Efficiency Ladder (Ponytail Pattern)

Antes de escribir cualquier código nuevo, el agente **debe** escalar estos seis peldaños en orden. Detente en el primero que resuelva el problema.

| Peldaño | Pregunta | Acción si aplica |
|---------|----------|-----------------|
| **1. Necesidad** | ¿Es realmente necesario este código? | Eliminar el requerimiento o simplificar el caso de uso |
| **2. Stdlib / Built-in** | ¿Lo resuelve la librería estándar del lenguaje? | Usar directamente sin dependencias externas |
| **3. Feature nativa** | ¿Lo resuelve una feature nativa del framework/DB? | Configurar, no programar |
| **4. Dependencia existente** | ¿Ya está instalada una librería que lo hace? | Reutilizar sin agregar nueva dependencia |
| **5. Solución simple** | ¿Puede resolverse con < 10 líneas sin abstracciones? | Escribir inline, sin clases ni helpers |
| **6. Solución custom** | Ninguno de los anteriores aplica | Implementar con justificación explícita |

## Regla de deuda técnica

Cuando se elige un peldaño inferior al óptimo por urgencia o restricción, marcar con:

```python
# ponytail: upgrade a stdlib una vez que X esté resuelto
```

```typescript
// ponytail: reemplazar con feature nativa de PG una vez en prod
```

Estos marcadores se buscan con `grep -rn 'ponytail:'` al planear deuda técnica.


## Integración con el ECC Harness

Se aplica **antes** del límite de 3 intentos (ver `systematic-debugging`). Si el intento 1 ya usa el peldaño incorrecto, los reintentos 2 y 3 escalarán hacia peldaños superiores antes de hacer halt.
