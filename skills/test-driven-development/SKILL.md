---
name: test-driven-development
description: Ciclo rojo-verde-refactor: escribir primero la prueba que falla, el código mínimo que la pasa y refactorizar en verde; toda regla o validación con un caso que debe pasar y otro que debe fallar.
---

# Skill: Test-Driven Development (TDD)

**Origen:** Adaptado de [obra/superpowers](https://github.com/obra/superpowers) — MIT License  
**Aplica a:** Todo desarrollo de features y corrección de bugs

---

## Regla absoluta

> **SIN TEST FALLANDO PRIMERO, NO SE ESCRIBE CÓDIGO DE PRODUCCIÓN.**

Si no viste fallar el test, no puedes saber si valida el comportamiento correcto.

---

## El Ciclo RED → GREEN → REFACTOR

### 🔴 RED — Crear el test mínimo que falla

1. Escribe el test más simple que demuestre el comportamiento deseado.
2. **Ejecuta el test y confirma que falla** (no sólo que compila — que falla con el error correcto).
3. Si pasa inmediatamente: el test está mal escrito o el código ya existe. Ajusta.

```bash
# Python
pytest tests/test_feature.py::test_nuevo_comportamiento -v
# Debe mostrar FAILED — AssertionError: ...

# TypeScript
npm test -- --testNamePattern="nuevo comportamiento"
# Debe mostrar ● FAIL
```

### 🟢 GREEN — El código mínimo para pasar

1. Escribe **el código más simple posible** que haga pasar el test.
2. No optimices. No abstraigas. Sólo haz que el test pase.
3. **Ejecuta el test y confirma que pasa.**

### 🔵 REFACTOR — Limpiar sin romper

1. Mejora el código: extrae funciones, reduce duplicación, mejora nombres.
2. **Ejecuta todos los tests después de cada cambio.**
3. Si algún test falla: revierte el último cambio y refactoriza de forma más pequeña.

---

## Integración con ECC Harness (límite 3 intentos)

| Intento | Si el test no pasa |
|---------|-------------------|
| 1 | Re-lee el error, ajusta el código de producción (no el test) |
| 2 | Verifica que el test valida el comportamiento correcto (no la implementación) |
| 3 | Halt — consulta `memory.lessons`, posible problema arquitectónico |

---

## Racionalizaciones rechazadas

| Excusa | Realidad |
|--------|----------|
| "Es demasiado simple para testearse" | El código simple también se rompe |
| "Lo pruebo después de implementar" | Tests post-implementación pasan trivialmente → no prueban nada |
| "Ya lo probé manualmente" | Las pruebas manuales no son sistemáticas ni reproducibles |
| "Es urgente, no hay tiempo" | El debugging post-producción cuesta más que el test |

---

## Señales de alerta — detente y reinicia

- Escribiste código antes del test
- El test pasó inmediatamente al crearlo
- No puedes explicar por qué el test falló primero
- Vas a comentar "sólo esta vez"

---

## Relación con otros skills

- **systematic-debugging**: Úsalo cuando un test falla de forma inesperada
- **verification-before-completion**: Ejecuta la suite completa antes de declarar "listo"
- **ponytail-review**: Asegura que los helpers de test no dupliquen la stdlib


---

## Pares positivo/negativo (regla de oro de los detectores y validaciones)
Toda regla, validación o función que decide («¿esto es válido/peligroso?») se prueba con **al menos un caso que debe disparar y otro que no debe disparar**. Una regla sin caso negativo termina marcando lo que no debe; sin caso positivo, nunca se sabe si funciona. Si una prueba solo usa mocks de red, decláralo (`clean-code-contract/references/honesty.md` §3).
