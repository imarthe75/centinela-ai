# Manejo de errores y trabajos en segundo plano

1. **Prohibido silenciar excepciones.** Un `except Exception` (o `except:`) debe relanzar, registrar la traza completa (`logger.error(..., exc_info=True)`) o devolver un error explícito. Capturar y devolver éxito, o `pass`, esconde fallos durante meses. 2. **Captura estrecha.** Captura la excepción concreta que sabes manejar; el `except` amplio es solo el último recurso de un bucle de trabajo, y registra.
3. **Un fallo parcial no es un éxito.** Si una operación falló a medias, el resultado lo dice (`failed`/`partial`), no `ok`.
4. **Trabajos en segundo plano** (cron, workers, bucles): se prueban ejecutándolos directamente y comprobando el efecto real (consulta a la base), sin duplicar filas ni dejar nulos huérfanos; las conexiones usan el administrador de contexto completo.
5. **Señal ausente ≠ señal limpia.** «Sin salida» de un comando o de un escáner puede significar que falló. Distingue «no encontró nada» de «no pudo comprobar», y declara lo segundo como `NO EVALUADO`.
