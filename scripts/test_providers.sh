#!/usr/bin/env bash
set -euo pipefail
# Script de prueba para validar proveedores LLM definidos en .env
# No imprime claves; muestra solo extractos de respuesta.

# Cargar .env si existe
if [ -f .env ]; then
  set -a
  . .env
  set +a
fi

command -v jq >/dev/null 2>&1 || { echo "Advertencia: jq no encontrado; la salida será menos legible."; }

echo "Probar NVIDIA NIM (OpenAI-compatible)..."
if [ -n "${NVIDIA_NIM_API_KEY-}" ] && [ -n "${NVIDIA_NIM_BASE_URL-}" ]; then
  resp=$(curl -s -H "Authorization: Bearer $NVIDIA_NIM_API_KEY" -H "Content-Type: application/json" \
    -X POST "$NVIDIA_NIM_BASE_URL/chat/completions" \
    -d '{"model":"'"$OPENAI_MODEL"'","messages":[{"role":"user","content":"Genera un JSON con campo result: hola"}],"max_tokens":64}') || true
  if command -v jq >/dev/null 2>&1; then
    echo "NVIDIA Extracto: $(echo "$resp" | jq -r '.choices[0].message.content // .choices[0].text // . | tostring' 2>/dev/null | head -c 300)"
  else
    echo "NVIDIA Extracto (sin jq): $(echo "$resp" | head -c 300)"
  fi
else
  echo "NVIDIA_NIM_API_KEY o NVIDIA_NIM_BASE_URL no configuradas; omitiendo."
fi

echo
echo "Probar OpenRouter (OpenAI-compatible)..."
if [ -n "${OPENROUTER_API_KEY-}" ] && [ -n "${OPENROUTER_BASE_URL-}" ]; then
  resp=$(curl -s -H "Authorization: Bearer $OPENROUTER_API_KEY" -H "Content-Type: application/json" \
    -X POST "$OPENROUTER_BASE_URL/chat/completions" \
    -d '{"model":"'"$OPENAI_MODEL"'","messages":[{"role":"user","content":"Genera un JSON con campo result: hola"}],"max_tokens":64}') || true
  if command -v jq >/dev/null 2>&1; then
    echo "OpenRouter Extracto: $(echo "$resp" | jq -r '.choices[0].message.content // .choices[0].text // . | tostring' 2>/dev/null | head -c 300)"
  else
    echo "OpenRouter Extracto (sin jq): $(echo "$resp" | head -c 300)"
  fi
else
  echo "OPENROUTER_API_KEY o OPENROUTER_BASE_URL no configuradas; omitiendo."
fi

echo
echo "Probar Google Generative Language..."
if [ -n "${GOOGLE_API_KEY-}" ] && [ -n "${OPENAI_MODEL-}" ]; then
  # Usamos generateContent como en ejemplos previos
  resp=$(curl -s -H "Content-Type: application/json" -H "X-goog-api-key: $GOOGLE_API_KEY" \
    -X POST "https://generativelanguage.googleapis.com/v1beta/models/$OPENAI_MODEL:generateContent" \
    -d '{"contents":[{"parts":[{"text":"Genera un JSON con campo result: hola"}]}]}') || true
  if command -v jq >/dev/null 2>&1; then
    echo "Google Extracto: $(echo "$resp" | jq -r '.candidates[0].content[0].text // . | tostring' 2>/dev/null | head -c 300)"
  else
    echo "Google Extracto (sin jq): $(echo "$resp" | head -c 300)"
  fi
else
  echo "GOOGLE_API_KEY o OPENAI_MODEL no configuradas; omitiendo."
fi

echo
echo "Pruebas completadas."