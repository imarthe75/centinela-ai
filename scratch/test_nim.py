import os
import json
import urllib.request
import urllib.error
import ssl

print("[1] Script started")
api_key = "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"
base_url = "https://integrate.api.nvidia.com/v1"
model_name = "meta/llama-3.1-70b-instruct"

prompt = "Genera un JSON con un campo 'test': 'exito'."

payload = {
    "model": model_name,
    "messages": [{"role": "user", "content": prompt}]
}

url = base_url.rstrip('/') + '/chat/completions'
print("[2] URL:", url)
data = json.dumps(payload).encode('utf-8')
req = urllib.request.Request(url, data=data, headers={
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {api_key}'
})
print("[3] Creating SSL context")
ctx = ssl.create_default_context()
print("[4] Opening URL (timeout 10)")
try:
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        print("[5] Reading response")
        res_text = resp.read().decode('utf-8')
        print("[6] Raw Success Response:")
        print(res_text[:200])
except urllib.error.HTTPError as e:
    print("[E] HTTP Error:", e.code)
    print(e.read().decode('utf-8'))
except Exception as e:
    print("[E] Error:", e)
print("[7] Script finished")
