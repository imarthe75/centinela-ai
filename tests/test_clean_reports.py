import pytest
from fastapi.testclient import TestClient
from main import app, extract_clean_code


def test_extract_clean_code_from_diff():
    diff_sample = """--- a/src/app/shared/components/visor-documento/visor-documento.component.ts
+++ b/src/app/shared/components/visor-documento/visor-documento.component.ts
@@ -25,6 +25,12 @@
-  return this.sanitizer.bypassSecurityTrustResourceUrl(urlInsegura);
+  const urlValidada = this.sanitizer.sanitize(SecurityContext.RESOURCE_URL, urlInsegura);
+  return this.sanitizer.bypassSecurityTrustResourceUrl(urlValidada);"""

    clean = extract_clean_code(diff_sample)
    assert "--- a/" not in clean
    assert "+++ b/" not in clean
    assert "@@" not in clean
    assert "-  return this.sanitizer.bypassSecurityTrustResourceUrl" not in clean
    assert "const urlValidada = this.sanitizer.sanitize(SecurityContext.RESOURCE_URL, urlInsegura);" in clean
    assert "return this.sanitizer.bypassSecurityTrustResourceUrl(urlValidada);" in clean


def test_extract_clean_code_empty_and_plain():
    assert extract_clean_code("") == ""
    assert extract_clean_code(None) == ""
    plain = "const a = 1;\nconst b = 2;"
    assert extract_clean_code(plain) == plain


def test_asset_report_html_endpoint():
    client = TestClient(app)
    response = client.get("/api/reports/asset/GitLab%2Fproyecto-g%2Ffrontend%2Ffrontend-proyecto-g?format=html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    content = response.text

    # Verifica tamaño de letra legible (15px)
    assert "font-size: 15px;" in content
    # Verifica etiquetas y redacción profesional y clara
    assert "Qué encontramos" in content
    assert "Riesgo al Negocio" in content
    assert "para dummies" not in content.lower()
    # Cada hallazgo muestra o bien un parche verificado (git apply --check) o, honestamente, que no
    # existe parche verificado -- nunca un diff inventado ni un texto que sugiera "no hace falta corregir".
    has_verified_patch = "Solución Recomendada (Código Limpio Listo para Usar)" in content and "clean-code-block" in content
    honest_no_patch = "Sin parche automático verificado" in content
    assert has_verified_patch or honest_no_patch
    assert "No se requiere modificación de código fuente" not in content
