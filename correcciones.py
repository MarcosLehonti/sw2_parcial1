import os
import requests
import json

def obtener_correcciones(results):
    """
    Envía los resultados de vulnerabilidades a Gemini y obtiene correcciones.
    Siempre devuelve un JSON (dict en Python).
    """
    API_KEY = os.getenv("GEMINI_API_KEY")
    MODEL = "gemini-2.0-flash"
    URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"

    if not isinstance(results, dict):
        return {"error": True, "message": f"'results' no es un dict, es {type(results)}"}

    texto_vulnerabilidades = "\n".join(
        f"{vuln}: {estado} (Riesgo: {riesgo})"
        for vuln, (estado, riesgo) in results.items()
    )

    prompt = f"""
Eres un experto en ciberseguridad.
Te paso las vulnerabilidades detectadas:

{texto_vulnerabilidades}

Responde estrictamente en JSON con la siguiente estructura:

[
  {{
    "vulnerabilidad": "SQL Injection",
    "riesgo": "Alto",
    "correcciones": [
      "Paso 1...",
      "Paso 2...",
      "Paso 3..."
    ]
  }}
]
"""

    body = {"contents": [{"parts": [{"text": prompt}]}]}
    headers = {"Content-Type": "application/json", "X-goog-api-key": API_KEY}

    try:
        response = requests.post(URL, headers=headers, json=body, timeout=30)

        if response.status_code != 200:
            return {
                "error": True,
                "message": f"Error HTTP {response.status_code}",
                "details": response.text
            }

        data = response.json()
        print("🔍 Respuesta cruda de Gemini:", data)

        correcciones_text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )

        if not correcciones_text:
            return {"error": True, "message": "Gemini no devolvió texto en 'candidates'"}

        try:
            correcciones_json = json.loads(correcciones_text)
            return {"error": False, "correcciones": correcciones_json}
        except json.JSONDecodeError:
            return {
                "error": True,
                "message": "Gemini devolvió un texto que no es JSON válido",
                "raw": correcciones_text
            }

    except Exception as e:
        return {
            "error": True,
            "message": "Error al comunicarse con Gemini",
            "details": str(e)
        }
