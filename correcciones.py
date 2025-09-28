import requests

def obtener_correcciones(results):
    """
    Envía los resultados de vulnerabilidades a Gemini y obtiene correcciones.
    Key hardcodeada para pruebas locales.
    """
    API_KEY = "AIzaSyCyDPMCVSBr-dtypgUwQMMo9H4jFl0b1r8"  # <-- solo pruebas locales
    MODEL = "gemini-2.0-flash"
    URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"

    # Construir texto de vulnerabilidades
    if isinstance(results, dict):
        texto_vulnerabilidades = "\n".join(
            f"{vuln}: {estado} (Riesgo: {riesgo})"
            for vuln, (estado, riesgo) in results.items()
        )
    else:
        return "❌ Error: 'results' no es un dict, es " + str(type(results))

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
  }},
  ...
]
"""


    body = {"contents": [{"parts": [{"text": prompt}]}]}
    headers = {"Content-Type": "application/json", "X-goog-api-key": API_KEY}

    try:
        response = requests.post(URL, headers=headers, json=body, timeout=30)

        # Si no es 200, mostrar error
        if response.status_code != 200:
            return f"❌ Error HTTP {response.status_code}: {response.text}"

        data = response.json()

        # Log para depuración (mira en tu consola Flask)
        print("🔍 Respuesta cruda de Gemini:", data)

        # Intentar extraer el texto de la respuesta
        correcciones = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )

        return correcciones or "⚠️ Gemini no devolvió texto en 'candidates'."

    except Exception as e:
        return f"❌ Error al comunicarse con Gemini: {str(e)}"
