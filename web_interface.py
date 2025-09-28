from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os
import sys
import threading
import queue
import time
from io import StringIO
import contextlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from correcciones import obtener_correcciones
import json
#===============================================================================
import ssl
import re
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin  # ya lo usas, pero lo dejo claro

#===============================================================================
app = Flask(__name__)
app.secret_key = 'vulnerability_scanner_secret_key'
scan_results = {}  # aquí se guardarán los resultados completos por sesión


# Configuración para entornos cloud y locales
REPORT_DIR = os.environ.get('REPORT_DIR', 'reports')

# Crear directorio para informes si no existe
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# Configurar logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Cola para comunicación entre el hilo de escaneo y la aplicación web
scan_queue = queue.Queue()
results_queue = queue.Queue()

# Funciones del escáner

# PDF report initialization
def generate_report(results, filename):
    pdf_path = os.path.join(REPORT_DIR, filename)
    pdf = canvas.Canvas(pdf_path, pagesize=letter)
    pdf.setTitle("Reporte de Vulnerabilidades de Aplicaciones Web")
    pdf.drawString(100, 750, "Reporte de Vulnerabilidades de Aplicaciones Web")
    y = 720
    for vuln, (status, level) in results.items():
        pdf.drawString(80, y, f"{vuln}: {status} (Risk: {level})")
        y -= 20
    pdf.save()
    return pdf_path


# Agrega esto (por ejemplo justo debajo de generate_report)


def generate_correcciones_pdf(correcciones_text, filename):
    """
    Genera un PDF con las correcciones sugeridas.
    - correcciones_text: puede ser un string (JSON), lista de strings o lista de dicts.
    - filename: nombre del archivo PDF (ej: 'correcciones_<session_id>.pdf')
    Retorna la ruta completa del PDF generado.
    """
    def format_correcciones(data):
        """
        Convierte correcciones en texto legible:
        - Si es lista de dicts con vulnerabilidad, riesgo y correcciones → formatea completo.
        - Si es lista de strings → las numera.
        - Si es string → lo devuelve tal cual.
        """
        lines = []
        if isinstance(data, list):
            # Caso: lista de dicts con vulnerabilidad
            if all(isinstance(x, dict) for x in data):
                for item in data:
                    vulnerabilidad = item.get("vulnerabilidad", "Desconocida")
                    riesgo = item.get("riesgo", "N/A")
                    correcciones = item.get("correcciones", [])

                    lines.append(f"Vulnerabilidad: {vulnerabilidad}")
                    lines.append(f"Riesgo: {riesgo}")
                    lines.append("Correcciones:")

                    if isinstance(correcciones, list):
                        for idx, corr in enumerate(correcciones, start=1):
                            lines.append(f"  {idx}. {corr}")
                    else:
                        lines.append(f"  - {correcciones}")

                    lines.append("")  # línea en blanco
            else:
                # Lista simple de strings
                for idx, corr in enumerate(data, start=1):
                    lines.append(f"{idx}. {corr}")
        else:
            # String plano
            lines.append(str(data))

        return "\n".join(lines)

    # 🔹 Intentar parsear JSON si es string
    if isinstance(correcciones_text, str):
        try:
            correcciones_text = json.loads(correcciones_text)
        except Exception:
            pass  # si no es JSON válido, lo dejamos como string

    contenido = format_correcciones(correcciones_text)

    pdf_path = os.path.join(REPORT_DIR, filename)
    try:
        pdf = canvas.Canvas(pdf_path, pagesize=letter)
        pdf.setTitle("Correcciones sugeridas - Vulnerability Scanner")

        # Encabezado
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(72, 750, "Correcciones sugeridas")
        pdf.setFont("Helvetica", 10)

        # Margenes y manejo de salto de linea
        x_margin = 72
        y = 730
        line_height = 12
        max_width = 460  # ancho útil de página

        # Dividir el texto en líneas que quepan en max_width
        from reportlab.pdfbase.pdfmetrics import stringWidth

        for paragraph in contenido.split("\n"):
            paragraph = paragraph.strip()
            if paragraph == "":
                y -= line_height
            else:
                words = paragraph.split(" ")
                line = ""
                for w in words:
                    test_line = (line + " " + w).strip()
                    if stringWidth(test_line, "Helvetica", 10) <= max_width:
                        line = test_line
                    else:
                        pdf.drawString(x_margin, y, line)
                        y -= line_height
                        line = w
                        if y < 72:
                            pdf.showPage()
                            pdf.setFont("Helvetica", 10)
                            y = 750

                if line:
                    pdf.drawString(x_margin, y, line)
                    y -= line_height

            if y < 72:
                pdf.showPage()
                pdf.setFont("Helvetica", 10)
                y = 750

        pdf.save()
        return pdf_path
    except Exception as e:
        logging.exception("Error generando PDF de correcciones: %s", e)
        return None


#varible que almacena las correciones de las vulnerabilidades


# NUEVA: A01 - Broken Access Control Test ============================================================
def check_broken_access_control(url):
    results_queue.put(f"Probando Broken Access Control (A01) en {url}...")
    try:
        # Obtener la página principal
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        # Buscar enlaces con patrones como /user/1, /profile/123
        potential_endpoints = [link for link in links if re.search(r'/[\w-]+/\d+', link)]
        
        if not potential_endpoints:
            # Fallback más genérico: probar /id/1
            potential_endpoints = [f"{urlparse(url).scheme}://{urlparse(url).netloc}/id/1"]
        
        vulnerable = False
        for endpoint in potential_endpoints[:2]:
            full_url = urljoin(url, endpoint)
            # Extraer ID original
            match = re.search(r'/(\d+)', full_url)
            if not match:
                continue
            original_id = match.group(1)
            tampered_url = re.sub(rf'/{original_id}', f'/{int(original_id) + 1}', full_url)
            
            # Hacer requests
            orig_res = requests.get(full_url, timeout=10)
            if orig_res.status_code != 200:
                continue
            
            tamp_res = requests.get(tampered_url, timeout=10)
            if tamp_res.status_code == 200 and len(tamp_res.text.strip()) > 0:
                vulnerable = True
                break
        
        result = ("Vulnerable" if vulnerable else "Safe", "Critical" if vulnerable else "Medium")
    except Exception as e:
        results_queue.put(f"Error en Broken Access Control: {str(e)}")
        result = ("Error", "Unknown")
    
    results_queue.put(f"Broken Access Control (A01): {result[0]} (Risk: {result[1]})")
    return result
#==================================================================================================

# NUEVA: A02 - Cryptographic Failures Test
def check_cryptographic_failures(url):
    results_queue.put(f"Probando Cryptographic Failures (A02) en {url}...")
    issues = []
    try:
        # Verificar HTTPS
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            issues.append("No HTTPS")
        else:
            # Intentar conexión TLS solo si es HTTPS
            hostname = parsed.netloc.split(':')[0]  # Extraer solo el nombre del host
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    if tls_version and 'TLSv1.3' not in tls_version and 'TLSv1.2' not in tls_version:
                        issues.append("TLS version weak (<1.2)")
                    
                    # Verificar certificado
                    cert = ssock.getpeercert()
                    if cert:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.now():
                            issues.append("Certificate expired")
                    else:
                        issues.append("Invalid certificate")
                        
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
        if parsed.scheme == 'https':
            issues.append(f"SSL/TLS Error: {str(e)}")
        # Si es HTTP, no intentamos TLS
    except Exception as e:
        issues.append(f"Error: {str(e)}")

    status = f"Issues: {', '.join(issues)}" if issues else "Secure"
    risk = "Critical" if issues else "Low"
    result = (status, risk)
    
    results_queue.put(f"Cryptographic Failures (A02): {result[0]} (Risk: {result[1]})")
    return result

#==========================================================================================================

# SQL Injection Test
def check_sql_injection(url):
    results_queue.put(f"Probando SQL Injection en {url}...")
    test_payloads = ["' OR '1'='1", '" OR "1"="1', "'--", "' OR 1=1 --"]
    vulnerable = False
    for payload in test_payloads:
        test_url = f"{url}?id={payload}"
        try:
            res = requests.get(test_url)
            if any(error in res.text.lower() for error in ["sql", "syntax", "mysql", "native client"]):
                vulnerable = True
                break
        except requests.exceptions.RequestException as e:
            results_queue.put(f"Error en la solicitud: {str(e)}")
            return ("Error", "Unknown")
    
    result = ("Vulnerable" if vulnerable else "Safe", "High" if vulnerable else "Low")
    results_queue.put(f"SQL Injection: {result[0]} (Risk: {result[1]})")
    return result

# XSS Test
def check_xss(url):
    results_queue.put(f"Probando XSS en {url}...")
    payload = "<script>alert(1)</script>"
    try:
        res = requests.get(f"{url}?q={payload}")
        if payload in res.text:
            result = ("Vulnerable", "High")
        else:
            result = ("Safe", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"XSS: {result[0]} (Risk: {result[1]})")
    return result

# Clickjacking Test
def check_clickjacking(url):
    results_queue.put(f"Probando Clickjacking en {url}...")
    try:
        headers = requests.get(url).headers
        if "X-Frame-Options" not in headers:
            result = ("Vulnerable", "Medium")
        else:
            result = ("Safe", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"Clickjacking: {result[0]} (Risk: {result[1]})")
    return result

# Security Headers Test
def check_security_headers(url):
    results_queue.put(f"Verificando Security Headers en {url}...")
    expected_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    try:
        res = requests.get(url)
        missing = [h for h in expected_headers if h not in res.headers]
        if missing:
            result = (f"Missing: {', '.join(missing)}", "Medium")
        else:
            result = ("All present", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"Security Headers: {result[0]} (Risk: {result[1]})")
    return result


# Open Redirect Test
def check_open_redirect(url):
    results_queue.put(f"Probando Open Redirect en {url}...")
    test_url = url + "/redirect?url=https://evil.com"
    try:
        res = requests.get(test_url, allow_redirects=False)
        if "Location" in res.headers and "evil.com" in res.headers["Location"]:
            result = ("Vulnerable", "High")
        else:
            result = ("Safe", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"Open Redirect: {result[0]} (Risk: {result[1]})")
    return result


# CSRF Token Test (basic)
def check_csrf(url):
    results_queue.put(f"Probando CSRF en {url}...")
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.text, 'html.parser')
        forms = soup.find_all('form')
        if forms:
            for form in forms:
                inputs = form.find_all('input')
                if not any("csrf" in inp.get("name", "").lower() for inp in inputs):
                    result = ("Missing CSRF Token", "Medium")
                    break
            else:
                result = ("Token Present", "Low")
        else:
            result = ("No Forms Found", "Low")
    except Exception as e:
        results_queue.put(f"Error: {str(e)}")
        return (f"Error: {str(e)}", "Unknown")
    
    results_queue.put(f"CSRF: {result[0]} (Risk: {result[1]})")
    return result


# Función extendida para probar XSS con Selenium
def check_xss_selenium(url):
    results_queue.put(f"Probando XSS con Selenium en {url}...")
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        from webdriver_manager.core.os_manager import ChromeType
        from selenium.webdriver.chrome.service import Service
        
        # Configuración para entorno cloud
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-setuid-sandbox")
        
        # Usar webdriver-manager para gestionar el driver automáticamente
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
        except:
            # Fallback para entornos cloud donde ChromeDriverManager podría fallar
            results_queue.put("Fallback: Usando método alternativo para XSS - simulación sin navegador real")
            # Simulamos la prueba sin navegador real para entornos donde Selenium no funciona
            response = requests.get(url)
            if "<script>alert" in response.text:
                return ("Potencialmente Vulnerable (Simulado)", "Medium")
            return ("No se detectaron XSS simples (Simulado)", "Low")
        
        driver.get(url)
        
        script = "<script>alert('XSS')</script>"
        try:
            inputs = driver.find_elements(By.TAG_NAME, 'input')
            xss_detected = False
            
            for input_field in inputs:
                try:
                    input_field.send_keys(script)
                    try:
                        input_field.submit()
                    except:
                        pass
                    
                    # Comprobar si aparece una alerta
                    try:
                        alert = driver.switch_to.alert
                        alert.accept()
                        xss_detected = True
                        break
                    except:
                        pass
                except:
                    continue
            
            driver.quit()
            
            if xss_detected:
                result = ("Vulnerable (Selenium)", "High")
            else:
                result = ("Safe (Selenium)", "Low")
        except Exception as inner_e:
            driver.quit()
            results_queue.put(f"Error al interactuar con la página: {str(inner_e)}")
            result = ("Error en pruebas XSS", "Unknown")
    except Exception as e:
        results_queue.put(f"Error en la prueba con Selenium: {str(e)}")
        # Usar alternativa: comprobación básica si Selenium falla completamente
        try:
            response = requests.get(url)
            if "<script>alert" in response.text:
                return ("Potencialmente Vulnerable (Alternativo)", "Medium")
            return ("Prueba alternativa: No se detectaron XSS simples", "Low")
        except:
            return ("Error en todas las pruebas XSS", "Unknown")
    
    results_queue.put(f"XSS (Selenium): {result[0]} (Risk: {result[1]})")
    return result

# Función principal de escaneo
def scan(url, session_id):
    results_queue.put("Iniciando escaneo de vulnerabilidades...")
    results = {}
    
    # Verificar que la URL es válida
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error: No se puede conectar a {url}: {str(e)}")
        return None
    
    results_queue.put(f"Escaneando {url} y sus vulnerabilidades...")
    
    # Ejecutar las pruebas
    results["SQL Injection"] = check_sql_injection(url)
    results["XSS"] = check_xss(url)
    results["Clickjacking"] = check_clickjacking(url)
    results["Open Redirect"] = check_open_redirect(url)
    results["Security Headers"] = check_security_headers(url)
    results["CSRF"] = check_csrf(url)
    
    # Prueba adicional de XSS con Selenium
    try:
        results["XSS (Selenium)"] = check_xss_selenium(url)
    except Exception as e:
        results_queue.put(f"Error en la prueba XSS con Selenium: {str(e)}")
        results["XSS (Selenium)"] = ("Error", "Unknown")

    # NUEVAS: Agregar A01 y A02
    results["Broken Access Control (A01)"] = check_broken_access_control(url)
    results["Cryptographic Failures (A02)"] = check_cryptographic_failures(url)
        
    
    results_queue.put("\n--- Resultados del Scan ---")
    for vuln, (status, risk) in results.items():
        results_queue.put(f"{vuln}: {status} (Risk: {risk})")
    
    # Generar reporte PDF
    filename = f"vulnerability_report_{session_id}.pdf"
    pdf_path = generate_report(results, filename)
    results_queue.put(f"Reporte PDF generado: {filename}")

     # Obtener correcciones desde Gemini
    correcciones = obtener_correcciones(results)
    results_queue.put("\n--- Correcciones sugeridas ---")
    results_queue.put(correcciones)

     # --- Añadir: generar PDF de correcciones y guardarlo ---
    corr_filename = f"correcciones_{session_id}.pdf"
    corr_pdf_path = generate_correcciones_pdf(correcciones, corr_filename)
    # Guarda la ruta en scan_results (mapa global) para que /get_results o /download pueda usarlo
    scan_results[session_id] = {
        "results": results,
        "report_pdf": pdf_path,
        "correcciones_pdf": corr_pdf_path
    }
    
    # Señalar que se completó el escaneo
    results_queue.put("SCAN_COMPLETE")
    
    return results, pdf_path

# Rutas de la aplicación web
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    url = request.form.get('url')
    if not url:
        flash('Por favor, ingrese una URL válida', 'danger')
        return redirect(url_for('index'))
    
    # Generar ID de sesión único
    session_id = str(int(time.time()))
    
    # Iniciar el escaneo en un hilo separado
    thread = threading.Thread(target=scan, args=(url, session_id))
    thread.daemon = True
    thread.start()
    
    return redirect(url_for('results', session_id=session_id))

@app.route('/results/<session_id>')
def results(session_id):
    return render_template('results.html', session_id=session_id)

@app.route('/get_results')
def get_results():
    session_id = request.args.get("session_id")  # recibes el id desde el frontend
    results_list = []
    correcciones = []

    while not results_queue.empty():
        result = results_queue.get()
        if result == "SCAN_COMPLETE":
            results_dict = scan_results.get(session_id, {})
            correcciones = obtener_correcciones(results_dict.get('results', {}))
            correcciones_pdf = results_dict.get('correcciones_pdf')  # puede ser None
            return {
                'results': results_list,
                'correcciones': correcciones,
                'correcciones_pdf': correcciones_pdf,
                'complete': True
        }

        results_list.append(result)

    return {'results': results_list, 'correcciones': correcciones, 'complete': False}


@app.route('/download/<session_id>')
def download_report(session_id):
    filename = f"vulnerability_report_{session_id}.pdf"
    file_path = os.path.join(REPORT_DIR, filename)
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        flash('El reporte no está disponible', 'danger')
        return redirect(url_for('index'))
    

@app.route('/download_correcciones/<session_id>')
def download_correcciones(session_id):
    entry = scan_results.get(session_id, {})
    corr_path = entry.get('correcciones_pdf')
    if corr_path and os.path.exists(corr_path):
        return send_file(corr_path, as_attachment=True)
    else:
        flash('El PDF de correcciones no está disponible', 'danger')
        return redirect(url_for('index'))


if __name__ == '__main__':
    # Obtener el puerto desde la variable de entorno o usar 5000 como predeterminado
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
