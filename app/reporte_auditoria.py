"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Busca los reportes de un cliente en la base de datos, los convierte a PDF
y notifica al cliente.

Corregido en el Laboratorio 1 (Parte M): consulta parametrizada, ejecución
sin shell con lista blanca, YAML seguro, hash con sal y credenciales fuera
del código.
"""

import hashlib
import os
import re
import sqlite3
import subprocess
from pathlib import Path

import yaml

# Credenciales leídas del entorno, nunca escritas en el código.
# Las anteriores quedaron en el historial de Git: se consideran comprometidas y rotadas.
NOTIFICATION_API_KEY = os.environ.get("REPORTAUDIT_NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("REPORTAUDIT_SMTP_PASSWORD", "")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")

# Lista blanca de nombres: letras, números, _ . - y extensión .html; nunca empieza por "-".
NOMBRE_HTML_VALIDO = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.html$")


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        # safe_load solo construye datos (dict, list, str, números), nunca objetos de Python.
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente."""
    conexion = sqlite3.connect(ruta_db)
    cursor = conexion.cursor()
    # Consulta parametrizada: el dato viaja separado de la orden SQL.
    query = "SELECT * FROM reportes WHERE cliente = ?"
    cursor.execute(query, (nombre_cliente,))
    resultados = cursor.fetchall()
    conexion.close()
    return resultados


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF usando la utilidad del sistema."""
    # Se valida el nombre COMPLETO (sin rutas ni "/"): así nunca puede empezar por "-".
    if not NOMBRE_HTML_VALIDO.fullmatch(nombre_archivo):
        raise ValueError("Nombre de archivo no válido")
    # "./nombre": aunque la validación fallara, wkhtmltopdf nunca lo leería como una opción.
    entrada = os.path.join(".", nombre_archivo)
    salida = entrada + ".pdf"
    try:
        # Lista de argumentos y sin shell: cada elemento llega como texto literal.
        subprocess.run(["wkhtmltopdf", entrada, salida], check=False)
    except FileNotFoundError:
        print("Aviso: wkhtmltopdf no está instalado; no se generó el PDF.")
    return nombre_archivo + ".pdf"


def hash_password_legacy(password):
    """Genera el hash de una contraseña con PBKDF2-SHA256 y sal aleatoria."""
    sal = os.urandom(16)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode(), sal, 600_000)
    return sal.hex() + ":" + derivado.hex()


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    # Nunca se escribe una credencial en un log, ni siquiera parcialmente.
    estado = "configurada" if NOTIFICATION_API_KEY else "NO configurada"
    print(f"[NotifyAPI clave {estado}] -> {email}: {mensaje}")
    return True
