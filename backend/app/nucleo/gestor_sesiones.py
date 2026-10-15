"""
gestor_sesiones.py -- Creación y persistencia de sesiones de usuario
(cookie -> datos de sesión), en un archivo JSON en disco para que un
reinicio del servidor no desloguee a todo el mundo.

Incluye usuarios DEMO (sin contraseña, MFA fijo) SOLO para desarrollo y para
demostraciones controladas. Están DESHABILITADOS por defecto: el código MFA fijo
no es autenticación multifactor real (Sección 4.6 de la tesis) y, en un sistema
expuesto a internet, la cuenta demo de Administrador daría control total a
cualquiera que conozca el correo. Se habilitan con NEMESIS_CUENTAS_DEMO=true.
En producción, el primer Administrador real se crea con NEMESIS_ADMIN_EMAIL
(ver gestion_usuarios.asegurar_administrador_inicial).
"""

import os
import json
import secrets
from datetime import datetime, timedelta

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUTA_SESIONES = os.path.join(DIRECTORIO_BACKEND, "data", "sesiones.json")

DURACION_SESION_HORAS = 8

_USUARIOS_DEMO = {
    "admin@nemesis.ec":    {"nombre": "Admin Nemesis", "rol": "Administrador", "mfa_code": "123456"},
    "tanya@nemesis.ec":    {"nombre": "Tanya Vaca",    "rol": "Analista SOC",  "mfa_code": "654321"},
    "fernando@nemesis.ec": {"nombre": "Fernando Y.",   "rol": "Analista SOC",  "mfa_code": "112233"},
}


def cuentas_demo_habilitadas() -> bool:
    """Las cuentas demo solo existen si NEMESIS_CUENTAS_DEMO=true (default: apagado)."""
    return os.environ.get("NEMESIS_CUENTAS_DEMO", "false").strip().lower() == "true"


def obtener_usuarios_demo() -> dict:
    return _USUARIOS_DEMO if cuentas_demo_habilitadas() else {}


def _cargar_sesiones() -> dict:
    if not os.path.exists(RUTA_SESIONES):
        return {}
    try:
        with open(RUTA_SESIONES, "r", encoding="utf-8") as archivo:
            return json.load(archivo)
    except (json.JSONDecodeError, OSError):
        return {}


def _guardar_sesiones(sesiones: dict) -> None:
    os.makedirs(os.path.dirname(RUTA_SESIONES), exist_ok=True)
    with open(RUTA_SESIONES, "w", encoding="utf-8") as archivo:
        json.dump(sesiones, archivo)


def crear_sesion(email: str, usuario: dict) -> str:
    """Genera un token de sesión nuevo y lo persiste en disco."""
    sesiones = _cargar_sesiones()
    token = secrets.token_urlsafe(32)
    sesiones[token] = {
        "email": email,
        "usuario": usuario,
        "expira": (datetime.now() + timedelta(hours=DURACION_SESION_HORAS)).isoformat(),
    }
    _guardar_sesiones(sesiones)
    return token


def eliminar_sesion(token: str) -> None:
    sesiones = _cargar_sesiones()
    if token in sesiones:
        del sesiones[token]
        _guardar_sesiones(sesiones)
