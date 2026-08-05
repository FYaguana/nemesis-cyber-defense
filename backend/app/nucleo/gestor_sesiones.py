"""
gestor_sesiones.py -- Creación y persistencia de sesiones de usuario
(cookie -> datos de sesión), en un archivo JSON en disco para que un
reinicio del servidor no desloguee a todo el mundo.

Incluye los usuarios DEMO de respaldo (sin contraseña, MFA fijo) para que
nunca se pueda quedar bloqueado del sistema -- se usan para el primer
ingreso, desde donde se invita al primer Administrador real.
"""

import os
import json
import secrets
from datetime import datetime, timedelta

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUTA_SESIONES = os.path.join(DIRECTORIO_BACKEND, "data", "sesiones.json")

DURACION_SESION_HORAS = 8

USUARIOS_DEMO = {
    "admin@nemesis.ec":    {"nombre": "Admin Nemesis", "rol": "Administrador", "mfa_code": "123456"},
    "tanya@nemesis.ec":    {"nombre": "Tanya Vaca",    "rol": "Analista SOC",  "mfa_code": "654321"},
    "fernando@nemesis.ec": {"nombre": "Fernando Y.",   "rol": "Analista SOC",  "mfa_code": "112233"},
}


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
