"""
seguridad.py -- Verificación de sesión reutilizable como dependencia de
FastAPI (Depends). Mantiene la misma lógica de sesiones persistidas en
data/sesiones.json que ya usaba el sistema, pero expuesta como una
dependencia inyectable en vez de una función llamada a mano en cada endpoint.
"""

import json
from datetime import datetime

from fastapi import Request, HTTPException, Depends

from app.nucleo.gestor_sesiones import RUTA_SESIONES
import os


class SesionUsuario:
    def __init__(self, email: str, nombre: str, rol: str):
        self.email = email
        self.nombre = nombre
        self.rol = rol

    @property
    def es_administrador(self) -> bool:
        return self.rol == "Administrador"


def _cargar_sesiones_desde_disco() -> dict:
    if not os.path.exists(RUTA_SESIONES):
        return {}
    try:
        with open(RUTA_SESIONES, "r", encoding="utf-8") as archivo:
            return json.load(archivo)
    except (json.JSONDecodeError, OSError):
        return {}


def requiere_sesion_autenticada(peticion: Request) -> SesionUsuario:
    """Dependencia de FastAPI: exige una cookie de sesión válida y no vencida."""
    token = peticion.cookies.get("nemesis_session")
    sesiones = _cargar_sesiones_desde_disco()
    sesion_guardada = sesiones.get(token) if token else None

    if not sesion_guardada:
        raise HTTPException(status_code=401, detail="No autorizado")

    if datetime.now() > datetime.fromisoformat(sesion_guardada["expira"]):
        raise HTTPException(status_code=401, detail="La sesión expiró")

    usuario = sesion_guardada["usuario"]
    return SesionUsuario(email=sesion_guardada["email"], nombre=usuario["nombre"], rol=usuario["rol"])


def requiere_rol_administrador(sesion: SesionUsuario = Depends(requiere_sesion_autenticada)) -> SesionUsuario:
    """Dependencia de FastAPI: además de sesión válida, exige rol Administrador."""
    if not sesion.es_administrador:
        raise HTTPException(status_code=403, detail="Esta acción requiere rol Administrador")
    return sesion
