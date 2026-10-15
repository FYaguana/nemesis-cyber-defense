"""Fixtures compartidas. Cada prueba corre con una base de datos y un archivo de sesiones
TEMPORALES: ninguna prueba toca data/nemesis.db ni data/sesiones.json reales."""
import os
import secrets
import sys
from datetime import datetime, timedelta

import pyotp
import pytest

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ["NEMESIS_MONITOREO_AUTOINICIO"] = "false"  # el monitoreo no debe arrancar en pruebas
DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DIRECTORIO_BACKEND)


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    from app.motor import base_datos
    from app.nucleo import gestor_sesiones, seguridad
    monkeypatch.setattr(base_datos, "DB_PATH", str(tmp_path / "test.db"))
    ruta_sesiones = str(tmp_path / "sesiones.json")
    monkeypatch.setattr(gestor_sesiones, "RUTA_SESIONES", ruta_sesiones)
    monkeypatch.setattr(seguridad, "RUTA_SESIONES", ruta_sesiones)
    monkeypatch.delenv("NEMESIS_CUENTAS_DEMO", raising=False)
    base_datos.init_db()
    return tmp_path


@pytest.fixture
def cliente(entorno):
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)  # sin 'with': no ejecuta el ciclo de vida (no inicia el monitoreo)


def crear_usuario_activo(email="analista@test.ec", rol="Analista SOC", password="ClaveSegura123"):
    """Crea un usuario real y lo activa por el flujo normal (contraseña + TOTP)."""
    from app.motor import base_datos, gestion_usuarios
    token = secrets.token_urlsafe(16)
    base_datos.crear_usuario_invitado(email, "Usuario Prueba", rol, token,
                                      (datetime.now() + timedelta(hours=1)).isoformat())
    datos, error = gestion_usuarios.preparar_activacion(token)
    assert error is None, error
    ok, mensaje = gestion_usuarios.confirmar_activacion(
        datos["usuario_id"], datos["secreto"], pyotp.TOTP(datos["secreto"]).now(), password, password)
    assert ok, mensaje
    return {"email": email, "password": password, "secreto": datos["secreto"], "id": datos["usuario_id"]}


def iniciar_sesion_http(cliente, usuario) -> None:
    """Login HTTP completo (contraseña + TOTP) y deja la cookie en el cliente."""
    r = cliente.post("/api/auth/verify-mfa", json={
        "email": usuario["email"], "password": usuario["password"],
        "code": pyotp.TOTP(usuario["secreto"]).now()})
    assert r.json().get("ok") is True
    cookie = r.cookies.get("nemesis_session") or r.headers["set-cookie"].split("nemesis_session=")[1].split(";")[0]
    cliente.cookies.set("nemesis_session", cookie)
