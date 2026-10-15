"""Corrección de seguridad: las cuentas demo (código MFA fijo, sin contraseña) NO deben existir
en un despliegue expuesto a internet. Solo se habilitan con NEMESIS_CUENTAS_DEMO=true."""
from datetime import datetime, timedelta

from tests.conftest import crear_usuario_activo, iniciar_sesion_http


def test_cuentas_demo_deshabilitadas_por_defecto(cliente):
    r = cliente.post("/api/auth/check-email", json={"email": "admin@nemesis.ec"})
    assert r.json() == {"ok": False}
    assert "123456" not in r.text, "el servidor jamás debe revelar un código MFA"
    r = cliente.post("/api/auth/verify-mfa", json={"email": "admin@nemesis.ec", "password": "", "code": "123456"})
    assert r.json() == {"ok": False}
    assert "set-cookie" not in r.headers


def test_con_la_bandera_activa_la_cuenta_demo_funciona(cliente, monkeypatch):
    monkeypatch.setenv("NEMESIS_CUENTAS_DEMO", "true")
    assert cliente.post("/api/auth/check-email", json={"email": "admin@nemesis.ec"}).json()["tipo"] == "demo"
    r = cliente.post("/api/auth/verify-mfa", json={"email": "admin@nemesis.ec", "password": "", "code": "123456"})
    assert r.json() == {"ok": True}


def test_sesion_demo_deja_de_valer_si_se_deshabilitan_las_cuentas_demo(cliente, monkeypatch):
    monkeypatch.setenv("NEMESIS_CUENTAS_DEMO", "true")
    r = cliente.post("/api/auth/verify-mfa", json={"email": "admin@nemesis.ec", "password": "", "code": "123456"})
    cliente.cookies.set("nemesis_session", r.headers["set-cookie"].split("nemesis_session=")[1].split(";")[0])
    assert cliente.get("/api/auth/estado").status_code == 200
    monkeypatch.setenv("NEMESIS_CUENTAS_DEMO", "false")
    assert cliente.get("/api/auth/estado").status_code == 401


def test_el_archivo_de_sesiones_no_guarda_el_codigo_mfa(cliente, monkeypatch, entorno):
    monkeypatch.setenv("NEMESIS_CUENTAS_DEMO", "true")
    cliente.post("/api/auth/verify-mfa", json={"email": "admin@nemesis.ec", "password": "", "code": "123456"})
    assert "123456" not in (entorno / "sesiones.json").read_text()


def test_administrador_inicial_se_crea_y_se_activa_por_el_flujo_normal(entorno):
    from app.motor import base_datos, gestion_usuarios as g
    link = g.asegurar_administrador_inicial("jefe@empresa.ec", "Jefe", "https://front.example")
    assert link.startswith("https://front.example/activar.html?token=")
    u = base_datos.obtener_usuario_por_email("jefe@empresa.ec")
    assert u["rol"] == "Administrador" and u["activo"] is False
    # Idempotente: si la invitación se perdió, se regenera el token sin duplicar el usuario.
    link2 = g.asegurar_administrador_inicial("jefe@empresa.ec", "Jefe", "https://front.example")
    assert link2 != link and len(base_datos.listar_usuarios()) == 1
    # Una vez activo, ya no se genera nada.
    import pyotp
    datos, _ = g.preparar_activacion(link2.split("token=")[1])
    assert g.confirmar_activacion(datos["usuario_id"], datos["secreto"], pyotp.TOTP(datos["secreto"]).now(),
                                  "ClaveSegura123", "ClaveSegura123")[0]
    assert g.asegurar_administrador_inicial("jefe@empresa.ec", "Jefe", "https://front.example") is None
