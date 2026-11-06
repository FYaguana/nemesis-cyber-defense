"""Sección 4.6 de la tesis: PBKDF2 200,000 iteraciones con sal de 16 bytes, TOTP (RFC 6238),
sesión con token de 256 bits, cookie HttpOnly + SameSite=Lax de 8 horas."""
import hashlib
import re
from datetime import datetime, timedelta

import pyotp
from tests.conftest import crear_usuario_activo, iniciar_sesion_http


def test_hash_pbkdf2_200000_iteraciones_y_sal_de_16_bytes(entorno):
    from app.motor import gestion_usuarios as g
    assert g.PBKDF2_ITERACIONES == 200_000
    guardado = g._hash_password("MiClave-Segura-1")
    sal_hex, hash_hex = guardado.split("$")
    assert len(bytes.fromhex(sal_hex)) == 16
    esperado = hashlib.pbkdf2_hmac("sha256", b"MiClave-Segura-1", bytes.fromhex(sal_hex), 200_000).hex()
    assert hash_hex == esperado
    assert g._hash_password("MiClave-Segura-1") != guardado, "cada usuario/hash debe tener su propia sal"
    assert g._verificar_password("MiClave-Segura-1", guardado)
    assert not g._verificar_password("otra-clave", guardado)


def test_activacion_rechaza_codigo_totp_incorrecto(entorno):
    import secrets
    from app.motor import base_datos, gestion_usuarios as g
    token = secrets.token_urlsafe(16)
    base_datos.crear_usuario_invitado("x@test.ec", "X", "Analista SOC", token,
                                      (datetime.now() + timedelta(hours=1)).isoformat())
    datos, _ = g.preparar_activacion(token)
    ok, _ = g.confirmar_activacion(datos["usuario_id"], datos["secreto"], "000000", "ClaveSegura123", "ClaveSegura123")
    assert ok is False
    assert not g.usuario_existe_activo("x@test.ec")


def test_login_exige_los_dos_factores(entorno):
    from app.motor import gestion_usuarios as g
    u = crear_usuario_activo()
    totp = pyotp.TOTP(u["secreto"]).now()
    assert g.verificar_login(u["email"], u["password"], totp)
    assert not g.verificar_login(u["email"], u["password"], "000000"), "contraseña sola no basta"
    assert not g.verificar_login(u["email"], "ContraseñaIncorrecta1", totp), "TOTP solo no basta"


def test_a_los_5_intentos_fallidos_se_ofrece_recuperar(entorno):
    from app.motor import gestion_usuarios as g
    u = crear_usuario_activo()
    resultados = [g.verificar_password_usuario(u["email"], "mala") for _ in range(5)]
    assert not any(r["ok"] for r in resultados)
    assert [r["mostrar_recuperar"] for r in resultados] == [False, False, False, False, True]


def test_recuperacion_de_password_exige_el_segundo_factor(entorno):
    import secrets
    from app.motor import base_datos, gestion_usuarios as g
    u = crear_usuario_activo()
    token = secrets.token_urlsafe(16)
    base_datos.crear_token_accion(u["id"], "reset_password", token, (datetime.now() + timedelta(hours=1)).isoformat())
    ok, _ = g.confirmar_recuperacion(token, "NuevaClave12345", "NuevaClave12345", "000000")
    assert ok is False, "sin el TOTP vigente no se debe poder cambiar la contraseña"
    ok, _ = g.confirmar_recuperacion(token, "NuevaClave12345", "NuevaClave12345", pyotp.TOTP(u["secreto"]).now())
    assert ok is True


def test_token_de_sesion_tiene_256_bits_y_expira_en_8_horas(entorno):
    from app.nucleo import gestor_sesiones as gs
    t1 = gs.crear_sesion("a@test.ec", {"nombre": "A", "rol": "Analista SOC"})
    t2 = gs.crear_sesion("a@test.ec", {"nombre": "A", "rol": "Analista SOC"})
    assert t1 != t2 and len(t1) >= 43 and re.fullmatch(r"[A-Za-z0-9_-]+", t1)  # 32 bytes en base64 url-safe
    expira = datetime.fromisoformat(gs._cargar_sesiones()[t1]["expira"])
    assert timedelta(hours=7, minutes=59) < expira - datetime.now() <= timedelta(hours=8)


def test_cookie_de_sesion_httponly_samesite_lax_8_horas(cliente):
    u = crear_usuario_activo()
    r = cliente.post("/api/auth/verify-mfa", json={
        "email": u["email"], "password": u["password"], "code": pyotp.TOTP(u["secreto"]).now()})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "max-age=28800" in cookie
    assert "secure" in cookie, "por defecto (producción) la cookie debe marcarse Secure"
