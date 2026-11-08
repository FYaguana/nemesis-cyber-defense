"""Correo de invitaciones (Gmail por SMTP): configuración por entorno y mensajes de error claros."""
import smtplib

import pytest

from app.motor import envio_correo as ec

VARIABLES = ("NEMESIS_GMAIL_USER", "NEMESIS_GMAIL_APP_PASSWORD", "NEMESIS_PERMITIR_SMTP_EN_NUBE",
             "RENDER", "DYNO", "K_SERVICE", "FLY_APP_NAME", "RAILWAY_ENVIRONMENT")


@pytest.fixture
def aislado(tmp_path, monkeypatch):
    """Sin configuración guardada y sin variables de entorno de correo ni de nube."""
    monkeypatch.setattr(ec, "CONFIG_PATH", str(tmp_path / "config_email.json"))
    for variable in VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    return tmp_path


def smtp_falso(falla_en=None, error=None, enviados=None):
    """Sustituto de smtplib.SMTP_SSL. `falla_en` = 'conectar' | 'login'."""
    class SMTPFalso:
        def __init__(self, host, puerto, timeout=None):
            assert (host, puerto) == ("smtp.gmail.com", 465)
            if falla_en == "conectar":
                raise error

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def login(self, usuario, clave):
            if falla_en == "login":
                raise error

        def sendmail(self, origen, destinos, mensaje):
            if enviados is not None:
                enviados.append((origen, destinos, mensaje))
    return SMTPFalso


def test_sin_nada_el_correo_no_esta_configurado(aislado):
    assert ec.correo_configurado() is False
    ok, mensaje = ec._enviar("a@b.com", "x", "<p>x</p>")
    assert ok is False and "no está configurado" in mensaje


def test_las_variables_de_entorno_configuran_el_correo(aislado, monkeypatch):
    monkeypatch.setenv("NEMESIS_GMAIL_USER", "envia@gmail.com")
    monkeypatch.setenv("NEMESIS_GMAIL_APP_PASSWORD", "abcd efgh ijkl mnop")
    assert ec.correo_configurado() is True
    assert ec.obtener_config() == {"gmail_user": "envia@gmail.com", "gmail_app_password": "abcd efgh ijkl mnop"}


def test_variables_incompletas_no_cuentan(aislado, monkeypatch):
    monkeypatch.setenv("NEMESIS_GMAIL_USER", "envia@gmail.com")
    assert ec.correo_configurado() is False


def test_lo_guardado_desde_la_pantalla_tiene_prioridad_sobre_el_entorno(aislado, monkeypatch):
    monkeypatch.setenv("NEMESIS_GMAIL_USER", "entorno@gmail.com")
    monkeypatch.setenv("NEMESIS_GMAIL_APP_PASSWORD", "clave-entorno")
    ec.guardar_config("pantalla@gmail.com", "clave-pantalla")
    assert ec.obtener_config()["gmail_user"] == "pantalla@gmail.com"


def test_un_archivo_vacio_cae_a_las_variables_de_entorno(aislado, monkeypatch):
    """Caso Docker local: data/config_email.json existe pero está vacío."""
    ec.guardar_config("", "")
    monkeypatch.setenv("NEMESIS_GMAIL_USER", "envia@gmail.com")
    monkeypatch.setenv("NEMESIS_GMAIL_APP_PASSWORD", "clave")
    assert ec.obtener_config()["gmail_user"] == "envia@gmail.com"


def test_envio_exitoso(aislado, monkeypatch):
    enviados = []
    ec.guardar_config("envia@gmail.com", "clave")
    monkeypatch.setattr(ec.smtplib, "SMTP_SSL", smtp_falso(enviados=enviados))
    assert ec._enviar("destino@correo.com", "Asunto", "<p>hola</p>") == (True, None)
    assert enviados[0][0] == "envia@gmail.com" and enviados[0][1] == ["destino@correo.com"]


def test_en_la_nube_no_se_intenta_el_envio_y_se_explica_el_bloqueo(aislado, monkeypatch):
    """Antes cada invitación esperaba 20 s a que venciera la conexión y mostraba '[Errno 101]'."""
    monkeypatch.setenv("RENDER", "true")
    ec.guardar_config("envia@gmail.com", "clave")
    intentos = []

    class NoDebeLlamarse:
        def __init__(self, *args, **kwargs):
            intentos.append(1)
    monkeypatch.setattr(ec.smtplib, "SMTP_SSL", NoDebeLlamarse)
    ok, mensaje = ec._enviar("d@c.com", "x", "<p>x</p>")
    assert ok is False and intentos == []
    assert "bloquea el correo saliente" in mensaje and "propio equipo" in mensaje and "Errno" not in mensaje


def test_en_un_plan_de_pago_se_puede_forzar_el_envio_desde_la_nube(aislado, monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("NEMESIS_PERMITIR_SMTP_EN_NUBE", "true")
    enviados = []
    ec.guardar_config("envia@gmail.com", "clave")
    monkeypatch.setattr(ec.smtplib, "SMTP_SSL", smtp_falso(enviados=enviados))
    assert ec._enviar("d@c.com", "x", "<p>x</p>") == (True, None) and len(enviados) == 1


def test_fuera_de_la_nube_el_fallo_de_red_sugiere_probar_otra_red(aislado, monkeypatch):
    ec.guardar_config("envia@gmail.com", "clave")
    monkeypatch.setattr(ec.smtplib, "SMTP_SSL", smtp_falso("conectar", OSError(101, "Network is unreachable")))
    ok, mensaje = ec._enviar("d@c.com", "x", "<p>x</p>")
    assert ok is False and "465" in mensaje and "otra red" in mensaje and "bloquea el correo saliente" not in mensaje


@pytest.mark.parametrize("en_la_nube", [True, False])
def test_credenciales_invalidas_conservan_su_mensaje_propio(aislado, monkeypatch, en_la_nube):
    """SMTPException hereda de OSError: no debe confundirse con un fallo de red."""
    if en_la_nube:
        monkeypatch.setenv("RENDER", "true")
        monkeypatch.setenv("NEMESIS_PERMITIR_SMTP_EN_NUBE", "true")   # plan que sí permite SMTP
    ec.guardar_config("envia@gmail.com", "mala")
    monkeypatch.setattr(ec.smtplib, "SMTP_SSL", smtp_falso("login", smtplib.SMTPAuthenticationError(535, b"no")))
    ok, mensaje = ec._enviar("d@c.com", "x", "<p>x</p>")
    assert ok is False and "contraseña de aplicación" in mensaje


def test_un_error_de_smtp_en_la_nube_no_se_confunde_con_el_bloqueo(aislado, monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("NEMESIS_PERMITIR_SMTP_EN_NUBE", "true")
    ec.guardar_config("envia@gmail.com", "clave")
    monkeypatch.setattr(ec.smtplib, "SMTP_SSL", smtp_falso("login", smtplib.SMTPServerDisconnected("cerrada")))
    ok, mensaje = ec._enviar("d@c.com", "x", "<p>x</p>")
    assert ok is False and "bloquea el correo saliente" not in mensaje
