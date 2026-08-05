"""
gestion_usuarios.py – Usuarios reales con roles y MFA por TOTP.

Vive en la raíz del proyecto, junto a app_v2.py.

Reemplaza el diccionario fijo USUARIOS_DEMO por usuarios reales guardados en
la base de datos (src/database_manager.py), con:

- Invitación por correo real (Gmail, vía envio_correo.py) cuando un
  Administrador agrega a alguien.
- Activación de cuenta con TOTP (Google Authenticator / Authy / cualquier
  app compatible con el estándar RFC 6238) — el usuario escanea un QR una
  sola vez, y desde ahí genera sus propios códigos de 6 dígitos.
- Gestión de roles: un Administrador puede asignar/cambiar el rol de cada
  usuario (Administrador / Analista SOC), activarlo o desactivarlo.

Los usuarios DEMO originales (admin@nemesis.ec, etc.) se mantienen como
respaldo de arranque en app_v2.py, para no quedar bloqueado del dashboard
la primera vez, antes de invitarte a vos mismo con tu correo real.
"""

import os
import secrets
import hashlib
import logging
from datetime import datetime, timedelta

import pyotp
import qrcode
import io
import base64

from app.motor.base_datos import (
    crear_usuario_invitado, obtener_usuario_por_email, obtener_usuario_por_token,
    activar_usuario, listar_usuarios, actualizar_rol_usuario,
    actualizar_estado_usuario, eliminar_usuario,
    crear_token_accion, limpiar_token, incrementar_intentos_fallidos,
    resetear_intentos_fallidos, actualizar_password_usuario,
    limpiar_totp_secret, guardar_nuevo_totp,
)

logger = logging.getLogger("NEMESIS-USUARIOS")

ROLES_VALIDOS = ("Administrador", "Analista SOC")
NOMBRE_EMISOR_TOTP = "Nemesis Cyber Defense"
PBKDF2_ITERACIONES = 200_000
MAX_INTENTOS_FALLIDOS = 5


def _hash_password(password: str) -> str:
    """
    Hashea la contraseña con PBKDF2-SHA256 (librería estándar de Python,
    sin dependencias extra). Formato guardado: 'salt_hex$hash_hex'.
    """
    salt = secrets.token_hex(16)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                    bytes.fromhex(salt), PBKDF2_ITERACIONES)
    return f"{salt}${derivado.hex()}"


def _verificar_password(password: str, hash_guardado: str) -> bool:
    if not hash_guardado or "$" not in hash_guardado:
        return False
    salt, hash_esperado = hash_guardado.split("$", 1)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                    bytes.fromhex(salt), PBKDF2_ITERACIONES)
    return secrets.compare_digest(derivado.hex(), hash_esperado)


def invitar_usuario(email: str, nombre: str, rol: str, url_base: str):
    """
    Crea el registro de usuario (inactivo) con un token de invitación de
    24 horas, y envía el correo real con el link de activación.
    Retorna (ok: bool, mensaje: str).
    """
    email = email.lower().strip()
    if rol not in ROLES_VALIDOS:
        return False, f"Rol inválido. Debe ser uno de: {', '.join(ROLES_VALIDOS)}"
    if obtener_usuario_por_email(email):
        return False, "Ya existe un usuario con ese correo."

    token = secrets.token_urlsafe(24)
    expira = (datetime.now() + timedelta(hours=24)).isoformat()
    crear_usuario_invitado(email, nombre, rol, token, expira)

    link = f"{url_base.rstrip('/')}/activar.html?token={token}"

    from app.motor.envio_correo import enviar_invitacion, correo_configurado
    if not correo_configurado():
        logger.warning("Correo no configurado. Link de activación para %s: %s", email, link)
        return True, (f"Usuario creado, pero el envío de correo no está configurado. "
                       f"Compartí este link manualmente: {link}")

    ok, error = enviar_invitacion(email, nombre, link)
    if not ok:
        logger.error("Fallo al enviar invitación a %s: %s", email, error)
        return True, (f"Usuario creado, pero no se pudo enviar el correo ({error}). "
                       f"Compartí este link manualmente: {link}")
    return True, f"Invitación enviada a {email}."


def preparar_activacion(token: str):
    """
    Valida el token de invitación y genera un secreto TOTP NUEVO (aún no
    guardado) junto con su QR en base64, listo para mostrar en pantalla.
    El secreto se confirma recién en confirmar_activacion(), tras validar
    que el usuario efectivamente escaneó bien el QR.
    """
    usuario = obtener_usuario_por_token(token)
    if not usuario:
        return None, "El link de activación no es válido."
    if usuario["activo"]:
        return None, "Esta cuenta ya fue activada. Iniciá sesión normalmente."
    if datetime.now() > datetime.fromisoformat(usuario["token_expira"]):
        return None, "El link de activación expiró (24 horas). Pedile a un administrador que te invite de nuevo."

    secreto = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secreto).provisioning_uri(name=usuario["email"], issuer_name=NOMBRE_EMISOR_TOTP)

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("ascii")

    return {
        "usuario_id": usuario["id"], "email": usuario["email"], "nombre": usuario["nombre"],
        "secreto": secreto, "qr_base64": qr_base64,
    }, None


def confirmar_activacion(usuario_id: int, secreto: str, codigo: str, password: str, password_confirmacion: str):
    """Valida contraseña + primer código TOTP, y si ambos son correctos, activa la cuenta con los DOS factores."""
    if not password or len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if password != password_confirmacion:
        return False, "Las contraseñas no coinciden."

    totp = pyotp.TOTP(secreto)
    if not totp.verify(codigo, valid_window=1):
        return False, "El código no es correcto. Verificá la hora de tu teléfono y probá de nuevo."

    activar_usuario(usuario_id, secreto, _hash_password(password))
    return True, "Cuenta activada correctamente."


def verificar_password_usuario(email: str, password: str) -> dict:
    """
    Verifica la contraseña y lleva la cuenta de intentos fallidos consecutivos.
    Retorna {ok, intentos, mostrar_recuperar} — a partir del 5to intento fallido
    consecutivo, mostrar_recuperar=True para que el frontend ofrezca el link
    de "olvidé mi contraseña".
    """
    u = obtener_usuario(email)
    if not u or not u.get("activo") or not u.get("password_hash"):
        return {"ok": False, "intentos": 0, "mostrar_recuperar": False}

    if _verificar_password(password, u["password_hash"]):
        resetear_intentos_fallidos(email)
        return {"ok": True, "intentos": 0, "mostrar_recuperar": False}

    intentos = incrementar_intentos_fallidos(email)
    return {"ok": False, "intentos": intentos, "mostrar_recuperar": intentos >= MAX_INTENTOS_FALLIDOS}


def verificar_login(email: str, password: str, codigo: str):
    """
    Verifica el login de DOS FACTORES de un usuario real ya activado:
    1) la contraseña (algo que sabe) y 2) el código TOTP (algo que tiene).
    Ambos deben ser correctos. (El conteo de intentos fallidos de contraseña
    se maneja en verificar_password_usuario, en el paso previo del login;
    esta función es la verificación final antes de crear la sesión.)
    """
    usuario_full = obtener_usuario(email)
    if not usuario_full or not usuario_full.get("activo") or not usuario_full.get("totp_secret"):
        return False
    if not _verificar_password(password, usuario_full.get("password_hash", "")):
        return False
    totp = pyotp.TOTP(usuario_full["totp_secret"])
    return totp.verify(codigo, valid_window=1)


# ─── Recuperación de contraseña (el usuario todavía tiene su MFA) ────────────

def solicitar_recuperacion(email: str, url_base: str):
    """
    Genera un link de recuperación de 1 hora y lo envía por correo. Requiere
    que el usuario todavía tenga acceso a su app autenticadora (se le va a
    pedir el código TOTP para confirmar el cambio de contraseña) — si perdió
    también el teléfono, un Administrador debe resetearle el MFA primero.
    """
    email = email.lower().strip()
    u = obtener_usuario(email)
    if not u or not u.get("activo"):
        # No revelamos si el correo existe o no, por seguridad.
        return True, "Si el correo está registrado, vas a recibir instrucciones para recuperar tu contraseña."

    token = secrets.token_urlsafe(24)
    expira = (datetime.now() + timedelta(hours=1)).isoformat()
    crear_token_accion(u["id"], "reset_password", token, expira)

    link = f"{url_base.rstrip('/')}/recuperar.html?token={token}"

    from app.motor.envio_correo import enviar_recuperacion, correo_configurado
    if not correo_configurado():
        logger.warning("Correo no configurado. Link de recuperación para %s: %s", email, link)
        return True, f"El correo no está configurado. Compartí este link manualmente: {link}"

    ok, error = enviar_recuperacion(email, u["nombre"], link)
    if not ok:
        logger.error("Fallo al enviar recuperación a %s: %s", email, error)
        return True, f"No se pudo enviar el correo ({error}). Compartí este link manualmente: {link}"
    return True, "Si el correo está registrado, vas a recibir instrucciones para recuperar tu contraseña."


def preparar_recuperacion(token: str):
    u = obtener_usuario_por_token(token)
    if not u or u.get("token_tipo") != "reset_password":
        return None, "El link de recuperación no es válido."
    if datetime.now() > datetime.fromisoformat(u["token_expira"]):
        return None, "El link de recuperación expiró (1 hora). Solicitá uno nuevo."
    return {"usuario_id": u["id"], "email": u["email"], "nombre": u["nombre"]}, None


def confirmar_recuperacion(token: str, password: str, password_confirmacion: str, codigo: str):
    datos, error = preparar_recuperacion(token)
    if error:
        return False, error
    if not password or len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if password != password_confirmacion:
        return False, "Las contraseñas no coinciden."

    usuario_full = obtener_usuario(datos["email"])
    if not usuario_full.get("totp_secret"):
        return False, ("No tenés un MFA configurado (fue reseteado). "
                        "Pedile a un Administrador el link para reconfigurarlo primero.")
    totp = pyotp.TOTP(usuario_full["totp_secret"])
    if not totp.verify(codigo, valid_window=1):
        return False, "El código de tu app autenticadora no es correcto."

    actualizar_password_usuario(datos["usuario_id"], _hash_password(password))
    return True, "Contraseña actualizada correctamente."


# ─── Reset de MFA por un Administrador (ej. teléfono perdido) ────────────────

def admin_resetear_mfa(usuario_id: int, url_base: str):
    """
    Invalida el MFA actual DE INMEDIATO (por si el teléfono perdido cae en
    manos de alguien más) y envía un link para que el usuario configure uno
    nuevo escaneando un QR fresco. No toca la contraseña.
    """
    from app.motor.base_datos import listar_usuarios as _listar  # evitar import circular innecesario
    usuarios = _listar()
    usuario = next((u for u in usuarios if u["id"] == usuario_id), None)
    if not usuario:
        return False, "Usuario no encontrado."
    if not usuario["activo"]:
        return False, "Ese usuario todavía no activó su cuenta."

    limpiar_totp_secret(usuario_id)

    token = secrets.token_urlsafe(24)
    expira = (datetime.now() + timedelta(hours=24)).isoformat()
    crear_token_accion(usuario_id, "reset_mfa", token, expira)

    link = f"{url_base.rstrip('/')}/reconfigurar-mfa.html?token={token}"

    from app.motor.envio_correo import enviar_reset_mfa, correo_configurado
    if not correo_configurado():
        logger.warning("Correo no configurado. Link de reset de MFA para %s: %s", usuario["email"], link)
        return True, (f"MFA reseteado. El correo no está configurado — "
                       f"compartí este link manualmente: {link}")

    ok, error = enviar_reset_mfa(usuario["email"], usuario["nombre"], link)
    if not ok:
        logger.error("Fallo al enviar reset de MFA a %s: %s", usuario["email"], error)
        return True, f"MFA reseteado, pero no se pudo enviar el correo ({error}). Link: {link}"
    return True, f"MFA reseteado. Se envió un correo a {usuario['email']} con el link para reconfigurarlo."


def preparar_reset_mfa(token: str):
    u = obtener_usuario_por_token(token)
    if not u or u.get("token_tipo") != "reset_mfa":
        return None, "El link no es válido."
    if datetime.now() > datetime.fromisoformat(u["token_expira"]):
        return None, "El link expiró (24 horas). Pedile a un administrador que lo genere de nuevo."

    secreto = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secreto).provisioning_uri(name=u["email"], issuer_name=NOMBRE_EMISOR_TOTP)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("ascii")

    return {"usuario_id": u["id"], "email": u["email"], "nombre": u["nombre"],
            "secreto": secreto, "qr_base64": qr_base64}, None


def confirmar_reset_mfa(usuario_id: int, secreto: str, codigo: str):
    totp = pyotp.TOTP(secreto)
    if not totp.verify(codigo, valid_window=1):
        return False, "El código no es correcto. Verificá la hora de tu teléfono y probá de nuevo."
    guardar_nuevo_totp(usuario_id, secreto)
    return True, "MFA reconfigurado correctamente."


def obtener_usuario(email: str):
    return obtener_usuario_por_email(email)


def usuario_existe_activo(email: str) -> bool:
    u = obtener_usuario_por_email(email)
    return bool(u and u["activo"])


def usuario_existe(email: str) -> bool:
    return obtener_usuario_por_email(email) is not None