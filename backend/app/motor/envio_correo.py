"""
envio_correo.py – Envío de correos reales (invitaciones de usuario) vía Gmail.

Vive en la raíz del proyecto, junto a app_v2.py.

Usa una cuenta de Gmail con "contraseña de aplicación" (no la contraseña
normal de la cuenta) — se genera en:
https://myaccount.google.com/apppasswords
(requiere verificación en 2 pasos activada en esa cuenta de Gmail).

La configuración se guarda en data/config_email.json, igual que la API key
de Gemini: gestionada solo por un Administrador desde el dashboard, nunca
expuesta a otros roles.
"""

import os
import json
import smtplib
import logging
from email.mime.text import MIMEText

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # backend/
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_PATH = os.path.join(DATA_DIR, "config_email.json")

os.makedirs(DATA_DIR, exist_ok=True)

logger = logging.getLogger("NEMESIS-CORREO")


def obtener_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def guardar_config(gmail_user: str, gmail_app_password: str):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump({"gmail_user": gmail_user, "gmail_app_password": gmail_app_password}, f)


def correo_configurado() -> bool:
    c = obtener_config()
    return bool(c.get("gmail_user") and c.get("gmail_app_password"))


def _enviar(destinatario: str, asunto: str, cuerpo_html: str):
    config = obtener_config()
    if not config.get("gmail_user") or not config.get("gmail_app_password"):
        return False, "El envío de correo no está configurado."

    msg = MIMEText(cuerpo_html, "html", "utf-8")
    msg["Subject"] = asunto
    msg["From"] = config["gmail_user"]
    msg["To"] = destinatario

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
            server.login(config["gmail_user"], config["gmail_app_password"])
            server.sendmail(config["gmail_user"], [destinatario], msg.as_string())
        return True, None
    except smtplib.SMTPAuthenticationError:
        return False, "Credenciales de Gmail inválidas (usá una contraseña de aplicación, no la normal)."
    except Exception as e:
        logger.error("Error enviando correo a %s: %s", destinatario, e)
        return False, str(e)


def enviar_invitacion(destinatario: str, nombre: str, link_activacion: str):
    asunto = "🛡️ Bienvenido a Nemesis Cyber Defense"
    cuerpo = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#1a1a1a">
      <div style="background:linear-gradient(135deg,#0062cc,#00aaff);padding:24px;border-radius:10px 10px 0 0;text-align:center">
        <h1 style="color:white;margin:0;font-size:22px">🛡️ Nemesis Cyber Defense</h1>
        <p style="color:#dbeeff;margin:6px 0 0;font-size:13px">Plataforma de monitoreo y detección de intrusiones con IA</p>
      </div>
      <div style="border:1px solid #e0e0e0;border-top:none;border-radius:0 0 10px 10px;padding:24px">
        <p style="font-size:16px">¡Hola {nombre}! 👋</p>
        <p style="line-height:1.6;color:#444">
          Fuiste invitado/a a unirte a <b>Nemesis Cyber Defense</b>, la plataforma
          que usamos para monitorear el tráfico de red en tiempo real y detectar
          posibles amenazas de seguridad con modelos de inteligencia artificial.
        </p>
        <p style="line-height:1.6;color:#444">
          Para activar tu cuenta vas a necesitar 2 minutos: vas a crear una
          contraseña y configurar la verificación en dos pasos (MFA) con tu
          app autenticadora (Google Authenticator, Authy, o similar).
        </p>
        <p style="margin:28px 0;text-align:center">
          <a href="{link_activacion}" style="background:#0062cc;color:white;
            padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:bold;
            display:inline-block">
            Activar mi cuenta →
          </a>
        </p>
        <p style="color:#888;font-size:12px;border-top:1px solid #eee;padding-top:14px">
          Este enlace expira en 24 horas. Si no esperabas esta invitación,
          podés ignorar este correo con total tranquilidad.
        </p>
      </div>
    </div>
    """
    return _enviar(destinatario, asunto, cuerpo)


def enviar_recuperacion(destinatario: str, nombre: str, link_recuperacion: str):
    asunto = "🔑 Recuperar tu contraseña — Nemesis Cyber Defense"
    cuerpo = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#1a1a1a">
      <div style="background:linear-gradient(135deg,#cc6600,#ffaa00);padding:24px;border-radius:10px 10px 0 0;text-align:center">
        <h1 style="color:white;margin:0;font-size:22px">🔑 Recuperar contraseña</h1>
        <p style="color:#fff3e0;margin:6px 0 0;font-size:13px">Nemesis Cyber Defense</p>
      </div>
      <div style="border:1px solid #e0e0e0;border-top:none;border-radius:0 0 10px 10px;padding:24px">
        <p style="font-size:16px">Hola {nombre},</p>
        <p style="line-height:1.6;color:#444">
          Recibimos una solicitud para restablecer tu contraseña. Vas a necesitar
          tu app autenticadora a mano para confirmar el cambio.
        </p>
        <p style="margin:28px 0;text-align:center">
          <a href="{link_recuperacion}" style="background:#cc6600;color:white;
            padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:bold;
            display:inline-block">
            Restablecer mi contraseña →
          </a>
        </p>
        <p style="color:#888;font-size:12px;border-top:1px solid #eee;padding-top:14px">
          Este enlace expira en 1 hora. Si no fuiste vos quien pidió esto,
          podés ignorar este correo — tu contraseña actual sigue siendo válida.
        </p>
      </div>
    </div>
    """
    return _enviar(destinatario, asunto, cuerpo)


def enviar_reset_mfa(destinatario: str, nombre: str, link_reset: str):
    asunto = "📱 Tu verificación en dos pasos fue reiniciada — Nemesis Cyber Defense"
    cuerpo = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#1a1a1a">
      <div style="background:linear-gradient(135deg,#6600cc,#aa66ff);padding:24px;border-radius:10px 10px 0 0;text-align:center">
        <h1 style="color:white;margin:0;font-size:22px">📱 Reconfigurar tu MFA</h1>
        <p style="color:#f0e6ff;margin:6px 0 0;font-size:13px">Nemesis Cyber Defense</p>
      </div>
      <div style="border:1px solid #e0e0e0;border-top:none;border-radius:0 0 10px 10px;padding:24px">
        <p style="font-size:16px">Hola {nombre},</p>
        <p style="line-height:1.6;color:#444">
          Un administrador reinició tu verificación en dos pasos (por ejemplo,
          porque perdiste el acceso a tu teléfono anterior). Tu método anterior
          ya no es válido — necesitás configurar uno nuevo para poder ingresar.
        </p>
        <p style="margin:28px 0;text-align:center">
          <a href="{link_reset}" style="background:#6600cc;color:white;
            padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:bold;
            display:inline-block">
            Configurar mi nuevo MFA →
          </a>
        </p>
        <p style="color:#888;font-size:12px;border-top:1px solid #eee;padding-top:14px">
          Este enlace expira en 24 horas. Tu contraseña no cambió, solo el MFA.
        </p>
      </div>
    </div>
    """
    return _enviar(destinatario, asunto, cuerpo)