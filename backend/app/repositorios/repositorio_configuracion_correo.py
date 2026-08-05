"""
repositorio_configuracion_correo.py -- Acceso a la configuración de envío
de correo (cuenta de Gmail + contraseña de aplicación), delegando al motor
ya probado en app.motor.envio_correo.
"""

from app.motor.envio_correo import obtener_config, guardar_config, correo_configurado


def obtener_configuracion_correo() -> dict:
    return obtener_config()


def guardar_configuracion_correo(correo_gmail: str, contrasena_aplicacion: str) -> None:
    guardar_config(correo_gmail, contrasena_aplicacion)


def hay_correo_configurado() -> bool:
    return correo_configurado()
