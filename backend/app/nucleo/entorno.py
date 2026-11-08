"""entorno.py -- Detección del entorno de ejecución, compartida por los módulos que dependen de él."""
import os

# Variables que definen las plataformas cloud más comunes (Render, Heroku, Cloud Run, Fly.io, Railway).
_VARIABLES_NUBE = ("RENDER", "DYNO", "K_SERVICE", "FLY_APP_NAME", "RAILWAY_ENVIRONMENT")


def en_nube() -> bool:
    """True si el backend corre en una plataforma cloud. Allí no hay captura de red real
    y, en los planes gratuitos, tampoco correo saliente por SMTP."""
    return any(os.environ.get(variable) for variable in _VARIABLES_NUBE)


def smtp_disponible() -> bool:
    """¿Puede este despliegue enviar correo por SMTP? En los planes gratuitos de la nube está bloqueado
    (Render: puertos 25, 465 y 587). Quien use un plan de pago puede forzarlo con
    NEMESIS_PERMITIR_SMTP_EN_NUBE=true."""
    if not en_nube():
        return True
    return os.environ.get("NEMESIS_PERMITIR_SMTP_EN_NUBE", "").strip().lower() == "true"
