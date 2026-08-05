"""
repositorio_configuracion_ia.py -- Acceso a la configuración persistida de
la integración con Gemini (la API key). Responsabilidad única: leer/escribir
ese archivo de configuración. No valida, no decide nada de negocio.
"""

import json
import os

_DIRECTORIO_RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
_RUTA_CONFIGURACION = os.path.join(_DIRECTORIO_RAIZ, "data", "config_ia.json")


def obtener_clave_api_gemini() -> str | None:
    """Busca la API key primero en la variable de entorno GEMINI_API_KEY
    (recomendado en despliegues con Docker/producción) y, si no existe,
    en el archivo de configuración persistido desde el panel de administración."""
    clave_desde_entorno = os.environ.get("GEMINI_API_KEY")
    if clave_desde_entorno:
        return clave_desde_entorno

    if not os.path.exists(_RUTA_CONFIGURACION):
        return None
    try:
        with open(_RUTA_CONFIGURACION, "r", encoding="utf-8") as archivo:
            return json.load(archivo).get("gemini_api_key")
    except (json.JSONDecodeError, OSError):
        return None


def guardar_clave_api_gemini(clave_api: str) -> None:
    os.makedirs(os.path.dirname(_RUTA_CONFIGURACION), exist_ok=True)
    with open(_RUTA_CONFIGURACION, "w", encoding="utf-8") as archivo:
        json.dump({"gemini_api_key": clave_api}, archivo)


def hay_clave_api_configurada() -> bool:
    return bool(obtener_clave_api_gemini())
