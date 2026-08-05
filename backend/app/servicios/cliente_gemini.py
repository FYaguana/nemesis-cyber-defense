"""
cliente_gemini.py -- Encapsula toda la comunicación HTTP con la API de
Google Gemini, incluyendo el modo streaming (Server-Sent Events).

Responsabilidad única: enviar el prompt y devolver los fragmentos de texto
a medida que llegan. No sabe nada del dominio (planes de respuesta, features
del modelo de detección, etc.) -- eso vive en el servicio que lo usa.
"""

import json
import logging
from dataclasses import dataclass
from typing import Iterator, Optional

import requests

logger = logging.getLogger("nemesis.cliente_gemini")

MODELO_GEMINI = "gemini-2.5-flash"
URL_BASE_GEMINI = "https://generativelanguage.googleapis.com/v1beta/models"


class ErrorClienteGemini(Exception):
    """Error al comunicarse con la API de Gemini (red, autenticación, etc.)."""

    def __init__(self, mensaje_usuario: str, es_error_autenticacion: bool = False):
        super().__init__(mensaje_usuario)
        self.mensaje_usuario = mensaje_usuario
        self.es_error_autenticacion = es_error_autenticacion


@dataclass(frozen=True)
class UsoTokensGemini:
    tokens_entrada: int
    tokens_salida: int


class ClienteGemini:
    """Cliente HTTP para la API de Gemini, con soporte de respuesta en streaming."""

    def __init__(self, clave_api: str, tiempo_espera_segundos: int = 30):
        self._clave_api = clave_api
        self._tiempo_espera_segundos = tiempo_espera_segundos

    def generar_contenido_en_streaming(self, prompt: str) -> Iterator[str]:
        """
        Envía el prompt a Gemini y va entregando (yield) cada fragmento de
        texto a medida que el modelo lo genera, usando Server-Sent Events.
        El último fragmento entregado siempre incluye el texto completo
        acumulado hasta ese punto (así el llamador puede mostrar el efecto
        de "escritura en vivo" sin tener que reconstruirlo él mismo).
        """
        url = f"{URL_BASE_GEMINI}/{MODELO_GEMINI}:streamGenerateContent"
        cuerpo = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": 3000,
                "thinkingConfig": {"thinkingBudget": 0},
            },
        }

        try:
            respuesta = requests.post(
                url,
                params={"key": self._clave_api, "alt": "sse"},
                headers={"content-type": "application/json"},
                json=cuerpo,
                stream=True,
                timeout=self._tiempo_espera_segundos,
            )
        except requests.RequestException as error:
            raise ErrorClienteGemini(f"Error de conexión con la IA: {error}") from error

        if respuesta.status_code != 200:
            raise self._construir_error_desde_respuesta(respuesta)

        yield from self._leer_eventos_sse(respuesta)

    def _leer_eventos_sse(self, respuesta: requests.Response) -> Iterator[str]:
        texto_acumulado = ""
        for linea in respuesta.iter_lines(decode_unicode=True):
            if not linea or not linea.startswith("data: "):
                continue
            fragmento_json = linea[len("data: "):]
            try:
                evento = json.loads(fragmento_json)
            except json.JSONDecodeError:
                continue

            candidatos = evento.get("candidates", [])
            if not candidatos:
                continue
            partes = candidatos[0].get("content", {}).get("parts", [])
            texto_nuevo = "".join(parte.get("text", "") for parte in partes)
            if texto_nuevo:
                texto_acumulado += texto_nuevo
                yield texto_acumulado

    def _construir_error_desde_respuesta(self, respuesta: requests.Response) -> ErrorClienteGemini:
        logger.error("Gemini respondió %s: %s", respuesta.status_code, respuesta.text[:300])
        if respuesta.status_code in (401, 403):
            return ErrorClienteGemini("La API key configurada no es válida.", es_error_autenticacion=True)
        if respuesta.status_code == 429:
            return ErrorClienteGemini("Se alcanzó el límite de uso gratuito de Gemini. Probá en unos minutos.")
        return ErrorClienteGemini(f"La API de Gemini respondió un error ({respuesta.status_code}).")
