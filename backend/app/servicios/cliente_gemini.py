"""
cliente_gemini.py -- Encapsula toda la comunicación HTTP con la API de
Google Gemini, incluyendo el modo streaming (Server-Sent Events).

Responsabilidad única: enviar el prompt y devolver los fragmentos de texto
a medida que llegan. No sabe nada del dominio (planes de respuesta, features
del modelo de detección, etc.) -- eso vive en el servicio que lo usa.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Iterator, Optional

import requests

logger = logging.getLogger("nemesis.cliente_gemini")

# El modelo se puede cambiar sin tocar el código (Google retira modelos con el tiempo):
#   NEMESIS_GEMINI_MODELO=<nombre-del-modelo>
MODELO_GEMINI = os.environ.get("NEMESIS_GEMINI_MODELO", "gemini-2.5-flash")
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
            # La clave va en el ENCABEZADO x-goog-api-key (como exige la API de Gemini) y NO en la
            # URL: las excepciones de `requests` incluyen la URL completa en su mensaje, y una clave
            # en la query string terminaba en los logs y en el mensaje que ve el usuario.
            respuesta = requests.post(
                url,
                params={"alt": "sse"},
                headers={"content-type": "application/json", "x-goog-api-key": self._clave_api},
                json=cuerpo,
                stream=True,
                timeout=self._tiempo_espera_segundos,
            )
        except requests.RequestException as error:
            logger.warning("Fallo de red al llamar a Gemini: %s", self._ocultar_clave(str(error)))
            raise ErrorClienteGemini("No se pudo conectar con el servicio de IA (error de red).") from None

        if respuesta.status_code != 200:
            raise self._construir_error_desde_respuesta(respuesta)

        yield from self._leer_eventos_sse(respuesta)

    def _ocultar_clave(self, texto: str) -> str:
        """Defensa en profundidad: nunca dejar la clave en un mensaje, aunque algún día vuelva a viajar en la URL."""
        return texto.replace(self._clave_api, "***") if self._clave_api else texto

    def _leer_eventos_sse(self, respuesta: requests.Response) -> Iterator[str]:
        texto_acumulado = ""
        # Se leen BYTES y se decodifican como UTF-8 a mano: con decode_unicode=True, `requests` asume
        # ISO-8859-1 para respuestas text/* sin charset (el caso de text/event-stream) y todos los
        # acentos llegaban rotos ("ContenciÃ³n").
        for linea_cruda in respuesta.iter_lines():
            linea = linea_cruda.decode("utf-8", errors="replace") if isinstance(linea_cruda, bytes) else linea_cruda
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
        logger.error("Gemini respondió %s: %s", respuesta.status_code, self._ocultar_clave(respuesta.text[:300]))
        if respuesta.status_code in (401, 403):
            return ErrorClienteGemini("La API key configurada no es válida.", es_error_autenticacion=True)
        if respuesta.status_code == 429:
            return ErrorClienteGemini("Se alcanzó el límite de uso gratuito de Gemini. Probá en unos minutos.")
        return ErrorClienteGemini(f"La API de Gemini respondió un error ({respuesta.status_code}).")
