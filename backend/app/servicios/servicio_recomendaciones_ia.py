"""
servicio_recomendaciones_ia.py -- Orquesta la generación de planes de
respuesta a incidentes usando IA, con streaming en vivo hacia el cliente.

Responsabilidad única: reglas de negocio de "cómo se arma un plan de
respuesta" (qué va en el prompt, qué forma debe tener la salida, cuándo
usar el plan de referencia en vez de la IA). NO sabe de HTTP ni de Gemini
directamente -- eso se delega a ClienteGemini y al router.
"""

import json
import logging
from dataclasses import dataclass
from typing import Iterator, Optional

from app.nucleo.limitador_tasa import LimitadorTasa
from app.servicios.cliente_gemini import ClienteGemini, ErrorClienteGemini

logger = logging.getLogger("nemesis.servicio_recomendaciones_ia")

CLASES_VALIDAS = ("NORMAL", "DoS", "Probe", "R2L", "U2R")
CANTIDAD_MINIMA_PASOS = 3
CANTIDAD_MAXIMA_PASOS = 5

# Límites del nivel gratuito de Gemini Flash (ajustables según el plan real).
LIMITE_SOLICITUDES_POR_MINUTO = 10
LIMITE_SOLICITUDES_POR_DIA = 200


@dataclass(frozen=True)
class DeteccionParaAnalizar:
    """Datos de entrada necesarios para pedirle un plan a la IA."""
    clase: str
    severidad: str
    confianza: float
    features_influyentes: list[dict]
    alertas_recientes: list[dict]


@dataclass(frozen=True)
class FragmentoPlanEnProgreso:
    """Un fragmento de texto parcial mientras la IA todavía está escribiendo."""
    texto_parcial: str
    completado: bool = False


@dataclass(frozen=True)
class PlanRespuestaIncidente:
    pasos: list[dict]
    tiempo_respuesta: str
    prioridad: str
    color_prioridad: str
    referencia_nist: str
    generado_por_ia: bool
    motivo_uso_plantilla: Optional[str] = None


class ServicioRecomendacionesIA:
    """
    Genera planes de respuesta a incidentes, en streaming, respetando un
    límite de uso del nivel gratuito de la API. Si la IA no está disponible
    (sin API key, límite alcanzado, error de red), cae a un plan de
    referencia estático -- nunca deja al usuario sin respuesta.
    """

    def __init__(self, obtener_clave_api_callback, generar_plan_referencia_callback):
        self._obtener_clave_api = obtener_clave_api_callback
        self._generar_plan_referencia = generar_plan_referencia_callback
        self._limitador_tasa = LimitadorTasa(
            maximo_por_minuto=LIMITE_SOLICITUDES_POR_MINUTO,
            maximo_por_dia=LIMITE_SOLICITUDES_POR_DIA,
        )

    def generar_plan_en_streaming(
        self, deteccion: DeteccionParaAnalizar
    ) -> Iterator[FragmentoPlanEnProgreso | PlanRespuestaIncidente]:
        """
        Generador que primero entrega fragmentos de texto parciales (para
        mostrar el efecto de escritura en vivo en la interfaz) y al final
        entrega el PlanRespuestaIncidente ya validado. Si algo falla en
        cualquier punto, entrega el plan de referencia en su lugar.
        """
        clave_api = self._obtener_clave_api()
        if not clave_api:
            yield self._plan_de_referencia(deteccion, "No hay una API key de Gemini configurada.")
            return

        resultado_limite = self._limitador_tasa.evaluar_solicitud()
        if not resultado_limite.permitida:
            yield self._plan_de_referencia(deteccion, resultado_limite.motivo)
            return

        prompt = self._construir_prompt(deteccion)
        cliente = ClienteGemini(clave_api)

        try:
            texto_final = ""
            for texto_acumulado in cliente.generar_contenido_en_streaming(prompt):
                texto_final = texto_acumulado
                yield FragmentoPlanEnProgreso(texto_parcial=texto_acumulado)
        except ErrorClienteGemini as error:
            logger.warning("Fallo la IA, usando plantilla: %s", error.mensaje_usuario)
            yield self._plan_de_referencia(deteccion, error.mensaje_usuario)
            return

        plan_extraido = self._extraer_plan_json(texto_final)
        if plan_extraido is None or not self._validar_forma_del_plan(plan_extraido):
            logger.warning("La IA respondió en un formato inesperado: %r", texto_final[:500])
            yield self._plan_de_referencia(deteccion, "La IA respondió en un formato inesperado.")
            return

        yield PlanRespuestaIncidente(**plan_extraido, generado_por_ia=True)

    def _construir_prompt(self, deteccion: DeteccionParaAnalizar) -> str:
        texto_features = self._formatear_features(deteccion.features_influyentes)
        texto_alertas = self._formatear_alertas_recientes(deteccion.alertas_recientes)

        return f"""Eres el asistente de un centro de operaciones de seguridad (SOC) de una empresa.
Un sistema de detección de intrusiones basado en redes neuronales (MLP + RNN, entrenado con NSL-KDD)
acaba de clasificar una conexión de red con el siguiente resultado:

- Clase detectada: {deteccion.clase}
- Severidad: {deteccion.severidad}
- Confianza del modelo: {deteccion.confianza}%

Features más influyentes en la decisión del modelo:
{texto_features}

Últimas alertas registradas en el sistema (contexto reciente, más nueva primero):
{texto_alertas}

Genera un plan de respuesta a incidentes accionable, basado en las fases de NIST SP 800-61r2
(Preparación, Detección y Análisis, Contención/Erradicación/Recuperación, Actividad Post-Incidente),
adaptado específicamente a este caso y considerando el contexto reciente de alertas.

Si la clase es NORMAL, el plan debe ser breve y centrado en monitoreo continuo, no en contención.

REGLA DE FORMATO OBLIGATORIA: el texto de "titulo" y "detalle" debe ser texto plano, sin
formato Markdown de ningún tipo -- nada de **negritas**, *cursivas*, listas con "-" o "*",
encabezados con "#", ni bloques de código con backticks. Es texto que se muestra directo en
una interfaz web, no un documento Markdown.

Responde con un objeto JSON con exactamente esta forma:
{{
  "pasos": [
    {{"titulo": "...", "detalle": "..."}}
  ],
  "tiempo_respuesta": "...",
  "prioridad": "BAJA|MEDIA|ALTA|CRÍTICA|MÁXIMA",
  "color_prioridad": "#hexcolor",
  "referencia_nist": "NIST SP 800-61r2 §X - Nombre de la fase"
}}
El arreglo "pasos" debe tener entre {CANTIDAD_MINIMA_PASOS} y {CANTIDAD_MAXIMA_PASOS} elementos."""

    def _formatear_features(self, features: list[dict]) -> str:
        if not features:
            return "Sin features destacadas."
        return "\n".join(
            f"- {f.get('feature')}: valor observado {f.get('valor')} (rango normal: {f.get('normal')})"
            for f in features[:5]
        )

    def _formatear_alertas_recientes(self, alertas: list[dict]) -> str:
        if not alertas:
            return "No hay alertas previas registradas en el sistema."
        return "\n".join(
            f"- [{a['timestamp']}] {a['tipo_ataque']} (nivel {a['nivel']}, confianza {a['confianza']:.0f}%)"
            for a in alertas[:8]
        )

    def _extraer_plan_json(self, texto: str) -> Optional[dict]:
        """Intenta parsear el texto como JSON, tolerando que venga envuelto
        en bloques Markdown pese a la instrucción explícita de no usarlo."""
        texto = texto.strip()
        try:
            return json.loads(texto)
        except json.JSONDecodeError:
            pass

        if "```" in texto:
            for parte in texto.split("```"):
                candidato = parte.strip()
                if candidato.startswith("json"):
                    candidato = candidato[4:].strip()
                if candidato.startswith("{"):
                    try:
                        return json.loads(candidato)
                    except json.JSONDecodeError:
                        continue

        inicio, fin = texto.find("{"), texto.rfind("}")
        if inicio != -1 and fin != -1 and fin > inicio:
            try:
                return json.loads(texto[inicio:fin + 1])
            except json.JSONDecodeError:
                pass
        return None

    def _validar_forma_del_plan(self, plan: dict) -> bool:
        if not isinstance(plan, dict):
            return False
        pasos = plan.get("pasos")
        if not isinstance(pasos, list) or not pasos:
            return False
        if not all(isinstance(p, dict) and "titulo" in p and "detalle" in p for p in pasos):
            return False
        campos_requeridos = ("tiempo_respuesta", "prioridad", "color_prioridad", "referencia_nist")
        return all(campo in plan for campo in campos_requeridos)

    def _plan_de_referencia(self, deteccion: DeteccionParaAnalizar, motivo: str) -> PlanRespuestaIncidente:
        plantilla = self._generar_plan_referencia(
            deteccion.clase, deteccion.severidad, deteccion.confianza, deteccion.features_influyentes
        )
        return PlanRespuestaIncidente(
            pasos=plantilla["pasos"],
            tiempo_respuesta=plantilla["tiempo_respuesta"],
            prioridad=plantilla["prioridad"],
            color_prioridad=plantilla["color_prioridad"],
            referencia_nist=plantilla["referencia_nist"],
            generado_por_ia=False,
            motivo_uso_plantilla=motivo,
        )
