"""
dependencias.py -- Composición de objetos para inyección de dependencias.

Este es el ÚNICO lugar donde se "cablean" las implementaciones concretas
(de dónde sale la API key, cuál es el plan de referencia) con el servicio
que las necesita. Los routers y servicios nunca importan estas fuentes
concretas directamente -- así se pueden reemplazar en tests sin tocar nada
más (Inversión de Dependencias, la "D" de SOLID).
"""

from functools import lru_cache

from app.servicios.servicio_recomendaciones_ia import ServicioRecomendacionesIA
from app.repositorios.repositorio_configuracion_ia import obtener_clave_api_gemini
from app.servicios.planes_referencia import generar_plan_de_referencia


@lru_cache
def proveer_servicio_recomendaciones_ia() -> ServicioRecomendacionesIA:
    """Instancia única (singleton de proceso) del servicio de IA, con sus
    dos colaboradores externos inyectados: de dónde sale la clave de API,
    y cómo se genera el plan de referencia cuando la IA no está disponible."""
    return ServicioRecomendacionesIA(
        obtener_clave_api_callback=obtener_clave_api_gemini,
        generar_plan_referencia_callback=generar_plan_de_referencia,
    )
