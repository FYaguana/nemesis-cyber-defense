"""
limitador_tasa.py -- Control de cuántas solicitudes se permiten a un recurso
externo por minuto y por día (ventana deslizante en memoria).

Responsabilidad única: decidir si una solicitud puede pasar o debe esperar/
rechazarse. No sabe nada de Gemini, HTTP, ni de negocio -- es reutilizable
para cualquier API externa con límites de uso.
"""

import time
import threading
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class ResultadoLimiteTasa:
    """Resultado de evaluar si una solicitud puede ejecutarse ahora."""
    permitida: bool
    motivo: str = ""
    segundos_espera_sugerida: float = 0.0


class LimitadorTasa:
    """
    Limitador de tasa por ventana deslizante, con dos límites simultáneos:
    uno por minuto y uno por día. Pensado para una única API key compartida
    por todo el servidor (no por usuario individual).
    """

    def __init__(self, maximo_por_minuto: int, maximo_por_dia: int):
        self._maximo_por_minuto = maximo_por_minuto
        self._maximo_por_dia = maximo_por_dia
        self._marcas_tiempo_minuto: deque[float] = deque()
        self._marcas_tiempo_dia: deque[float] = deque()
        self._bloqueo = threading.Lock()

    def evaluar_solicitud(self) -> ResultadoLimiteTasa:
        """Evalúa si una nueva solicitud puede ejecutarse en este instante."""
        ahora = time.time()
        with self._bloqueo:
            self._descartar_marcas_vencidas(ahora)

            if len(self._marcas_tiempo_dia) >= self._maximo_por_dia:
                segundos_hasta_liberar = 86400 - (ahora - self._marcas_tiempo_dia[0])
                return ResultadoLimiteTasa(
                    permitida=False,
                    motivo=f"Se alcanzó el límite diario gratuito ({self._maximo_por_dia} solicitudes).",
                    segundos_espera_sugerida=max(segundos_hasta_liberar, 0),
                )

            if len(self._marcas_tiempo_minuto) >= self._maximo_por_minuto:
                segundos_hasta_liberar = 60 - (ahora - self._marcas_tiempo_minuto[0])
                return ResultadoLimiteTasa(
                    permitida=False,
                    motivo="Se alcanzó el límite de solicitudes por minuto. Esperá unos segundos.",
                    segundos_espera_sugerida=max(segundos_hasta_liberar, 0),
                )

            self._marcas_tiempo_minuto.append(ahora)
            self._marcas_tiempo_dia.append(ahora)
            return ResultadoLimiteTasa(permitida=True)

    def _descartar_marcas_vencidas(self, ahora: float) -> None:
        while self._marcas_tiempo_minuto and ahora - self._marcas_tiempo_minuto[0] > 60:
            self._marcas_tiempo_minuto.popleft()
        while self._marcas_tiempo_dia and ahora - self._marcas_tiempo_dia[0] > 86400:
            self._marcas_tiempo_dia.popleft()
