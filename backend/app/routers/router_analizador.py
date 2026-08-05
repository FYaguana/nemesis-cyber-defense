"""
router_analizador.py -- Genera tráfico simulado y lo pasa por el mismo
motor de inferencia que el tráfico real, para pruebas y demostraciones
(no se cuenta como producción real -- ver servicio_recomendaciones_ia y
la etiqueta "_fuente" que distingue "simulacion" de "red_real" en el
frontend).
"""

from fastapi import APIRouter, Depends, HTTPException

from app.nucleo.seguridad import requiere_sesion_autenticada
from app.motor.procesador_nemesis import obtener_procesador

TIPOS_VALIDOS = ("normal", "dos", "probe", "r2l", "u2r", "aleatorio")

enrutador = APIRouter(prefix="/api/analizador", tags=["Analizador (simulación)"],
                       dependencies=[Depends(requiere_sesion_autenticada)])


@enrutador.post("/{tipo_trafico}")
async def analizar_trafico_simulado(tipo_trafico: str):
    tipo = tipo_trafico.lower()
    if tipo not in TIPOS_VALIDOS:
        raise HTTPException(400, "Tipo inválido")

    procesador = obtener_procesador()
    if not procesador._cargado:
        raise HTTPException(503, "Los modelos no están cargados todavía.")

    muestra_simulada = procesador.generar_trafico_demo(tipo)
    return procesador.analizar_trafico(muestra_simulada)
