"""
router_alertas.py -- Consulta de alertas recientes y etiquetado humano de
capturas reales (la base del aprendizaje activo / reentrenamiento).
"""

from fastapi import APIRouter, Request, Depends, HTTPException

from app.nucleo.seguridad import requiere_sesion_autenticada, SesionUsuario
from app.motor.base_datos import obtener_alertas_recientes, etiquetar_captura, contar_capturas

CLASES_VALIDAS = ("NORMAL", "DoS", "Probe", "R2L", "U2R")

enrutador = APIRouter(prefix="/api/alertas", tags=["Alertas"],
                       dependencies=[Depends(requiere_sesion_autenticada)])


@enrutador.get("")
async def listar_alertas_recientes(limite: int = 50):
    return obtener_alertas_recientes(limite)


@enrutador.post("/capturas/{captura_id}/etiquetar")
async def etiquetar_captura_real(
    captura_id: int, peticion: Request, sesion: SesionUsuario = Depends(requiere_sesion_autenticada)
):
    cuerpo = await peticion.json()
    etiqueta = cuerpo.get("etiqueta")
    if etiqueta not in CLASES_VALIDAS:
        raise HTTPException(400, "Etiqueta inválida.")
    etiquetar_captura(captura_id, etiqueta, sesion.email)
    return {"ok": True}


@enrutador.get("/capturas/estadisticas")
async def estadisticas_capturas_reales():
    return contar_capturas()
