"""
router_monitoreo.py -- Control del monitoreo continuo de red real.
Delgado: toda la lógica de captura vive en app.motor.captura_red.
"""

from fastapi import APIRouter, Request, Depends, HTTPException

from app.nucleo.seguridad import requiere_sesion_autenticada
from app.motor.captura_red import obtener_gestor_captura

enrutador = APIRouter(prefix="/api/monitoreo", tags=["Monitoreo de Red"],
                       dependencies=[Depends(requiere_sesion_autenticada)])


@enrutador.post("/iniciar")
async def iniciar_monitoreo(peticion: Request):
    cuerpo = await peticion.json()
    interfaz = (cuerpo.get("iface") or "").strip() or None
    ventana_segundos = int(cuerpo.get("ventana", 5))

    gestor = obtener_gestor_captura()
    ok, mensaje = gestor.iniciar_continuo(interfaz, ventana_segundos)
    return {"ok": ok, "mensaje": mensaje}


@enrutador.post("/detener")
async def detener_monitoreo():
    gestor = obtener_gestor_captura()
    ok, mensaje = gestor.detener()
    return {"ok": ok, "mensaje": mensaje}


@enrutador.get("/estado")
async def estado_monitoreo(desde: int = 0):
    gestor = obtener_gestor_captura()
    return gestor.obtener_estado(desde)
