"""
router_monitoreo.py -- Control del monitoreo continuo de red real.
Delgado: toda la lógica de captura vive en app.motor.captura_red.
"""

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool

from app.nucleo.seguridad import requiere_sesion_autenticada
from app.motor.captura_red import obtener_gestor_captura
from app.motor.dispositivos_red import escanear_dispositivos_lan

enrutador = APIRouter(prefix="/api/monitoreo", tags=["Monitoreo de Red"],
                       dependencies=[Depends(requiere_sesion_autenticada)])


@enrutador.post("/iniciar")
async def iniciar_monitoreo(peticion: Request):
    cuerpo = await peticion.json()
    interfaz = (cuerpo.get("iface") or "").strip() or None
    ventana_segundos = int(cuerpo.get("ventana", 5))
    # "psutil" (default, sin Npcap) o "scapy" (captura real, requiere Npcap en Windows)
    backend = (cuerpo.get("backend") or "psutil").strip().lower()

    gestor = obtener_gestor_captura()
    ok, mensaje = gestor.iniciar_continuo(interfaz, ventana_segundos, backend)
    return {"ok": ok, "mensaje": mensaje, "backend": backend}


@enrutador.get("/dispositivos")
async def listar_dispositivos_lan():
    """Descubre los dispositivos conectados a la red local (ping sweep +
    tabla ARP del SO). No requiere Npcap ni intercepta tráfico ajeno."""
    resultado = await run_in_threadpool(escanear_dispositivos_lan)
    if not resultado["ok"]:
        raise HTTPException(status_code=503, detail=resultado["mensaje"])
    return resultado


@enrutador.post("/detener")
async def detener_monitoreo():
    gestor = obtener_gestor_captura()
    ok, mensaje = gestor.detener()
    return {"ok": ok, "mensaje": mensaje}


@enrutador.get("/estado")
async def estado_monitoreo(desde: int = 0):
    gestor = obtener_gestor_captura()
    return gestor.obtener_estado(desde)
