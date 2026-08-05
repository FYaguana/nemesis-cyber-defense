"""
router_modelos.py -- Métricas de los modelos entrenados y control del
reentrenamiento con datos reales confirmados. El reentrenamiento en sí
exige rol Administrador; consultar métricas solo exige sesión válida.
"""

import os
import json

from fastapi import APIRouter, Request, Depends, HTTPException

from app.nucleo.seguridad import requiere_sesion_autenticada, requiere_rol_administrador
from app.motor.reentrenamiento import obtener_gestor_reentrenamiento

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

enrutador = APIRouter(prefix="/api/modelos", tags=["Modelos"])


@enrutador.get("/{nombre_modelo}/metricas", dependencies=[Depends(requiere_sesion_autenticada)])
async def obtener_metricas_modelo(nombre_modelo: str):
    ruta = os.path.join(DIRECTORIO_BACKEND, "models", f"{nombre_modelo}_metricas.json")
    if not os.path.exists(ruta):
        raise HTTPException(404, "No encontrado")
    with open(ruta, "r", encoding="utf-8") as archivo:
        return json.load(archivo)


@enrutador.post("/reentrenar", dependencies=[Depends(requiere_rol_administrador)])
async def iniciar_reentrenamiento(peticion: Request):
    cuerpo = await peticion.json()
    epochs = int(cuerpo.get("epochs", 20))
    gestor = obtener_gestor_reentrenamiento()
    ok, mensaje = gestor.iniciar(epochs=epochs)
    return {"ok": ok, "mensaje": mensaje}


@enrutador.get("/reentrenar/estado", dependencies=[Depends(requiere_rol_administrador)])
async def estado_reentrenamiento():
    gestor = obtener_gestor_reentrenamiento()
    return gestor.obtener_estado()
