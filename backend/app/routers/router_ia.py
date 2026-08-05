"""
router_ia.py -- Endpoints HTTP relacionados a la IA de recomendaciones.

Responsabilidad única: traducir HTTP <-> servicio. No arma prompts, no
valida planes, no habla con Gemini directamente -- todo eso vive en
ServicioRecomendacionesIA.
"""

import json
import dataclasses

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import StreamingResponse

from app.servicios.servicio_recomendaciones_ia import (
    ServicioRecomendacionesIA,
    DeteccionParaAnalizar,
    FragmentoPlanEnProgreso,
    PlanRespuestaIncidente,
)
from app.nucleo.seguridad import requiere_sesion_autenticada, requiere_rol_administrador
from app.nucleo.dependencias import proveer_servicio_recomendaciones_ia
from app.repositorios.repositorio_configuracion_ia import (
    guardar_clave_api_gemini, hay_clave_api_configurada,
)

enrutador = APIRouter(prefix="/api/ia", tags=["Recomendaciones IA"])


def _evento_sse(nombre_evento: str, datos: dict) -> str:
    """Formatea un evento en el formato Server-Sent Events estándar."""
    return f"event: {nombre_evento}\ndata: {json.dumps(datos, ensure_ascii=False)}\n\n"


@enrutador.post("/recomendaciones")
async def generar_recomendaciones_sin_streaming(
    peticion: Request,
    sesion=Depends(requiere_sesion_autenticada),
    servicio: ServicioRecomendacionesIA = Depends(proveer_servicio_recomendaciones_ia),
):
    """
    Versión sin streaming, para clientes que solo necesitan el resultado
    final (ej. el dashboard actual). Reutiliza el mismo servicio que el
    endpoint en streaming -- consume el generador internamente y se queda
    solo con el plan final, sin duplicar ninguna lógica.
    """
    cuerpo = await peticion.json()
    deteccion = DeteccionParaAnalizar(
        clase=cuerpo.get("clase", "NORMAL"),
        severidad=cuerpo.get("severidad", "NORMAL"),
        confianza=cuerpo.get("confianza", 0),
        features_influyentes=cuerpo.get("features", []),
        alertas_recientes=cuerpo.get("alertas_recientes", []),
    )
    plan_final = None
    for resultado in servicio.generar_plan_en_streaming(deteccion):
        if isinstance(resultado, PlanRespuestaIncidente):
            plan_final = resultado
    return dataclasses.asdict(plan_final)


@enrutador.post("/recomendaciones/stream")
async def generar_recomendaciones_en_streaming(
    peticion: Request,
    sesion=Depends(requiere_sesion_autenticada),
    servicio: ServicioRecomendacionesIA = Depends(proveer_servicio_recomendaciones_ia),
):
    """
    Genera el plan de respuesta en streaming: el cliente recibe eventos
    'fragmento' con el texto parcial a medida que la IA escribe, y un
    evento final 'plan_completo' con el plan ya estructurado y validado.
    """
    cuerpo = await peticion.json()
    deteccion = DeteccionParaAnalizar(
        clase=cuerpo.get("clase", "NORMAL"),
        severidad=cuerpo.get("severidad", "NORMAL"),
        confianza=cuerpo.get("confianza", 0),
        features_influyentes=cuerpo.get("features", []),
        alertas_recientes=cuerpo.get("alertas_recientes", []),
    )

    def flujo_eventos():
        for resultado in servicio.generar_plan_en_streaming(deteccion):
            if isinstance(resultado, FragmentoPlanEnProgreso):
                yield _evento_sse("fragmento", {"texto_parcial": resultado.texto_parcial})
            elif isinstance(resultado, PlanRespuestaIncidente):
                yield _evento_sse("plan_completo", dataclasses.asdict(resultado))

    return StreamingResponse(flujo_eventos(), media_type="text/event-stream")


# ─── Configuración de la API key de Gemini (solo Administrador) ─────────────

@enrutador.get("/config/estado")
async def estado_configuracion_ia():
    return {"configurada": hay_clave_api_configurada()}


@enrutador.post("/config", dependencies=[Depends(requiere_rol_administrador)])
async def guardar_configuracion_ia(peticion: Request):
    cuerpo = await peticion.json()
    clave_api = (cuerpo.get("api_key") or "").strip()
    if len(clave_api) < 20:
        raise HTTPException(400, "Eso no parece una API key válida de Google Gemini.")
    guardar_clave_api_gemini(clave_api)
    return {"ok": True}
