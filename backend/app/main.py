"""
main.py -- Punto de entrada de la aplicación backend.

Responsabilidad única: crear la instancia de FastAPI, configurar CORS
(porque ahora el frontend vive en otro contenedor/origen), inicializar
recursos al arrancar (base de datos, monitoreo automático), y montar
los routers. No contiene lógica de negocio ni de infraestructura -- eso
vive en app/servicios y app/repositorios.
"""

import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import (
    router_ia, router_autenticacion, router_usuarios,
    router_monitoreo, router_alertas, router_modelos, router_analizador,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NEMESIS] %(message)s")
logger = logging.getLogger("nemesis.main")

ORIGENES_PERMITIDOS = os.environ.get("ORIGENES_FRONTEND_PERMITIDOS", "http://localhost:5173").split(",")


@asynccontextmanager
async def ciclo_de_vida(aplicacion: FastAPI):
    """Reemplaza el patrón deprecado @app.on_event('startup'). Corre una
    vez al arrancar el servidor, antes de aceptar el primer request."""
    from app.motor.base_datos import init_db
    init_db()
    logger.info("Base de datos inicializada.")

    try:
        from app.motor.captura_red import obtener_gestor_captura
        gestor = obtener_gestor_captura()
        ok, mensaje = gestor.iniciar_continuo()
        if ok:
            logger.info("Monitoreo de red real iniciado automáticamente (%s)", mensaje)
        else:
            logger.warning("Monitoreo de red real no se pudo iniciar automáticamente: %s", mensaje)
            logger.warning("Configuralo una vez desde el panel de Monitoreo de Red.")
    except Exception as error:
        logger.warning("Aviso: el monitoreo automático no se pudo iniciar (%s). "
                        "El resto del sistema funciona con normalidad.", error)

    yield  # la aplicación queda corriendo acá

    logger.info("Apagando Nemesis Cyber Defense...")


def crear_aplicacion() -> FastAPI:
    aplicacion = FastAPI(
        title="Nemesis Cyber Defense - API",
        version="3.0.0",
        description="Backend de detección de intrusiones con IA (arquitectura backend/frontend separados).",
        lifespan=ciclo_de_vida,
    )

    aplicacion.add_middleware(
        CORSMiddleware,
        allow_origins=ORIGENES_PERMITIDOS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    aplicacion.include_router(router_autenticacion.enrutador)
    aplicacion.include_router(router_usuarios.enrutador)
    aplicacion.include_router(router_monitoreo.enrutador)
    aplicacion.include_router(router_alertas.enrutador)
    aplicacion.include_router(router_modelos.enrutador)
    aplicacion.include_router(router_analizador.enrutador)
    aplicacion.include_router(router_ia.enrutador)

    return aplicacion


app = crear_aplicacion()

