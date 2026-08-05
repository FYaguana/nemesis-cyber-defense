"""
router_usuarios.py -- Endpoints de administración de usuarios y de la
configuración de envío de correo. Todo el router exige rol Administrador.
"""

from fastapi import APIRouter, Request, Depends, HTTPException

from app.nucleo.seguridad import requiere_rol_administrador
from app.nucleo.configuracion import URL_FRONTEND
from app.servicios.servicio_usuarios import ServicioUsuarios
from app.repositorios.repositorio_configuracion_correo import (
    obtener_configuracion_correo, guardar_configuracion_correo, hay_correo_configurado,
)

enrutador = APIRouter(prefix="/api/usuarios", tags=["Usuarios"], dependencies=[Depends(requiere_rol_administrador)])
_servicio = ServicioUsuarios()


@enrutador.get("")
async def listar_usuarios():
    return _servicio.listar()


@enrutador.post("/invitar")
async def invitar_usuario(peticion: Request):
    cuerpo = await peticion.json()
    correo = (cuerpo.get("email") or "").strip()
    nombre = (cuerpo.get("nombre") or "").strip()
    rol = cuerpo.get("rol", "Analista SOC")
    if not correo or not nombre:
        raise HTTPException(400, "Correo y nombre son obligatorios.")

    ok, mensaje = _servicio.invitar(correo, nombre, rol, URL_FRONTEND)
    if not ok:
        raise HTTPException(400, mensaje)
    return {"ok": True, "mensaje": mensaje}


@enrutador.post("/{usuario_id}/rol")
async def cambiar_rol_usuario(usuario_id: int, peticion: Request):
    cuerpo = await peticion.json()
    try:
        _servicio.cambiar_rol(usuario_id, cuerpo.get("rol"))
    except ValueError as error:
        raise HTTPException(400, str(error))
    return {"ok": True}


@enrutador.post("/{usuario_id}/estado")
async def cambiar_estado_usuario(usuario_id: int, peticion: Request):
    cuerpo = await peticion.json()
    _servicio.cambiar_estado(usuario_id, bool(cuerpo.get("activo")))
    return {"ok": True}


@enrutador.delete("/{usuario_id}")
async def eliminar_usuario(usuario_id: int):
    _servicio.eliminar(usuario_id)
    return {"ok": True}


@enrutador.post("/{usuario_id}/resetear-mfa")
async def resetear_mfa_usuario(usuario_id: int):
    ok, mensaje = _servicio.resetear_mfa(usuario_id, URL_FRONTEND)
    if not ok:
        raise HTTPException(400, mensaje)
    return {"ok": True, "mensaje": mensaje}


# ─── Configuración de correo (para las invitaciones) ─────────────────────────

@enrutador.get("/configuracion/correo/estado")
async def estado_configuracion_correo():
    return {"configurado": hay_correo_configurado()}


@enrutador.post("/configuracion/correo")
async def guardar_configuracion_correo_endpoint(peticion: Request):
    cuerpo = await peticion.json()
    correo_gmail = (cuerpo.get("gmail_user") or "").strip()
    contrasena_aplicacion = (cuerpo.get("gmail_app_password") or "").strip()
    if "@" not in correo_gmail or len(contrasena_aplicacion) < 8:
        raise HTTPException(400, "Revisá el correo y la contraseña de aplicación.")
    guardar_configuracion_correo(correo_gmail, contrasena_aplicacion)
    return {"ok": True}
