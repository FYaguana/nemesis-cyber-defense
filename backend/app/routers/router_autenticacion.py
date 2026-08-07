"""
router_autenticacion.py -- Endpoints de login, activación de cuenta,
recuperación de contraseña y reconfiguración de MFA.

Responsabilidad única: traducir HTTP <-> ServicioAutenticacion / motor de
gestión de usuarios. Sin lógica de negocio propia.
"""

from fastapi import APIRouter, Request, Response, HTTPException, Depends

from app.servicios.servicio_autenticacion import ServicioAutenticacion
from app.motor import gestion_usuarios
from app.nucleo.gestor_sesiones import eliminar_sesion
from app.nucleo.seguridad import requiere_sesion_autenticada
from app.nucleo.configuracion import URL_FRONTEND, COOKIE_SECURE

enrutador = APIRouter(prefix="/api/auth", tags=["Autenticación"])
_servicio = ServicioAutenticacion()

DURACION_COOKIE_SEGUNDOS = 8 * 60 * 60


@enrutador.post("/check-email")
async def verificar_correo(peticion: Request):
    cuerpo = await peticion.json()
    cuenta = _servicio.buscar_cuenta_por_correo(cuerpo.get("email", ""))
    if cuenta is None:
        return {"ok": False}

    usuario_respuesta = {"nombre": cuenta.nombre, "rol": cuenta.rol}
    if cuenta.es_cuenta_demo:
        usuario_respuesta["mfa_code"] = cuenta.codigo_demo
        return {"ok": True, "tipo": "demo", "usuario": usuario_respuesta}
    return {"ok": True, "tipo": "real", "usuario": usuario_respuesta}


@enrutador.post("/verify-password")
async def verificar_contrasena(peticion: Request):
    cuerpo = await peticion.json()
    return _servicio.verificar_contrasena(cuerpo.get("email", ""), cuerpo.get("password", ""))


@enrutador.post("/verify-mfa")
async def verificar_mfa(peticion: Request, respuesta: Response):
    cuerpo = await peticion.json()
    token = _servicio.iniciar_sesion(
        cuerpo.get("email", ""), cuerpo.get("password", ""), cuerpo.get("code", "")
    )
    if token is None:
        return {"ok": False}

    # Con el frontend haciendo de proxy inverso hacia este backend (ver
    # frontend/nginx.conf.template), el navegador ve TODO como un solo
    # origen -- ya no hace falta samesite="none" (eso era solo necesario
    # cuando el navegador hablaba directo con dos dominios distintos).
    # "lax" alcanza y es más restrictivo/seguro por defecto.
    # secure=COOKIE_SECURE: True en producción (Render, siempre HTTPS),
    # False en desarrollo local por HTTP plano (ver COOKIE_SECURE en
    # nucleo/configuracion.py).
    respuesta.set_cookie("nemesis_session", token, httponly=True,
                          max_age=DURACION_COOKIE_SEGUNDOS,
                          samesite="lax", secure=COOKIE_SECURE)
    return {"ok": True}


@enrutador.post("/logout")
async def cerrar_sesion(peticion: Request, respuesta: Response):
    token = peticion.cookies.get("nemesis_session")
    if token:
        eliminar_sesion(token)
    # Los atributos deben coincidir con los usados en set_cookie, si no
    # algunos navegadores no la borran correctamente.
    respuesta.delete_cookie("nemesis_session", samesite="lax", secure=COOKIE_SECURE)
    return {"ok": True}


@enrutador.get("/estado")
async def obtener_estado_sesion(sesion=Depends(requiere_sesion_autenticada)):
    return {"email": sesion.email, "nombre": sesion.nombre, "rol": sesion.rol}


# ─── Activación de cuenta (público, el token de invitación ES la credencial) ─

@enrutador.get("/activar/preparar")
async def preparar_activacion_cuenta(token: str):
    datos, error = gestion_usuarios.preparar_activacion(token)
    if error:
        raise HTTPException(400, error)
    return datos


@enrutador.post("/activar/confirmar")
async def confirmar_activacion_cuenta(peticion: Request):
    cuerpo = await peticion.json()
    ok, mensaje = gestion_usuarios.confirmar_activacion(
        cuerpo.get("usuario_id"), cuerpo.get("secreto"), cuerpo.get("codigo", ""),
        cuerpo.get("password", ""), cuerpo.get("password_confirmacion", ""),
    )
    if not ok:
        raise HTTPException(400, mensaje)
    return {"ok": True, "mensaje": mensaje}


# ─── Recuperación de contraseña (requiere el MFA vigente como prueba) ────────

@enrutador.post("/recuperar/solicitar")
async def solicitar_recuperacion_contrasena(peticion: Request):
    cuerpo = await peticion.json()
    ok, mensaje = gestion_usuarios.solicitar_recuperacion(cuerpo.get("email", ""), URL_FRONTEND)
    return {"ok": ok, "mensaje": mensaje}


@enrutador.get("/recuperar/preparar")
async def preparar_recuperacion_contrasena(token: str):
    datos, error = gestion_usuarios.preparar_recuperacion(token)
    if error:
        raise HTTPException(400, error)
    return datos


@enrutador.post("/recuperar/confirmar")
async def confirmar_recuperacion_contrasena(peticion: Request):
    cuerpo = await peticion.json()
    ok, mensaje = gestion_usuarios.confirmar_recuperacion(
        cuerpo.get("token", ""), cuerpo.get("password", ""),
        cuerpo.get("password_confirmacion", ""), cuerpo.get("codigo", ""),
    )
    if not ok:
        raise HTTPException(400, mensaje)
    return {"ok": True, "mensaje": mensaje}


# ─── Reconfiguración de MFA (el admin la dispara desde /router_usuarios) ─────

@enrutador.get("/mfa-reset/preparar")
async def preparar_reconfiguracion_mfa(token: str):
    datos, error = gestion_usuarios.preparar_reset_mfa(token)
    if error:
        raise HTTPException(400, error)
    return datos


@enrutador.post("/mfa-reset/confirmar")
async def confirmar_reconfiguracion_mfa(peticion: Request):
    cuerpo = await peticion.json()
    ok, mensaje = gestion_usuarios.confirmar_reset_mfa(
        cuerpo.get("usuario_id"), cuerpo.get("secreto"), cuerpo.get("codigo", "")
    )
    if not ok:
        raise HTTPException(400, mensaje)
    return {"ok": True, "mensaje": mensaje}
