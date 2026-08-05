"""
servicio_autenticacion.py -- Orquesta el flujo de login de dos factores
para usuarios reales (contraseña + TOTP) y el acceso simplificado de los
usuarios demo (correo + código fijo), unificados detrás de una sola API.
"""

from dataclasses import dataclass
from typing import Optional

from app.motor import gestion_usuarios
from app.nucleo.gestor_sesiones import USUARIOS_DEMO, crear_sesion


@dataclass(frozen=True)
class InformacionCuenta:
    nombre: str
    rol: str
    es_cuenta_demo: bool
    codigo_demo: Optional[str] = None


class ServicioAutenticacion:
    def buscar_cuenta_por_correo(self, correo: str) -> Optional[InformacionCuenta]:
        correo = correo.lower().strip()

        if gestion_usuarios.usuario_existe_activo(correo):
            usuario = gestion_usuarios.obtener_usuario(correo)
            return InformacionCuenta(nombre=usuario["nombre"], rol=usuario["rol"], es_cuenta_demo=False)

        if correo in USUARIOS_DEMO:
            usuario_demo = USUARIOS_DEMO[correo]
            return InformacionCuenta(
                nombre=usuario_demo["nombre"], rol=usuario_demo["rol"],
                es_cuenta_demo=True, codigo_demo=usuario_demo["mfa_code"],
            )
        return None

    def verificar_contrasena(self, correo: str, contrasena: str) -> dict:
        """Solo aplica a cuentas reales -- las demo no tienen contraseña."""
        return gestion_usuarios.verificar_password_usuario(correo.lower().strip(), contrasena)

    def iniciar_sesion(self, correo: str, contrasena: str, codigo_mfa: str) -> Optional[str]:
        """Verifica ambos factores (o el código demo) y, si son correctos,
        crea la sesión y retorna el token. Retorna None si falla."""
        correo = correo.lower().strip()

        if gestion_usuarios.usuario_existe_activo(correo):
            if not gestion_usuarios.verificar_login(correo, contrasena, codigo_mfa):
                return None
            usuario = gestion_usuarios.obtener_usuario(correo)
            return crear_sesion(correo, {"nombre": usuario["nombre"], "rol": usuario["rol"]})

        usuario_demo = USUARIOS_DEMO.get(correo)
        if not usuario_demo or usuario_demo["mfa_code"] != codigo_mfa:
            return None
        return crear_sesion(correo, usuario_demo)
