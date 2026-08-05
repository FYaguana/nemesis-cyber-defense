"""
servicio_usuarios.py -- Reglas de negocio de administración de usuarios.
Delega la mecánica (TOTP, hashing, envío de correo) al motor de gestión de
usuarios ya probado; este servicio solo agrega las validaciones de
"quién puede hacer qué" propias del caso de uso administrativo.
"""

from app.motor import gestion_usuarios
from app.motor.base_datos import (
    listar_usuarios as _listar_usuarios_db,
    actualizar_rol_usuario,
    actualizar_estado_usuario,
    eliminar_usuario as _eliminar_usuario_db,
)


class ServicioUsuarios:
    def listar(self) -> list:
        return _listar_usuarios_db()

    def invitar(self, correo: str, nombre: str, rol: str, url_base: str) -> tuple[bool, str]:
        return gestion_usuarios.invitar_usuario(correo, nombre, rol, url_base)

    def cambiar_rol(self, usuario_id: int, nuevo_rol: str) -> None:
        if nuevo_rol not in gestion_usuarios.ROLES_VALIDOS:
            raise ValueError(f"Rol inválido. Debe ser uno de: {', '.join(gestion_usuarios.ROLES_VALIDOS)}")
        actualizar_rol_usuario(usuario_id, nuevo_rol)

    def cambiar_estado(self, usuario_id: int, activo: bool) -> None:
        actualizar_estado_usuario(usuario_id, activo)

    def eliminar(self, usuario_id: int) -> None:
        _eliminar_usuario_db(usuario_id)

    def resetear_mfa(self, usuario_id: int, url_base: str) -> tuple[bool, str]:
        return gestion_usuarios.admin_resetear_mfa(usuario_id, url_base)
