"""Sección 4.7: el control de acceso por roles se aplica en el SERVIDOR, no solo en la interfaz."""
from tests.conftest import crear_usuario_activo, iniciar_sesion_http


def test_sin_sesion_los_endpoints_protegidos_responden_401(cliente):
    for ruta in ("/api/alertas", "/api/usuarios", "/api/monitoreo/estado", "/api/alertas/capturas/validacion"):
        assert cliente.get(ruta).status_code == 401, ruta


def test_analista_no_accede_a_endpoints_administrativos(cliente):
    iniciar_sesion_http(cliente, crear_usuario_activo("analista@test.ec", "Analista SOC"))
    assert cliente.get("/api/usuarios").status_code == 403
    assert cliente.post("/api/usuarios/invitar", json={"email": "z@test.ec", "nombre": "Z"}).status_code == 403
    assert cliente.post("/api/modelos/reentrenar").status_code == 403
    assert cliente.post("/api/ia/config", json={"api_key": "x"}).status_code == 403
    # ...pero sí tiene privilegios operativos (Sección 3.9)
    assert cliente.get("/api/alertas").status_code == 200


def test_administrador_si_accede_a_la_gestion_de_usuarios(cliente):
    iniciar_sesion_http(cliente, crear_usuario_activo("admin@test.ec", "Administrador"))
    assert cliente.get("/api/usuarios").status_code == 200
