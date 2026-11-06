"""Sección 3.8 y 4.7: el control de acceso por roles se aplica en el SERVIDOR en CADA endpoint.

Se audita la tabla completa de rutas (OpenAPI, API pública de FastAPI) con la regla de DENEGAR POR
DEFECTO: lo que un Analista SOC puede hacer está enumerado explícitamente; cualquier otra ruta (y
cualquier ruta nueva que se agregue en el futuro sin decidirlo aquí) debe responder 403 al analista."""
import re

import pytest

from app.main import app
from tests.conftest import crear_usuario_activo, iniciar_sesion_http

PUBLICAS = "/api/auth/"   # login, activación y recuperación: ocurren ANTES de tener sesión

# Privilegios operativos del Analista SOC (Sección 3.8): dashboard, monitoreo de red y confirmación
# de detecciones. Sin acceso a las pantallas de configuración administrativa.
ANALISTA_PUEDE = {
    ("GET", "/api/alertas"),
    ("GET", "/api/alertas/capturas/estadisticas"),
    ("GET", "/api/alertas/capturas/validacion"),
    ("GET", "/api/alertas/capturas/validacion/csv"),
    ("POST", "/api/alertas/capturas/{captura_id}/etiquetar"),
    ("POST", "/api/analizador/{tipo_trafico}"),
    ("POST", "/api/ia/recomendaciones"),
    ("POST", "/api/ia/recomendaciones/stream"),
    ("GET", "/api/ia/config/estado"),
    ("GET", "/api/modelos/{nombre_modelo}/metricas"),
    ("POST", "/api/monitoreo/iniciar"),
    ("POST", "/api/monitoreo/detener"),
    ("GET", "/api/monitoreo/estado"),
    ("GET", "/api/monitoreo/dispositivos"),
}


def rutas():
    for path, operaciones in app.openapi()["paths"].items():
        for metodo in operaciones:
            yield metodo.upper(), path


def concreta(path):
    return re.sub(r"\{[^}]+\}", "1", path)


def test_el_contrato_del_analista_no_tiene_rutas_obsoletas():
    existentes = set(rutas())
    assert ANALISTA_PUEDE <= existentes, f"rutas que ya no existen: {ANALISTA_PUEDE - existentes}"
    assert len(existentes) >= 30   # la auditoría revisa de verdad la API (antes pasaba sin revisar nada)


def test_sin_sesion_toda_ruta_no_publica_responde_401(cliente):
    revisadas = 0
    for metodo, path in rutas():
        if path.startswith(PUBLICAS):
            continue
        r = cliente.request(metodo, concreta(path), json={})
        assert r.status_code == 401, f"{metodo} {path} -> {r.status_code}"
        revisadas += 1
    assert revisadas >= 20


def test_el_analista_recibe_403_en_todo_lo_que_no_este_en_su_contrato(cliente):
    iniciar_sesion_http(cliente, crear_usuario_activo("analista@test.ec", "Analista SOC"))
    administrativas = [(m, p) for m, p in rutas() if not p.startswith(PUBLICAS) and (m, p) not in ANALISTA_PUEDE]
    assert len(administrativas) >= 10
    for metodo, path in administrativas:
        r = cliente.request(metodo, concreta(path), json={})
        assert r.status_code == 403, f"{metodo} {path} -> {r.status_code} (debería ser exclusivo del Administrador)"
    for esperado in (("GET", "/api/usuarios"), ("POST", "/api/ia/config"), ("POST", "/api/modelos/reentrenar"),
                     ("GET", "/api/modelos/reentrenar/estado"),
                     ("POST", "/api/usuarios/{usuario_id}/resetear-mfa")):
        assert esperado in administrativas, esperado


def test_el_analista_si_tiene_acceso_a_lo_operativo(cliente):
    iniciar_sesion_http(cliente, crear_usuario_activo("analista@test.ec", "Analista SOC"))
    for path in ("/api/alertas", "/api/alertas/capturas/estadisticas", "/api/alertas/capturas/validacion",
                 "/api/ia/config/estado", "/api/monitoreo/estado"):
        assert cliente.get(path).status_code == 200, path
    # métricas de un modelo: pueden no existir todavía en la BD de prueba (404), pero NO se prohíben al analista
    assert cliente.get("/api/modelos/Nemesis_MLP/metricas").status_code not in (401, 403)
    # el estado del reentrenamiento y el reentrenamiento mismo son administrativos (Sección 3.8)
    assert cliente.get("/api/modelos/reentrenar/estado").status_code == 403


def test_el_administrador_pasa_el_control_de_rol(cliente):
    iniciar_sesion_http(cliente, crear_usuario_activo("admin@test.ec", "Administrador"))
    assert cliente.get("/api/usuarios").status_code == 200
