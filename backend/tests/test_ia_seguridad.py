"""Secciones 3.9 y 4.8: cliente Gemini sin fugas de la clave, formato sin Markdown verificado,
contexto de alertas recientes leído por el servidor y plan de respaldo ante cualquier fallo."""
import json
import logging

import pytest
import requests

from app.servicios import cliente_gemini as cg
from app.servicios import servicio_recomendaciones_ia as svc
from app.servicios.servicio_recomendaciones_ia import (
    DeteccionParaAnalizar, FragmentoPlanEnProgreso, PlanRespuestaIncidente, ServicioRecomendacionesIA)
from tests.conftest import crear_usuario_activo, iniciar_sesion_http

CLAVE = "AIzaSyClaveMuySecreta1234567890"


class RespuestaFalsa:
    def __init__(self, status=200, lineas=(), texto=""):
        self.status_code, self._lineas, self.text = status, lineas, texto

    def iter_lines(self, decode_unicode=True):
        yield from self._lineas


def evento(texto):
    return "data: " + json.dumps({"candidates": [{"content": {"parts": [{"text": texto}]}}]})


def test_la_clave_viaja_en_el_encabezado_y_nunca_en_la_url(monkeypatch):
    visto = {}

    def post_falso(url, params=None, headers=None, json=None, stream=None, timeout=None):
        visto.update(url=url, params=params or {}, headers=headers)
        return RespuestaFalsa(lineas=[evento("hola")])

    monkeypatch.setattr(cg.requests, "post", post_falso)
    assert list(cg.ClienteGemini(CLAVE).generar_contenido_en_streaming("p")) == ["hola"]
    assert visto["headers"]["x-goog-api-key"] == CLAVE
    assert CLAVE not in visto["url"] and "key" not in visto["params"]
    assert visto["params"] == {"alt": "sse"}


def test_un_error_de_red_no_filtra_la_clave_ni_al_usuario_ni_al_log(monkeypatch, caplog):
    def post_roto(*a, **k):
        raise requests.ConnectionError(
            f"HTTPSConnectionPool(host='generativelanguage.googleapis.com'): url: /v1beta/models/x:stream?key={CLAVE}&alt=sse")

    monkeypatch.setattr(cg.requests, "post", post_roto)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(cg.ErrorClienteGemini) as e:
            list(cg.ClienteGemini(CLAVE).generar_contenido_en_streaming("p"))
    assert CLAVE not in e.value.mensaje_usuario and CLAVE not in caplog.text


def test_una_respuesta_de_error_tampoco_filtra_la_clave(monkeypatch, caplog):
    monkeypatch.setattr(cg.requests, "post", lambda *a, **k: RespuestaFalsa(403, texto=f"API key {CLAVE} not valid"))
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(cg.ErrorClienteGemini) as e:
            list(cg.ClienteGemini(CLAVE).generar_contenido_en_streaming("p"))
    assert e.value.es_error_autenticacion and CLAVE not in caplog.text


def test_el_modelo_de_gemini_se_puede_cambiar_por_entorno(monkeypatch):
    import importlib
    monkeypatch.setenv("NEMESIS_GEMINI_MODELO", "gemini-modelo-nuevo")
    assert importlib.reload(cg).MODELO_GEMINI == "gemini-modelo-nuevo"
    monkeypatch.delenv("NEMESIS_GEMINI_MODELO")
    assert importlib.reload(cg).MODELO_GEMINI == "gemini-2.5-flash"


# ─── Servicio ──────────────────────────────────────────────────────────────────
PLAN_REFERENCIA = {"pasos": [{"titulo": "Plantilla", "detalle": "Paso de la plantilla"}],
                   "tiempo_respuesta": "< 5 minutos", "prioridad": "CRÍTICA", "color_prioridad": "#ff0000",
                   "referencia_nist": "NIST SP 800-61r2 §3.2"}
DETECCION = DeteccionParaAnalizar("DoS", "CRÍTICO", 95.0,
                                  [{"feature": "count", "valor": 500, "normal": "1-20"}],
                                  [{"timestamp": "2026-01-01T10:00", "tipo_ataque": "Probe", "nivel": "ADVERTENCIA",
                                    "confianza": 82.0}])


def servicio(clave="clave", texto_ia=None, monkeypatch=None):
    if texto_ia is not None:
        class ClienteFalso:
            def __init__(self, clave_api): pass
            def generar_contenido_en_streaming(self, prompt):
                yield texto_ia
        monkeypatch.setattr(svc, "ClienteGemini", ClienteFalso)
    return ServicioRecomendacionesIA(lambda: clave, lambda *a: PLAN_REFERENCIA)


def plan_final(s):
    return [r for r in s.generar_plan_en_streaming(DETECCION) if isinstance(r, PlanRespuestaIncidente)][-1]


def test_el_markdown_que_devuelva_el_modelo_se_limpia_antes_de_mostrarlo(monkeypatch):
    texto = json.dumps({"pasos": [{"titulo": "**Aislar** el equipo", "detalle": "Revisar `iptables -L` y *confirmar*\n- bloquear"}],
                        "tiempo_respuesta": "< 5 min", "prioridad": "ALTA", "color_prioridad": "#ff0000",
                        "referencia_nist": "NIST SP 800-61 Rev. 2"})
    p = plan_final(servicio(texto_ia="```json\n" + texto + "\n```", monkeypatch=monkeypatch))
    assert p.generado_por_ia is True
    assert p.pasos[0]["titulo"] == "Aislar el equipo"
    assert not any(c in p.pasos[0]["detalle"] for c in "`*") and "- " not in p.pasos[0]["detalle"]


@pytest.mark.parametrize("entrada, esperado", [
    ("Puerto 443/tcp - revisar", "Puerto 443/tcp - revisar"),
    ("Tiempo: 5*3 = 15 y 2 * 4", "Tiempo: 5*3 = 15 y 2 * 4"),
    ("# Contención\n* Notificar", "Contención\nNotificar"),
])
def test_la_limpieza_de_markdown_no_altera_texto_normal(entrada, esperado):
    assert ServicioRecomendacionesIA._quitar_marcado(entrada) == esperado


@pytest.mark.parametrize("salida_ia", ["no es json", '{"pasos": []}', '{"pasos": [{"titulo": "x"}]}',
                                       '{"pasos": [{"titulo": "x", "detalle": "y"}]}'])
def test_un_formato_inesperado_cae_al_plan_de_respaldo_y_lo_avisa(monkeypatch, salida_ia):
    p = plan_final(servicio(texto_ia=salida_ia, monkeypatch=monkeypatch))
    assert p.generado_por_ia is False and "formato inesperado" in p.motivo_uso_plantilla
    assert p.pasos == PLAN_REFERENCIA["pasos"]


def test_sin_clave_se_usa_la_plantilla_y_se_notifica():
    p = plan_final(servicio(clave=None))
    assert p.generado_por_ia is False and "API key" in p.motivo_uso_plantilla


def test_con_el_limite_de_uso_alcanzado_se_usa_la_plantilla_y_se_notifica(monkeypatch):
    s = servicio(texto_ia='{"x": 1}', monkeypatch=monkeypatch)
    s._limitador_tasa = svc.LimitadorTasa(maximo_por_minuto=0, maximo_por_dia=10)   # límite 0: nada permitido
    p = plan_final(s)
    assert p.generado_por_ia is False and "límite" in p.motivo_uso_plantilla


def test_se_entregan_fragmentos_en_vivo_y_despues_el_plan_validado(monkeypatch):
    ok = json.dumps({"pasos": [{"titulo": "a", "detalle": "b"}], "tiempo_respuesta": "t", "prioridad": "BAJA",
                     "color_prioridad": "#fff", "referencia_nist": "n"})
    r = list(servicio(texto_ia=ok, monkeypatch=monkeypatch).generar_plan_en_streaming(DETECCION))
    assert isinstance(r[0], FragmentoPlanEnProgreso) and isinstance(r[-1], PlanRespuestaIncidente)


def test_el_prompt_incluye_clase_confianza_variables_y_alertas_recientes():
    prompt = servicio()._construir_prompt(DETECCION)
    for esperado in ("DoS", "95.0%", "count", "Probe", "ADVERTENCIA", "Rev. 2", "sintético"):
        assert esperado in prompt, esperado
    assert "sin\nformato Markdown" in prompt or "Markdown" in prompt


# ─── Router ───────────────────────────────────────────────────────────────────
def test_las_alertas_recientes_las_lee_el_servidor_no_el_cliente(cliente, monkeypatch):
    from app.routers import router_ia
    del_servidor = [{"timestamp": "t", "tipo_ataque": "U2R", "nivel": "CRÍTICO", "confianza": 97.0}]
    monkeypatch.setattr(router_ia, "obtener_alertas_recientes", lambda limite=8: del_servidor)
    visto = {}

    def generar_falso(self, deteccion):
        visto["d"] = deteccion
        yield PlanRespuestaIncidente(pasos=[], tiempo_respuesta="x", prioridad="BAJA", color_prioridad="#fff",
                                     referencia_nist="n", generado_por_ia=False)

    monkeypatch.setattr(ServicioRecomendacionesIA, "generar_plan_en_streaming", generar_falso)
    iniciar_sesion_http(cliente, crear_usuario_activo())
    r = cliente.post("/api/ia/recomendaciones", json={"clase": "DoS", "severidad": "CRÍTICO", "confianza": 95,
                                                       "features": [], "alertas_recientes": [{"tipo_ataque": "INYECTADO"}]})
    assert r.status_code == 200
    assert visto["d"].alertas_recientes == del_servidor, "el cliente no debe poder inyectar contexto en el prompt"


def test_el_estado_de_la_ia_ya_no_es_publico(cliente):
    assert cliente.get("/api/ia/config/estado").status_code == 401
