"""Sección 4.8: limitador de tasa de ventana deslizante y tolerancia a formatos de respuesta."""
from app.nucleo.limitador_tasa import LimitadorTasa


def test_limite_por_minuto():
    lim = LimitadorTasa(maximo_por_minuto=2, maximo_por_dia=100)
    assert lim.evaluar_solicitud().permitida and lim.evaluar_solicitud().permitida
    r = lim.evaluar_solicitud()
    assert not r.permitida and "minuto" in r.motivo and r.segundos_espera_sugerida > 0


def test_limite_por_dia():
    lim = LimitadorTasa(maximo_por_minuto=100, maximo_por_dia=2)
    lim.evaluar_solicitud(); lim.evaluar_solicitud()
    r = lim.evaluar_solicitud()
    assert not r.permitida and "diario" in r.motivo


def test_la_ventana_deslizante_libera_cupo(monkeypatch):
    import time
    from app.nucleo import limitador_tasa
    t = [1000.0]
    monkeypatch.setattr(limitador_tasa.time, "time", lambda: t[0])
    lim = LimitadorTasa(maximo_por_minuto=1, maximo_por_dia=100)
    assert lim.evaluar_solicitud().permitida
    assert not lim.evaluar_solicitud().permitida
    t[0] += 61
    assert lim.evaluar_solicitud().permitida


def test_el_plan_se_extrae_aunque_el_modelo_lo_envuelva_en_markdown():
    from app.servicios.servicio_recomendaciones_ia import ServicioRecomendacionesIA
    s = ServicioRecomendacionesIA.__new__(ServicioRecomendacionesIA)
    assert s._extraer_plan_json('{"a": 1}') == {"a": 1}
    assert s._extraer_plan_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert s._extraer_plan_json('Aquí está: {"a": 1} listo') == {"a": 1}
    assert s._extraer_plan_json("sin json") is None
