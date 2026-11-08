"""Pantalla de login sin ofertas falsas y monitoreo que explica sus límites en la nube."""
from scapy.all import Ether, IP, TCP

from tests.test_regresiones_infra import leer


def test_la_configuracion_publica_es_accesible_sin_sesion_y_las_demo_estan_apagadas(cliente, monkeypatch):
    for variable in ("RENDER", "DYNO", "K_SERVICE", "FLY_APP_NAME", "RAILWAY_ENVIRONMENT"):
        monkeypatch.delenv(variable, raising=False)
    r = cliente.get("/api/auth/config-publica")
    assert r.status_code == 200 and r.json() == {"cuentas_demo": False, "captura_red_disponible": True}


def test_en_la_nube_la_configuracion_publica_indica_que_no_hay_captura_de_red(cliente, monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    assert cliente.get("/api/auth/config-publica").json()["captura_red_disponible"] is False


def test_la_configuracion_publica_refleja_la_variable_de_entorno(cliente, monkeypatch):
    monkeypatch.setenv("NEMESIS_CUENTAS_DEMO", "true")
    assert cliente.get("/api/auth/config-publica").json()["cuentas_demo"] is True


def test_el_login_oculta_cuentas_demo_y_microsoft_salvo_que_el_servidor_lo_indique():
    html = leer("frontend", "login.html")
    for elemento in ('id="btn-ms" style="display:none"', 'id="sep-ms" style="display:none"',
                     'id="demo-box" style="display:none"'):
        assert elemento in html, elemento
    assert "/api/auth/config-publica" in html
    assert "(demoActivo ? ' Usa un usuario demo.' : '')" in html, "no se debe sugerir cuentas demo si no existen"


def test_en_la_nube_el_monitoreo_explica_el_limite_en_vez_de_pedir_ser_root(monkeypatch, entorno):
    from app.motor.captura_red import GestorCapturaReal
    monkeypatch.setenv("RENDER", "true")
    g = GestorCapturaReal()
    ok, mensaje = g.iniciar_continuo()
    assert ok is False and g.activa is False and g.error == mensaje
    assert "nube" in mensaje and "propio equipo" in mensaje
    assert "root" not in mensaje.lower(), "pedir ser root en un servicio cloud es imposible de cumplir"


def test_sin_permisos_de_captura_el_mensaje_orienta_al_usuario(monkeypatch, entorno):
    import scapy.all as scapy_all
    from app.motor.captura_red import GestorCapturaReal

    def sniff_sin_permiso(*a, **k):
        raise PermissionError("Operation not permitted")

    class ProcesadorFalso:
        def analizar_trafico(self, m):
            return {"clase": "NORMAL", "confianza": 99.0, "severidad": "NORMAL"}

    monkeypatch.setattr(scapy_all, "sniff", sniff_sin_permiso)
    g = GestorCapturaReal()
    monkeypatch.setattr(g, "_preparar_procesador", lambda: ProcesadorFalso())
    g.activa = True
    g._ejecutar_continuo("eth0", 1)
    assert "Sin permisos para capturar paquetes" in g.error and "nube" in g.error and g.activa is False


def test_el_analizador_traduce_el_error_de_pagina_html_a_un_mensaje_entendible():
    html = leer("frontend", "dashboard.html")
    assert "function mensajeErrorRed" in html and "mensajeErrorRed(e)" in html
    assert "'❌ Error: '+e.message" not in html


def test_el_dashboard_oculta_el_monitoreo_y_no_lo_consulta_si_el_despliegue_no_captura_red():
    html = leer("frontend", "dashboard.html")
    assert "captura_red_disponible" in html
    assert "niRed.style.display = 'none'" in html
    assert "if(capturaDisponible) iniciarPollingRR();" in html
    assert "\n  iniciarPollingRR();\n  if(ROL_USUARIO" not in html, "ya no debe arrancar el sondeo sin condiciones"
