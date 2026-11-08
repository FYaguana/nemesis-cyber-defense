"""Pantalla de login sin ofertas falsas y monitoreo que explica sus límites en la nube."""
from scapy.all import Ether, IP, TCP

from tests.test_regresiones_infra import leer


def limpiar_nube(monkeypatch):
    for variable in ("RENDER", "DYNO", "K_SERVICE", "FLY_APP_NAME", "RAILWAY_ENVIRONMENT", "NEMESIS_PERMITIR_SMTP_EN_NUBE"):
        monkeypatch.delenv(variable, raising=False)


def test_la_configuracion_publica_es_accesible_sin_sesion_y_las_demo_estan_apagadas(cliente, monkeypatch):
    limpiar_nube(monkeypatch)
    r = cliente.get("/api/auth/config-publica")
    assert r.status_code == 200
    assert r.json() == {"cuentas_demo": False, "captura_red_disponible": True, "correo_disponible": True}


def test_en_la_nube_no_se_ofrece_captura_de_red_ni_correo(cliente, monkeypatch):
    limpiar_nube(monkeypatch)
    monkeypatch.setenv("RENDER", "true")
    c = cliente.get("/api/auth/config-publica").json()
    assert c["captura_red_disponible"] is False and c["correo_disponible"] is False


def test_un_plan_de_pago_puede_habilitar_el_correo_en_la_nube(cliente, monkeypatch):
    limpiar_nube(monkeypatch)
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("NEMESIS_PERMITIR_SMTP_EN_NUBE", "true")
    c = cliente.get("/api/auth/config-publica").json()
    assert c["correo_disponible"] is True and c["captura_red_disponible"] is False


def test_la_configuracion_publica_refleja_la_variable_de_entorno(cliente, monkeypatch):
    monkeypatch.setenv("NEMESIS_CUENTAS_DEMO", "true")
    assert cliente.get("/api/auth/config-publica").json()["cuentas_demo"] is True


def test_el_login_ya_no_tiene_boton_de_microsoft_y_oculta_las_cuentas_demo_por_defecto():
    """El botón era una simulación que no verificaba a nadie: se eliminó del código, no solo se oculta."""
    html = leer("frontend", "login.html")
    for resto in ("btn-ms", "loginMS", "Continuar con Microsoft", "Entra ID"):
        assert resto not in html, resto
    assert 'id="demo-box" style="display:none"' in html
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


def test_el_dashboard_no_ofrece_configurar_el_correo_si_el_despliegue_no_puede_enviarlo():
    html = leer("frontend", "dashboard.html")
    assert 'id="us-panel-correo"' in html and "CONFIG_PUBLICA.correo_disponible === false" in html
    assert "panel.style.display = 'none'" in html and 'id="us-inv-nota"' in html


def test_ninguna_pagina_del_frontend_ofrece_microsoft_ni_mantiene_otra_copia_del_login():
    """Regresion: index.html (la pagina de la RAIZ del sitio) era una copia antigua del login con el boton
    de Microsoft y las cuentas demo; solo se habia corregido login.html y el usuario seguia viendo lo viejo."""
    import os
    carpeta = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "frontend")
    for nombre in sorted(os.listdir(carpeta)):
        if nombre.endswith(".html"):
            html = leer("frontend", nombre)
            assert "Continuar con Microsoft" not in html and "btn-ms" not in html, nombre
            if nombre != "login.html":
                assert "USUARIOS DEMO" not in html, f"{nombre} es otra copia de la pantalla de acceso"


def test_la_raiz_del_sitio_lleva_a_la_pantalla_de_acceso_actual():
    assert "index login.html;" in leer("frontend", "nginx.conf.template")
    assert 'location.replace("login.html")' in leer("frontend", "index.html")
