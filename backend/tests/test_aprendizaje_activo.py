"""Sección 4.2 (aprendizaje activo en 4 etapas) y 4.5 (captura). Etapa 1: cada flujo real se
guarda con la predicción del modelo; etapa 2: el analista etiqueta; etapa 3: solo entra al
ENTRENAMIENTO; etapa 4: recarga en caliente (cubierta en reentrenamiento.py)."""
import os
import pytest
from scapy.all import Ether, IP, TCP, UDP

from tests.conftest import crear_usuario_activo, iniciar_sesion_http


class ProcesadorFalso:
    def analizar_trafico(self, muestra):
        return {"clase": "DoS" if muestra.get("count", 0) > 50 else "NORMAL", "confianza": 91.5, "severidad": "CRÍTICO"}


def fila(**kw):
    base = {"timestamp": "2026-01-01T00:00:00", "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
            "src_port": 5000, "dst_port": 443, "src_mac": "B8:27:EB:00:00:01", "duration": 1.0,
            "protocol_type": "tcp", "service": "http", "flag": "SF", "src_bytes": 100, "dst_bytes": 0,
            "land": 0, "count": 3, "srv_count": 3, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "num_failed_logins": 0, "root_shell": 0, "logged_in": 0}
    base.update(kw)
    return base


def test_etapa1_cada_flujo_se_guarda_con_su_prediccion_y_metadatos(entorno):
    from app.motor.captura_red import GestorCapturaReal
    from app.motor import base_datos
    g = GestorCapturaReal()
    g._procesar_flujo(ProcesadorFalso(), fila(count=99), "scapy")
    r = g.resultados[0]
    assert r["_fuente"] == "red_real", "el dashboard solo muestra los botones de etiquetado si es 'red_real'"
    assert r["_backend"] == "scapy" and r["_dispositivo"] == "Raspberry Pi"
    assert r["_reputacion"]["nivel"] == "nuevo" and isinstance(r["_captura_id"], int)
    resumen = base_datos.obtener_resumen_validacion()
    assert resumen["total_flujos"] == 1 and resumen["distribucion_por_clase"] == {"DoS": 1}


def test_las_variables_de_metadato_no_llegan_al_modelo(entorno):
    from app.motor.captura_red import GestorCapturaReal
    recibido = {}

    class Espia(ProcesadorFalso):
        def analizar_trafico(self, muestra):
            recibido.update(muestra)
            return super().analizar_trafico(muestra)
    GestorCapturaReal()._procesar_flujo(Espia(), fila(), "scapy")
    assert not {"src_ip", "dst_ip", "src_mac", "timestamp", "src_port", "dst_port"} & set(recibido)


def test_la_reputacion_del_destino_se_acumula_durante_la_sesion(entorno):
    from app.motor.captura_red import GestorCapturaReal
    g = GestorCapturaReal()
    for _ in range(4):
        g._procesar_flujo(ProcesadorFalso(), fila(count=3), "scapy")
    assert g.resultados[-1]["_reputacion"]["nivel"] == "confiable"
    for _ in range(6):
        g._procesar_flujo(ProcesadorFalso(), fila(count=99), "scapy")
    assert g.resultados[-1]["_reputacion"]["nivel"] == "no_confiable"


def test_etapa2_el_analista_etiqueta_desde_la_api(cliente):
    from app.motor import base_datos
    iniciar_sesion_http(cliente, crear_usuario_activo())
    cid = base_datos.guardar_captura_real({"count": 1}, "DoS", 91.5)
    assert cliente.post(f"/api/alertas/capturas/{cid}/etiquetar", json={"etiqueta": "NORMAL"}).json() == {"ok": True}
    assert cliente.post(f"/api/alertas/capturas/{cid}/etiquetar", json={"etiqueta": "Inventada"}).status_code == 400
    assert base_datos.contar_capturas()["por_clase"] == {"NORMAL": 1}


def test_etapa3_las_capturas_del_modo_respaldo_no_se_usan_para_reentrenar(entorno):
    from app.motor import base_datos as bd
    for origen in ("scapy", "psutil"):
        cid = bd.guardar_captura_real({"count": 1}, "DoS", 90.0, origen=origen)
        bd.etiquetar_captura(cid, "NORMAL", "a@test.ec")
    assert len(bd.obtener_capturas_etiquetadas()) == 1
    assert len(bd.obtener_capturas_etiquetadas(incluir_aproximadas=True)) == 2


def test_las_muestras_reales_solo_entran_al_entrenamiento_nunca_al_test(entorno):
    from app.motor.preparacion_datos import preparar_datos_con_reales_y_base
    sin = preparar_datos_con_reales_y_base([])
    # Distintas entre sí: limpiar_datos() elimina duplicados exactos, como debe hacerlo.
    reales = [{"protocol_type": "tcp", "service": "http", "flag": "SF", "src_bytes": 10 + i, "label": "NORMAL"}
              for i in range(40)]
    con = preparar_datos_con_reales_y_base(reales)
    assert len(sin["X_test"]) == len(con["X_test"]) == 4000
    assert (sin["y_test"] == con["y_test"]).all(), "el benchmark de prueba debe ser idéntico entre reentrenamientos"
    assert len(con["X_train"]) + len(con["X_val"]) == 15000 + 40
    assert con["n_muestras_reales"] == 40 and con["n_muestras_base"] == 15000


def test_purga_conserva_las_etiquetadas_y_acota_las_demas(entorno):
    from app.motor import base_datos as bd
    ids = [bd.guardar_captura_real({"count": i}, "NORMAL", 99.0) for i in range(10)]
    bd.etiquetar_captura(ids[0], "DoS", "a@test.ec")
    assert bd.purgar_capturas_no_etiquetadas(max_filas=3) == 6
    assert bd.contar_capturas() == {"total": 4, "etiquetadas": 1, "por_clase": {"DoS": 1}}


def test_agregador_de_scapy_deriva_flags_y_mac_sin_npcap(entorno):
    """Scapy construye y analiza paquetes en Python puro: no hace falta Npcap para esta lógica."""
    from app.motor.captura_paquetes import AgregadorFlujos
    ag = AgregadorFlujos()
    mac = "b8:27:eb:00:00:09"
    ag.procesar_paquete(Ether(src=mac) / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=4000, dport=80, flags="S"))
    ag.procesar_paquete(Ether(src=mac) / IP(src="10.0.0.2", dst="1.1.1.1") / UDP(sport=4001, dport=53))
    filas = {f["dst_port"]: f for f in ag.construir_filas()}
    assert filas[80]["flag"] == "S0" and filas[80]["service"] == "http" and filas[80]["protocol_type"] == "tcp"
    assert filas[53]["service"] == "dns" and filas[53]["protocol_type"] == "udp"
    assert filas[80]["src_mac"] == mac
    assert filas[80]["num_failed_logins"] == 0 and filas[80]["root_shell"] == 0, \
        "las variables de auditoría de host no se inventan: valen 0 (Sección 4.5)"


def test_el_modo_respaldo_psutil_solo_emite_categorias_de_flag_conocidas():
    from app.motor.captura_psutil import _flag_desde_estado
    estados = ["ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT", "TIME_WAIT", "CLOSE", "CLOSING",
               "LAST_ACK", "FIN_WAIT1", "FIN_WAIT2", "NONE", "ESTADO_RARO"]
    assert {_flag_desde_estado(e) for e in estados} <= {"REJ", "RSTO", "S0", "SF"}


def test_autoinicio_no_arranca_en_la_nube(monkeypatch):
    from app.motor.captura_red import _autoinicio_habilitado
    monkeypatch.delenv("NEMESIS_MONITOREO_AUTOINICIO", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    assert _autoinicio_habilitado() is True
    monkeypatch.setenv("RENDER", "true")
    assert _autoinicio_habilitado() is False
    monkeypatch.setenv("NEMESIS_MONITOREO_AUTOINICIO", "true")
    assert _autoinicio_habilitado() is True


def test_endpoint_de_validacion_devuelve_el_resumen_y_el_csv(cliente):
    from app.motor import base_datos as bd
    iniciar_sesion_http(cliente, crear_usuario_activo())
    for clase in ("NORMAL", "NORMAL", "NORMAL", "DoS"):
        bd.guardar_captura_real({"count": 1}, clase, 95.0, flujo={"dst_ip": "8.8.8.8"}, dispositivo="Apple")
    r = cliente.get("/api/alertas/capturas/validacion").json()
    assert r["total_flujos"] == 4 and r["porcentaje_normal"] == 75.0
    assert r["dispositivos_identificados_distintos"] == 1 and r["destinos_distintos"] == 1
    csv = cliente.get("/api/alertas/capturas/validacion/csv")
    assert csv.headers["content-type"].startswith("text/csv")
    assert csv.text.splitlines()[0] == "minuto,total_flujos,flujos_no_normales"
    assert cliente.post("/api/monitoreo/iniciar", json={"backend": "inventado"}).status_code == 400


def test_si_libpcap_no_esta_disponible_la_captura_continua_sin_filtro_bpf(entorno, monkeypatch):
    """Regresión: en equipos sin libpcap, sniff(filter='ip') lanzaba 'Cannot compile filter' y el
    monitoreo se detenía. Ahora se reintenta sin filtro y la captura sigue funcionando."""
    import scapy.all as scapy_all
    from app.motor.captura_red import GestorCapturaReal
    llamadas = []
    g = GestorCapturaReal()

    def sniff_falso(iface=None, prn=None, store=False, timeout=None, filter=None, stop_filter=None):
        llamadas.append(filter)
        if filter:
            raise Exception("Cannot set filter: libpcap is not available. Cannot compile filter !")
        prn(Ether(src="b8:27:eb:00:00:07") / IP(src="10.0.0.2", dst="1.1.1.1") / TCP(sport=4000, dport=443, flags="A"))
        g._detener_solicitado.set()  # un solo ciclo con paquetes y termina

    monkeypatch.setattr(scapy_all, "sniff", sniff_falso)
    monkeypatch.setattr(g, "_preparar_procesador", lambda: ProcesadorFalso())
    g.activa = True
    g._ejecutar_continuo("eth0", 1)
    assert llamadas == ["ip", None], "primero con filtro; al fallar, reintento sin filtro"
    assert g.error is None and g.progreso["flujos_procesados"] == 1
    assert g.resultados[0]["_dispositivo"] == "Raspberry Pi"
