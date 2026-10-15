"""Secciones 4.4 y 4.5: fabricante por OUI (tabla local) y confiabilidad de destino."""
import pytest
from app.motor.identificacion_dispositivos import (
    ReputacionDestinos, es_mac_privada, identificar_dispositivo, normalizar_mac)


@pytest.mark.parametrize("mac, esperado", [
    ("B8:27:EB:12:34:56", "Raspberry Pi"),
    ("b8-27-eb-12-34-56", "Raspberry Pi"),       # otros formatos de escritura
    ("B827.EB12.3456", "Raspberry Pi"),
    ("08:00:27:aa:bb:cc", "VirtualBox"),
    ("00:50:56:aa:bb:cc", "VMware"),
    ("60:FD:A6:00:00:01", "Apple"),
])
def test_fabricante_por_prefijo_oui(mac, esperado):
    assert identificar_dispositivo(mac) == esperado


def test_mac_privada_o_aleatoria_se_marca_generica():
    assert es_mac_privada("02:42:ac:11:00:02")   # Docker
    assert es_mac_privada("DA:A1:19:00:00:01")   # bit 'localmente administrada' (teléfonos modernos)
    assert not es_mac_privada("B8:27:EB:00:00:01")
    assert "genérico" in identificar_dispositivo("02:42:ac:11:00:02")


@pytest.mark.parametrize("entrada", [None, "", "zz:zz", "12:34", 123])
def test_mac_invalida_o_ausente_es_no_identificado(entrada):
    assert normalizar_mac(entrada) is None
    assert "no identificado" in identificar_dispositivo(entrada)


def test_oui_asignado_pero_fuera_de_la_tabla_curada_es_no_identificado():
    # 00:00:01 es un prefijo real del IEEE (Xerox) que NO está en la tabla de marcas comunes.
    assert identificar_dispositivo("00:00:01:11:22:33") == "Dispositivo no identificado"


def test_la_mac_de_loopback_se_reconoce_como_equipo_local():
    assert identificar_dispositivo("00:00:00:00:00:00") == "Equipo local (loopback)"


def _registrar(rep, ip, normales, anomalas):
    for _ in range(normales):
        rep.registrar(ip, False)
    for _ in range(anomalas):
        rep.registrar(ip, True)


def test_menos_de_3_observaciones_es_sin_historial_suficiente():
    r = ReputacionDestinos()
    assert r.evaluar("1.1.1.1")["nivel"] == "nuevo"
    _registrar(r, "1.1.1.1", 2, 0)
    assert r.evaluar("1.1.1.1")["nivel"] == "nuevo"


def test_tasa_anomala_cero_es_confiable():
    r = ReputacionDestinos()
    _registrar(r, "8.8.8.8", 3, 0)
    ev = r.evaluar("8.8.8.8")
    assert ev["nivel"] == "confiable" and ev["tasa_anomala"] == 0


@pytest.mark.parametrize("anomalas, nivel", [(39, "revisar"), (40, "no_confiable"), (100, "no_confiable"), (1, "revisar")])
def test_umbral_de_40_por_ciento_para_poco_confiable(anomalas, nivel):
    r = ReputacionDestinos()
    _registrar(r, "9.9.9.9", 100 - anomalas, anomalas)
    assert r.evaluar("9.9.9.9")["nivel"] == nivel


def test_la_evaluacion_no_cuenta_el_flujo_actual():
    r = ReputacionDestinos()
    _registrar(r, "5.5.5.5", 3, 0)
    assert r.evaluar("5.5.5.5")["nivel"] == "confiable"
    r.registrar("5.5.5.5", True)  # recién DESPUÉS de evaluar se registra el flujo
    assert r.evaluar("5.5.5.5")["observaciones"] == 4


def test_memoria_acotada_descarta_destinos_antiguos():
    r = ReputacionDestinos(max_destinos=3)
    for ip in ("a", "b", "c", "d"):
        r.registrar(ip, False)
    assert r.evaluar("a")["observaciones"] == 0 and r.evaluar("d")["observaciones"] == 1
