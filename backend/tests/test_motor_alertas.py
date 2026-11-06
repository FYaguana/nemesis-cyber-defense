"""Sección 4.4: consenso MLP+RNN, umbrales de alerta (Tabla 6) y cooldown. Se usan modelos
simulados con probabilidades fijas para probar la REGLA, independiente del entrenamiento."""
import numpy as np
import pytest
from sklearn.preprocessing import LabelEncoder

CLASES = ["DoS", "NORMAL", "Probe", "R2L", "U2R"]


class ModeloFalso:
    def __init__(self, clase, confianza):
        p = np.full(5, (1 - confianza) / 4)
        p[CLASES.index(clase)] = confianza
        self._p = p[np.newaxis, :]

    def predict(self, X, verbose=0):
        return self._p


def procesador(mlp, rnn):
    from app.motor.procesador_nemesis import ProcesadorNemesis
    p = ProcesadorNemesis()
    p.le_target = LabelEncoder().fit(CLASES)
    p.modelo_mlp, p.modelo_rnn = ModeloFalso(*mlp), ModeloFalso(*rnn)
    p._cargado = True
    p.preprocesar_muestra = lambda m: np.zeros((1, 45), dtype=np.float32)
    p._features_influyentes = lambda m, c: []
    p.buffer_predicciones = [np.zeros(45, dtype=np.float32)] * 9  # con el actual completa la ventana de 10
    return p


def test_umbrales_de_la_tabla_6():
    from app.motor import procesador_nemesis as pn
    assert (pn.UMBRAL_CRITICO, pn.UMBRAL_ADVERTENCIA, pn.UMBRAL_INFO) == (0.90, 0.70, 0.50)
    assert pn.COOLDOWN_SEGUNDOS == 15 * 60


@pytest.mark.parametrize("confianza, severidad", [
    (0.95, "CRÍTICO"), (0.90, "CRÍTICO"), (0.89, "ADVERTENCIA"), (0.70, "ADVERTENCIA"),
    (0.69, "INFORMACIÓN"), (0.50, "INFORMACIÓN"), (0.49, "NORMAL")])
def test_severidad_segun_umbral(entorno, confianza, severidad):
    r = procesador(("DoS", confianza), ("DoS", confianza)).analizar_trafico({})
    assert r["clase"] == "DoS" and r["severidad"] == severidad


def test_si_mlp_y_rnn_coinciden_la_confianza_es_la_mayor(entorno):
    r = procesador(("DoS", 0.93), ("DoS", 0.98)).analizar_trafico({})
    assert r["clase"] == "DoS" and r["confianza"] == pytest.approx(98.0)


def test_si_solo_el_rnn_detecta_ataque_la_confianza_se_multiplica_por_085(entorno):
    r = procesador(("NORMAL", 0.99), ("DoS", 0.96)).analizar_trafico({})
    assert r["clase"] == "DoS"
    assert r["confianza"] == pytest.approx(96 * 0.85, abs=0.01)
    assert r["severidad"] == "ADVERTENCIA"


def test_si_solo_el_mlp_detecta_ataque_manda_el_mlp(entorno):
    r = procesador(("Probe", 0.93), ("NORMAL", 0.99)).analizar_trafico({})
    assert r["clase"] == "Probe" and r["severidad"] == "CRÍTICO"


def test_cooldown_evita_alertas_repetidas_del_mismo_tipo(entorno):
    p = procesador(("DoS", 0.97), ("DoS", 0.97))
    assert p.analizar_trafico({})["alerta_generada"] is True
    assert p.analizar_trafico({})["alerta_generada"] is False, "dentro de los 15 min no se repite"


def test_severidad_informacion_no_genera_alerta_en_el_dashboard(entorno):
    r = procesador(("DoS", 0.60), ("DoS", 0.60)).analizar_trafico({})
    assert r["severidad"] == "INFORMACIÓN" and r["alerta_generada"] is False


@pytest.mark.parametrize("confianza, tiempo", [(0.95, "< 5 min"), (0.80, "< 30 min"), (0.60, "< 2 horas"), (0.30, None)])
def test_tiempo_de_respuesta_objetivo_de_la_tabla_6(entorno, confianza, tiempo):
    r = procesador(("DoS", confianza), ("DoS", confianza)).analizar_trafico({})
    assert r["tiempo_respuesta_objetivo"] == tiempo
