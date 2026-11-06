"""Secciones 4.1 y 4.3: pipeline de datos (15,000 / 4,000, 85/15, sin fuga), arquitectura MLP
(Tabla 5) y ventanas del RNN. Incluye una prueba de consistencia de los modelos ENTREGADOS."""
import json
import os

import joblib
import numpy as np
import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELOS = os.path.join(BACKEND, "models")


@pytest.fixture(scope="module")
def datos():
    from app.motor.preparacion_datos import preparar_datos_con_reales_y_base
    return preparar_datos_con_reales_y_base([])


def test_division_de_datos_15000_4000_y_85_15(datos):
    assert len(datos["X_train"]) == 12750 and len(datos["X_val"]) == 2250
    assert len(datos["X_test"]) == 4000
    assert datos["n_features"] == 45


def test_el_scaler_se_ajusta_solo_con_entrenamiento(datos):
    """Sección 4.1: μ y σ se calculan EXCLUSIVAMENTE sobre el conjunto de entrenamiento.
    Entrenamiento queda normalizado (media 0, desviación 1) y validación NO (no participó del ajuste)."""
    assert np.allclose(datos["X_train"].mean(axis=0), 0, atol=1e-3)
    desv = datos["X_train"].std(axis=0)
    assert np.allclose(desv[desv > 0], 1, atol=1e-2)
    assert float(np.abs(datos["X_val"].mean(axis=0)).max()) > 1e-3, "la validación influyó en el escalador"
    assert datos["scaler"].n_features_in_ == 45


def test_arquitectura_mlp_coincide_con_la_tabla_5():
    from tensorflow import keras
    from app.motor.redes_neuronales import construir_mlp
    m = construir_mlp(n_features=45, n_clases=5)
    densas = [l for l in m.layers if isinstance(l, keras.layers.Dense)]
    assert [d.units for d in densas] == [256, 128, 64, 5]
    assert [d.activation.__name__ for d in densas] == ["relu", "relu", "relu", "softmax"]
    assert [l.rate for l in m.layers if isinstance(l, keras.layers.Dropout)] == [0.3, 0.3, 0.3]
    assert len([l for l in m.layers if isinstance(l, keras.layers.BatchNormalization)]) == 3
    assert float(m.optimizer.learning_rate.numpy()) == pytest.approx(1e-3)


def test_ventanas_del_rnn_se_etiquetan_con_el_ultimo_evento():
    """Es la forma en que el motor usa el RNN en inferencia (evento actual = último de la ventana).
    Regresión: antes se etiquetaba con el evento SIGUIENTE y el modelo colapsaba (Recall 0.20)."""
    from app.motor.redes_neuronales import crear_ventanas_temporales
    X = np.arange(30 * 3, dtype=np.float32).reshape(30, 3)
    y = np.arange(30)
    Xs, ys = crear_ventanas_temporales(X, y, window_size=10)
    assert Xs.shape == (21, 10, 3) and len(ys) == 21
    assert (Xs[0] == X[0:10]).all() and ys[0] == 9 and ys[-1] == 29
    with pytest.raises(ValueError):
        crear_ventanas_temporales(X[:5], y[:5], 10)


def test_los_modelos_entregados_coinciden_con_el_pipeline_actual():
    config = json.load(open(os.path.join(MODELOS, "config.json")))
    scaler = joblib.load(os.path.join(MODELOS, "scaler.pkl"))
    assert config["n_features"] == scaler.n_features_in_ == 45
    assert config["clases"] == ["DoS", "NORMAL", "Probe", "R2L", "U2R"]
    # Evaluados sobre el benchmark fijo de 4,000 (RNN: 4,000 - 10 + 1 ventanas), no sobre un split antiguo.
    for nombre, esperado in (("Nemesis_MLP", 4000), ("Nemesis_RNN", 3991)):
        m = json.load(open(os.path.join(MODELOS, f"{nombre}_metricas.json")))
        evaluadas = sum(m["reporte"][c]["support"] for c in config["clases"])
        assert evaluadas == esperado, f"{nombre}: modelo desactualizado (reentrenar con experimentos.py)"
        assert m["recall"] > 0.95, f"{nombre} no supera el 95% de Recall que afirma la tesis"


def test_el_procesador_carga_los_modelos_entregados_y_clasifica_el_trafico_demo(entorno):
    """Los botones de simulación del dashboard deben ser coherentes con el modelo entregado."""
    from app.motor.procesador_nemesis import ProcesadorNemesis
    p = ProcesadorNemesis(ruta_modelos=MODELOS)
    assert p.cargar_modelos() is True
    for tipo, clase in (("normal", "NORMAL"), ("dos", "DoS"), ("probe", "Probe"), ("r2l", "R2L"), ("u2r", "U2R")):
        aciertos = sum(p.analizar_trafico(p.generar_trafico_demo(tipo))["clase"] == clase for _ in range(10))
        assert aciertos >= 9, f"demo '{tipo}': solo {aciertos}/10 clasificadas como {clase}"
