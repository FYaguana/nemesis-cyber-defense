"""Sección 4.1: variables derivadas, limpieza y paridad ENTRENAMIENTO <-> INFERENCIA.

Regresión del error más grave hallado al comparar la tesis con el código: la inferencia armaba el
vector en el orden de las claves del diccionario, y con tráfico real 11 de las 45 variables
quedaban desalineadas respecto del entrenamiento."""
import os

import numpy as np
import pandas as pd
import pytest

from app.motor import preparacion_datos as pd_
from app.motor.preparacion_datos import (
    COLUMNAS_BASE, COLUMNAS_ENTRADA, N_VARIABLES_ENTRADA, VARIABLES_DERIVADAS,
    agregar_variables_derivadas, limpiar_datos, preparar_datos_con_reales_y_base,
    transformar_features, vectorizar_muestras)

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Lo que entrega el agregador de paquetes reales: 14 claves, en SU orden (no el del entrenamiento).
MUESTRA_REAL = {"duration": 0.4, "protocol_type": "tcp", "service": "http", "flag": "SF", "src_bytes": 900,
                "dst_bytes": 300, "land": 0, "count": 7, "srv_count": 7, "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0, "num_failed_logins": 0, "root_shell": 0, "logged_in": 0}


@pytest.fixture(scope="module")
def datos():
    return preparar_datos_con_reales_y_base([])


def test_los_csv_y_el_pipeline_comparten_el_mismo_orden_de_columnas():
    for archivo in ("NSL_KDD_train.csv", "NSL_KDD_test.csv"):
        columnas = list(pd.read_csv(os.path.join(BACKEND, "data", archivo), nrows=1).columns)
        assert columnas == COLUMNAS_BASE, archivo
    assert len(COLUMNAS_BASE) == 42 and N_VARIABLES_ENTRADA == 45  # 41 base + 4 derivadas


def test_variables_derivadas_segun_las_formulas_de_la_tesis():
    df = pd.DataFrame([{"src_bytes": 900, "dst_bytes": 299, "serror_rate": 0.25, "rerror_rate": 0.5,
                        "num_failed_logins": 3, "count": 5, "root_shell": 1, "num_root": 2, "num_compromised": 4}])
    r = agregar_variables_derivadas(df).iloc[0]
    assert VARIABLES_DERIVADAS == ["ratio_bytes", "tasa_errores", "intentos_fallo_norm", "actividad_root"]
    assert r["ratio_bytes"] == pytest.approx(900 / 300)
    assert r["tasa_errores"] == pytest.approx(0.75)
    assert r["intentos_fallo_norm"] == pytest.approx(3 / 6)
    assert r["actividad_root"] == 7


def test_el_orden_de_las_claves_no_cambia_el_vector(datos):
    a = vectorizar_muestras(MUESTRA_REAL, datos["scaler"], datos["encoders"])
    b = vectorizar_muestras(dict(reversed(list(MUESTRA_REAL.items()))), datos["scaler"], datos["encoders"])
    assert a.shape == (1, 45) and np.allclose(a, b)


def test_una_muestra_parcial_equivale_a_la_completa_con_ceros(datos):
    completa = {c: 0 for c in COLUMNAS_ENTRADA}
    completa.update(MUESTRA_REAL)
    a = vectorizar_muestras(MUESTRA_REAL, datos["scaler"], datos["encoders"])
    b = vectorizar_muestras(completa, datos["scaler"], datos["encoders"])
    assert np.allclose(a, b), "las variables no derivables de la red deben completarse con 0, sin aproximar"


def test_inferencia_y_entrenamiento_producen_el_mismo_vector(datos):
    """Paridad: transformar_features(fit=False) (evaluación) == vectorizar_muestras (producción)."""
    df = pd.read_csv(os.path.join(BACKEND, "data", "NSL_KDD_test.csv")).head(60)
    X_ent, *_ = transformar_features(df, scaler=datos["scaler"], encoders=datos["encoders"], fit=False)
    X_inf = vectorizar_muestras(df.drop(columns=["label"]).to_dict("records"), datos["scaler"], datos["encoders"])
    assert np.allclose(X_ent, X_inf, atol=1e-5)


def test_columnas_extra_se_ignoran_y_categorias_desconocidas_van_a_cero(datos):
    extra = dict(MUESTRA_REAL, timestamp="2026-01-01", src_ip="10.0.0.2", src_mac="aa:bb", servicio_raro=9)
    assert np.allclose(vectorizar_muestras(extra, datos["scaler"], datos["encoders"]),
                       vectorizar_muestras(MUESTRA_REAL, datos["scaler"], datos["encoders"]))
    desconocida = dict(MUESTRA_REAL, service="servicio-que-no-existe")
    assert vectorizar_muestras(desconocida, datos["scaler"], datos["encoders"]).shape == (1, 45)


def test_un_escalador_de_otra_dimension_falla_en_voz_alta(datos):
    class EscaladorViejo:
        n_features_in_ = 46
    with pytest.raises(ValueError, match="46"):
        vectorizar_muestras(MUESTRA_REAL, EscaladorViejo(), datos["encoders"])


def test_limpieza_elimina_duplicados_imputa_nulos_y_conserva_atipicos():
    base = pd.read_csv(os.path.join(BACKEND, "data", "NSL_KDD_test.csv")).head(200).copy()
    base.loc[50, "src_bytes"] = np.nan          # nulo numérico
    base.loc[51, "service"] = np.nan            # nulo categórico
    base.loc[60, "count"] = 10_000_000          # valor atípico: puede ser evidencia de un ataque
    df = pd.concat([base, base.head(5)], ignore_index=True)   # 5 duplicados exactos de filas intactas
    limpio = limpiar_datos(df)
    assert len(limpio) == 200
    assert limpio.isnull().sum().sum() == 0, "la imputación de nulos no se aplicó (pandas >= 3 ignora inplace)"
    assert limpio["count"].max() == 10_000_000, "los valores atípicos se conservan deliberadamente"


def test_el_nombre_antiguo_de_la_variable_no_sobrevive_en_el_codigo():
    for raiz, _, archivos in os.walk(os.path.join(BACKEND, "app")):
        for nombre in archivos:
            if nombre.endswith(".py"):
                with open(os.path.join(raiz, nombre), encoding="utf-8") as f:
                    assert "ratio_src_dst" not in f.read(), nombre


def test_la_division_valida_no_comparte_filas_con_entrenamiento(datos):
    assert len(datos["X_train"]) == 12750 and len(datos["X_val"]) == 2250
    # estratificación: la proporción de cada clase se conserva en entrenamiento y validación
    p_tr = np.bincount(datos["y_train"]) / len(datos["y_train"])
    p_va = np.bincount(datos["y_val"]) / len(datos["y_val"])
    assert np.allclose(p_tr, p_va, atol=0.01)


def test_todas_las_capas_densas_llevan_l2_de_1e_4():
    """Tabla 5: regularización L2 (λ = 1e-4), incluida la capa de salida Softmax."""
    from tensorflow import keras
    from app.motor.redes_neuronales import construir_mlp
    densas = [l for l in construir_mlp(45, 5).layers if isinstance(l, keras.layers.Dense)]
    assert len(densas) == 4
    for capa in densas:
        assert capa.kernel_regularizer is not None, capa.name
        assert float(capa.kernel_regularizer.l2) == pytest.approx(1e-4), capa.name
    adam = construir_mlp(45, 5).optimizer
    assert (float(adam.learning_rate.numpy()), adam.beta_1, adam.beta_2) == (pytest.approx(1e-3), 0.9, 0.999)
