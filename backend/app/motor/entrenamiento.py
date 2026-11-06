"""
entrenamiento.py -- ÚNICO lugar donde se entrenan y evalúan los modelos Nemesis (MLP y RNN/LSTM)
con el pipeline de la tesis (Capítulo 4). Lo usan:

  * entrenar_nemesis.py -- entrenamiento completo desde la línea de comandos;
  * reentrenamiento.py  -- aprendizaje activo (base + muestras reales confirmadas);
  * experimentos.py     -- reproducción de la Tabla 7.

Así los tres producen modelos con exactamente la misma arquitectura, datos y artefactos.
"""
import json
import logging
import os

import joblib
import numpy as np

from app.motor.redes_neuronales import (
    construir_mlp, construir_rnn, crear_ventanas_temporales, entrenar_modelo, evaluar_modelo,
)

logger = logging.getLogger(__name__)

TAMANO_VENTANA_RNN = 10  # Sección 4.3: ventanas de 10 eventos consecutivos


def guardar_artefactos(datos: dict, directorio: str) -> None:
    """Escalador, codificadores y configuración que la inferencia necesita junto a los modelos.
    Joblib garantiza que las mismas transformaciones del entrenamiento se apliquen en inferencia."""
    os.makedirs(directorio, exist_ok=True)
    joblib.dump(datos["scaler"], os.path.join(directorio, "scaler.pkl"))
    joblib.dump(datos["encoders"], os.path.join(directorio, "encoders.pkl"))
    joblib.dump(datos["le_target"], os.path.join(directorio, "le_target.pkl"))
    with open(os.path.join(directorio, "config.json"), "w", encoding="utf-8") as archivo:
        json.dump({"n_features": datos["n_features"], "n_clases": datos["n_clases"],
                   "clases": datos["clases"]}, archivo, indent=2)


def entrenar_modelos_nemesis(datos: dict, directorio_destino: str, epochs: int = 30,
                             callback_progreso=None) -> dict:
    """Entrena MLP y RNN/LSTM con `datos` (salida de preparar_datos_con_reales_y_base), los evalúa
    sobre el conjunto de prueba FIJO y guarda modelos, métricas y artefactos en `directorio_destino`.

    Devuelve {"mlp", "rnn", "metricas_mlp", "metricas_rnn", "ventanas_test"}.
    """
    def avance(paso: str, porcentaje: int) -> None:
        if callback_progreso:
            callback_progreso(paso, porcentaje)

    X_train, y_train = datos["X_train"], datos["y_train"]
    X_val, y_val = datos["X_val"], datos["y_val"]
    X_test, y_test = datos["X_test"], datos["y_test"]
    clases, n_feat, n_clases = datos["clases"], datos["n_features"], datos["n_clases"]

    guardar_artefactos(datos, directorio_destino)

    avance(f"Entrenando MLP ({epochs} épocas)...", 30)
    mlp = construir_mlp(n_features=n_feat, n_clases=n_clases)
    entrenar_modelo(mlp, X_train, y_train, X_val, y_val, epochs=epochs, ruta_guardado=directorio_destino)

    avance(f"Entrenando RNN ({epochs} épocas)...", 60)
    Xs_tr, ys_tr = crear_ventanas_temporales(X_train, y_train, TAMANO_VENTANA_RNN)
    Xs_va, ys_va = crear_ventanas_temporales(X_val, y_val, TAMANO_VENTANA_RNN)
    Xs_te, ys_te = crear_ventanas_temporales(X_test, y_test, TAMANO_VENTANA_RNN)
    rnn = construir_rnn(n_features=n_feat, n_clases=n_clases, window_size=TAMANO_VENTANA_RNN)
    entrenar_modelo(rnn, Xs_tr, ys_tr, Xs_va, ys_va, epochs=epochs, ruta_guardado=directorio_destino)

    avance("Evaluando modelos...", 85)
    metricas_mlp = evaluar_modelo(mlp, X_test, y_test, clases, directorio_destino)
    metricas_rnn = evaluar_modelo(rnn, Xs_te, ys_te, clases, directorio_destino)

    return {"mlp": mlp, "rnn": rnn, "metricas_mlp": metricas_mlp, "metricas_rnn": metricas_rnn,
            "ventanas_test": (Xs_te, ys_te)}


def predicciones_de_clase(modelo, X) -> np.ndarray:
    return np.argmax(modelo.predict(X, verbose=0), axis=1)
