"""
red_neuronal.py – Modelos de Deep Learning (MLP + RNN/LSTM)
Sistema Nemesis Cyber Defense
Tesis: Predicción y Prevención de Ciberataques con Deep Learning
"""

import numpy as np
import os
import logging
import json

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, regularizers, callbacks
from sklearn.metrics import (classification_report, confusion_matrix,
                             recall_score, precision_score, f1_score)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NEMESIS-NN] %(message)s")
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
#  MODELO 1: MLP – Red Neuronal Multicapa
# ══════════════════════════════════════════════════════════════════

def construir_mlp(n_features: int, n_clases: int,
                  capas_ocultas=(256, 128, 64),
                  dropout_rate=0.3,
                  l2_reg=1e-4) -> keras.Model:
    """
    Arquitectura MLP descrita en la tesis (Sección 2.1):
    Capa Entrada → Capas Ocultas con BatchNorm + Dropout → Capa Salida
    """
    entradas = keras.Input(shape=(n_features,), name="entrada_red")
    x = entradas

    for i, neuronas in enumerate(capas_ocultas):
        x = layers.Dense(
            neuronas,
            activation="relu",
            kernel_regularizer=regularizers.l2(l2_reg),
            name=f"oculta_{i+1}"
        )(x)
        x = layers.BatchNormalization(name=f"bn_{i+1}")(x)
        x = layers.Dropout(dropout_rate, name=f"dropout_{i+1}")(x)

    # Capa de salida – clasificación multiclase
    salida = layers.Dense(
        n_clases,
        activation="softmax",
        name="salida_probabilidades"
    )(x)

    modelo = keras.Model(inputs=entradas, outputs=salida, name="Nemesis_MLP")

    modelo.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    logger.info(f"MLP construido: {modelo.count_params():,} parámetros")
    return modelo


# ══════════════════════════════════════════════════════════════════
#  MODELO 2: RNN/LSTM – Red Neuronal Recurrente (estilo Tiresias)
# ══════════════════════════════════════════════════════════════════

def construir_rnn(n_features: int, n_clases: int,
                  window_size: int = 10,
                  lstm_units=(128, 64),
                  dropout_rate=0.3) -> keras.Model:
    """
    Arquitectura LSTM inspirada en Tiresias (Shen et al., 2018)
    para predicción secuencial de eventos de seguridad.
    """
    entradas = keras.Input(shape=(window_size, n_features), name="entrada_secuencia")
    x = entradas

    for i, unidades in enumerate(lstm_units):
        return_seq = (i < len(lstm_units) - 1)
        x = layers.LSTM(
            unidades,
            return_sequences=return_seq,
            dropout=dropout_rate,
            recurrent_dropout=dropout_rate * 0.5,
            name=f"lstm_{i+1}"
        )(x)

    x = layers.Dense(64, activation="relu", name="densa_final")(x)
    x = layers.Dropout(dropout_rate)(x)

    salida = layers.Dense(n_clases, activation="softmax", name="salida")(x)

    modelo = keras.Model(inputs=entradas, outputs=salida, name="Nemesis_RNN")
    modelo.compile(
        optimizer=keras.optimizers.Adam(learning_rate=5e-4),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    logger.info(f"RNN/LSTM construido: {modelo.count_params():,} parámetros")
    return modelo


def crear_ventanas_temporales(X: np.ndarray, y: np.ndarray,
                               window_size: int = 10) -> tuple:
    """Crea secuencias deslizantes (Sección 3.2.4 – Windowing)."""
    X_seq, y_seq = [], []
    for i in range(len(X) - window_size):
        X_seq.append(X[i:i + window_size])
        y_seq.append(y[i + window_size])
    return np.array(X_seq, dtype=np.float32), np.array(y_seq)


# ══════════════════════════════════════════════════════════════════
#  ENTRENAMIENTO
# ══════════════════════════════════════════════════════════════════

def entrenar_modelo(modelo: keras.Model,
                    X_train, y_train,
                    X_val, y_val,
                    epochs=30, batch_size=256,
                    ruta_guardado="models") -> dict:
    """
    Entrena el modelo con callbacks: EarlyStopping y ReduceLROnPlateau.
    """
    os.makedirs(ruta_guardado, exist_ok=True)
    nombre = modelo.name
    ruta_modelo = os.path.join(ruta_guardado, f"{nombre}.keras")

    cbs = [
        callbacks.EarlyStopping(
            monitor="val_loss", patience=7, restore_best_weights=True,
            verbose=1),
        callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=3,
            min_lr=1e-6, verbose=1),
        callbacks.ModelCheckpoint(
            ruta_modelo, save_best_only=True, verbose=0),
    ]

    logger.info(f"Entrenando {nombre}: {X_train.shape[0]} muestras | {epochs} épocas máx.")
    historia = modelo.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=cbs,
        verbose=1
    )

    logger.info(f"Modelo guardado en: {ruta_modelo}")
    return {
        "historia": historia.history,
        "ruta": ruta_modelo,
        "nombre": nombre
    }


# ══════════════════════════════════════════════════════════════════
#  EVALUACIÓN – Métricas del Capítulo 2.6 de la tesis
# ══════════════════════════════════════════════════════════════════

def evaluar_modelo(modelo: keras.Model,
                   X_test: np.ndarray, y_test: np.ndarray,
                   clases: list, ruta_guardado="models") -> dict:
    """
    Calcula Precisión, Recall (prioritario), F1-Score y matriz de confusión.
    Basado en Sección 2.6 – Identificación de Variables Críticas.
    """
    y_pred_prob = modelo.predict(X_test, verbose=0)
    y_pred = np.argmax(y_pred_prob, axis=1)

    recall_macro    = recall_score(y_test, y_pred, average="macro", zero_division=0)
    precision_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
    f1_macro        = f1_score(y_test, y_pred, average="macro", zero_division=0)

    logger.info(f"\n{'='*55}")
    logger.info(f"  EVALUACIÓN: {modelo.name}")
    logger.info(f"  Recall (prioritario): {recall_macro:.4f}")
    logger.info(f"  Precisión:            {precision_macro:.4f}")
    logger.info(f"  F1-Score:             {f1_macro:.4f}")
    logger.info(f"{'='*55}")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=clases, zero_division=0))

    # Guardar métricas
    metricas = {
        "modelo":    modelo.name,
        "recall":    round(recall_macro, 4),
        "precision": round(precision_macro, 4),
        "f1_score":  round(f1_macro, 4),
        "reporte":   classification_report(y_test, y_pred, target_names=clases,
                                           zero_division=0, output_dict=True),
        "matriz_confusion": confusion_matrix(y_test, y_pred).tolist(),
        "clases": clases
    }

    os.makedirs(ruta_guardado, exist_ok=True)
    ruta_json = os.path.join(ruta_guardado, f"{modelo.name}_metricas.json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(metricas, f, indent=2, ensure_ascii=False)
    logger.info(f"Métricas guardadas en: {ruta_json}")

    return metricas


def predecir(modelo: keras.Model, X: np.ndarray,
             le_target, umbral_critico=0.90,
             umbral_advertencia=0.70) -> list:
    """
    Genera predicciones con nivel de severidad según Sección 3.3.1:
    Crítico >90% | Advertencia 70-90% | Información 50-70%
    """
    probs = modelo.predict(X, verbose=0)
    resultados = []
    for i, prob in enumerate(probs):
        idx_clase = np.argmax(prob)
        confianza = float(prob[idx_clase])
        clase     = le_target.inverse_transform([idx_clase])[0]

        if clase != "NORMAL":
            if confianza >= umbral_critico:
                severidad = "CRÍTICO"
            elif confianza >= umbral_advertencia:
                severidad = "ADVERTENCIA"
            else:
                severidad = "INFORMACIÓN"
        else:
            severidad = "NORMAL"

        resultados.append({
            "clase":       clase,
            "confianza":   round(confianza * 100, 2),
            "severidad":   severidad,
            "probabilidades": {
                le_target.inverse_transform([j])[0]: round(float(p) * 100, 2)
                for j, p in enumerate(prob)
            }
        })
    return resultados


if __name__ == "__main__":
    print("red_neuronal.py – Módulo de modelos Deep Learning")
    print("Use entrenar_nemesis.py para entrenar el sistema completo.")
