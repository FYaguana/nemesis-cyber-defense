"""
experimentos.py -- Reproduce la comparación de la Tabla 7 de la tesis (Sección 5.2):
los dos modelos Nemesis (MLP y RNN/LSTM) frente a cuatro clasificadores tradicionales
(Random Forest, Gradient Boosting, SVM y KNN), sobre el MISMO benchmark fijo:

  - entrenamiento: data/NSL_KDD_train.csv (15,000 registros) -> 85 % train / 15 % validación
  - prueba:        data/NSL_KDD_test.csv  (4,000 registros), nunca usada para ajustar nada

Todos usan el mismo pipeline de preparación (preparacion_datos.preparar_datos_con_reales_y_base
sin muestras reales), de modo que el número de variables de entrada es el REAL del sistema.

Uso (desde backend/):
    python -m app.motor.experimentos                      # solo calcula y reporta
    python -m app.motor.experimentos --guardar-modelos    # además reemplaza los modelos de models/

Salidas:
    models/experimentos_resultados.json   (todas las métricas, reproducibles)
    docs/TABLA7_resultados.md             (tabla lista para copiar a la tesis)
"""
import argparse
import json
import logging
import os
import random
import tempfile
import time
from datetime import datetime

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC

logger = logging.getLogger("NEMESIS-EXPERIMENTOS")

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TAMANO_VENTANA_RNN = 10


def _metricas(y_real, y_pred, clases) -> dict:
    """Recall, Precisión y F1 en promedio macro (cada clase pesa igual: así una clase rara
    como U2R no queda tapada por NORMAL), Accuracy y Recall por clase."""
    recall_por_clase = recall_score(y_real, y_pred, average=None, labels=range(len(clases)), zero_division=0)
    return {
        "recall": round(float(recall_score(y_real, y_pred, average="macro", zero_division=0)), 4),
        "precision": round(float(precision_score(y_real, y_pred, average="macro", zero_division=0)), 4),
        "f1": round(float(f1_score(y_real, y_pred, average="macro", zero_division=0)), 4),
        "accuracy": round(float(accuracy_score(y_real, y_pred)), 4),
        "recall_por_clase": {c: round(float(r), 4) for c, r in zip(clases, recall_por_clase)},
        "n_evaluadas": int(len(y_real)),
    }


def ejecutar(epochs: int = 30, semilla: int = 42, guardar_modelos: bool = False) -> dict:
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
    import tensorflow as tf
    from app.motor.preparacion_datos import preparar_datos_con_reales_y_base
    from app.motor.redes_neuronales import (construir_mlp, construir_rnn, crear_ventanas_temporales,
                                            entrenar_modelo, evaluar_modelo)

    random.seed(semilla); np.random.seed(semilla); tf.keras.utils.set_random_seed(semilla)

    datos = preparar_datos_con_reales_y_base([], seed=semilla)  # base NSL-KDD fija, sin muestras reales
    Xtr, ytr, Xva, yva = datos["X_train"], datos["y_train"], datos["X_val"], datos["y_val"]
    Xte, yte = datos["X_test"], datos["y_test"]
    clases, n_feat, n_clases = datos["clases"], datos["n_features"], datos["n_clases"]
    logger.info("Variables de entrada: %s | clases: %s | train %s / val %s / test %s",
                n_feat, clases, len(Xtr), len(Xva), len(Xte))

    destino = os.path.join(DIRECTORIO_BACKEND, "models") if guardar_modelos else tempfile.mkdtemp(prefix="nemesis_exp_")
    resultados, tiempos = {}, {}

    # ── Deep Learning (modelos Nemesis) ──────────────────────────────────────
    t = time.time()
    mlp = construir_mlp(n_features=n_feat, n_clases=n_clases)
    entrenar_modelo(mlp, Xtr, ytr, Xva, yva, epochs=epochs, ruta_guardado=destino)
    m = evaluar_modelo(mlp, Xte, yte, clases, destino)
    resultados["MLP Nemesis (Deep Learning)"] = _metricas(yte, np.argmax(mlp.predict(Xte, verbose=0), axis=1), clases)
    tiempos["MLP Nemesis (Deep Learning)"] = round(time.time() - t, 1)

    t = time.time()
    Xs_tr, ys_tr = crear_ventanas_temporales(Xtr, ytr, TAMANO_VENTANA_RNN)
    Xs_va, ys_va = crear_ventanas_temporales(Xva, yva, TAMANO_VENTANA_RNN)
    Xs_te, ys_te = crear_ventanas_temporales(Xte, yte, TAMANO_VENTANA_RNN)
    rnn = construir_rnn(n_features=n_feat, n_clases=n_clases, window_size=TAMANO_VENTANA_RNN)
    entrenar_modelo(rnn, Xs_tr, ys_tr, Xs_va, ys_va, epochs=epochs, ruta_guardado=destino)
    evaluar_modelo(rnn, Xs_te, ys_te, clases, destino)
    resultados["RNN/LSTM Nemesis (Deep Learning)"] = _metricas(
        ys_te, np.argmax(rnn.predict(Xs_te, verbose=0), axis=1), clases)
    tiempos["RNN/LSTM Nemesis (Deep Learning)"] = round(time.time() - t, 1)

    # ── Línea base tradicional (mismos datos, mismo preprocesamiento) ───────────
    tradicionales = {
        "Random Forest (Tradicional)": RandomForestClassifier(n_estimators=200, random_state=semilla, n_jobs=-1),
        "Gradient Boosting (Tradicional)": GradientBoostingClassifier(random_state=semilla),
        "SVM (Tradicional)": SVC(kernel="rbf", random_state=semilla),
        "KNN (Tradicional)": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
    }
    for nombre, modelo in tradicionales.items():
        t = time.time()
        modelo.fit(Xtr, ytr)
        resultados[nombre] = _metricas(yte, modelo.predict(Xte), clases)
        tiempos[nombre] = round(time.time() - t, 1)
        logger.info("%s -> Recall %.4f", nombre, resultados[nombre]["recall"])

    if guardar_modelos:
        # El motor de inferencia carga estos artefactos junto con los modelos (ver reentrenamiento.py).
        joblib.dump(datos["scaler"], os.path.join(destino, "scaler.pkl"))
        joblib.dump(datos["encoders"], os.path.join(destino, "encoders.pkl"))
        joblib.dump(datos["le_target"], os.path.join(destino, "le_target.pkl"))
        with open(os.path.join(destino, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"n_features": n_feat, "n_clases": n_clases, "clases": clases}, f, indent=2)

    salida = {
        "generado_en": datetime.now().isoformat(timespec="seconds"),
        "semilla": semilla, "epocas_maximas": epochs,
        "n_variables_entrada": n_feat,
        "n_train": len(Xtr), "n_validacion": len(Xva), "n_test": len(Xte),
        "clases": clases, "resultados": resultados, "segundos_entrenamiento": tiempos,
        "nota_rnn": ("Las ventanas se etiquetan con la clase del último evento (coherente con la "
                     "inferencia). El dataset sintético no tiene orden temporal entre registros, "
                     "así que el contexto de los 9 eventos previos no aporta información: ver 5.5."),
    }
    ruta_json = os.path.join(DIRECTORIO_BACKEND, "models", "experimentos_resultados.json")
    os.makedirs(os.path.dirname(ruta_json), exist_ok=True)
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(salida, f, ensure_ascii=False, indent=2)
    _escribir_tabla_markdown(salida)
    return salida


def _escribir_tabla_markdown(salida: dict) -> None:
    clases = salida["clases"]
    pct = lambda v: f"{v * 100:.2f}%"
    lineas = [
        f"# Tabla 7 – Resultados en el conjunto de prueba NSL-KDD (n={salida['n_test']})",
        "",
        f"Generado por `python -m app.motor.experimentos` el {salida['generado_en']} "
        f"(semilla {salida['semilla']}, {salida['n_variables_entrada']} variables de entrada).",
        "Recall, Precisión y F1 en promedio macro. Columnas de clase = Recall por clase.",
        "",
        "| Modelo | Recall ↑ | Precisión | F1-Score | Accuracy | " + " | ".join(clases) + " |",
        "|---|---|---|---|---|" + "---|" * len(clases),
    ]
    for nombre, m in salida["resultados"].items():
        lineas.append(f"| {nombre} | {pct(m['recall'])} | {pct(m['precision'])} | {pct(m['f1'])} | "
                      f"{pct(m['accuracy'])} | " + " | ".join(pct(m["recall_por_clase"][c]) for c in clases) + " |")
    lineas += ["", f"Evaluadas: MLP/tradicionales {salida['n_test']}; "
               f"RNN {salida['n_test'] - TAMANO_VENTANA_RNN + 1} ventanas.", "",
               f"> {salida['nota_rnn']}"]
    ruta = os.path.join(os.path.dirname(DIRECTORIO_BACKEND), "docs", "TABLA7_resultados.md")
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas) + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [NEMESIS-EXPERIMENTOS] %(message)s")
    ap = argparse.ArgumentParser(description="Reproduce la Tabla 7 de la tesis")
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--semilla", type=int, default=42)
    ap.add_argument("--guardar-modelos", action="store_true",
                    help="Reemplaza los modelos de models/ por los recién entrenados")
    a = ap.parse_args()
    out = ejecutar(a.epochs, a.semilla, a.guardar_modelos)
    for nombre, m in out["resultados"].items():
        print(f"{nombre:40s} Recall {m['recall']:.4f} | Prec {m['precision']:.4f} | F1 {m['f1']:.4f} | Acc {m['accuracy']:.4f}")
