"""
entrenar_nemesis.py -- Entrena el sistema completo (MLP + RNN/LSTM) desde cero.

    python -m app.motor.entrenar_nemesis                 # solo dataset base (15,000 / 4,000)
    python -m app.motor.entrenar_nemesis --con-reales    # + muestras reales confirmadas por analistas
    python -m app.motor.entrenar_nemesis --epochs 40 --semilla 7

Escribe en backend/models/: Nemesis_MLP.keras, Nemesis_RNN.keras, sus métricas, scaler.pkl,
encoders.pkl, le_target.pkl y config.json. Es el script que los mensajes del sistema recomiendan
ejecutar cuando los modelos no están cargados.
"""
import argparse
import logging
import os
import random

import numpy as np

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main(argv=None) -> dict:
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
    ap = argparse.ArgumentParser(description="Entrena los modelos Nemesis (MLP + RNN/LSTM)")
    ap.add_argument("--epochs", type=int, default=30, help="épocas máximas (con EarlyStopping)")
    ap.add_argument("--semilla", type=int, default=42)
    ap.add_argument("--con-reales", action="store_true",
                    help="incluye las muestras reales confirmadas por analistas (base de datos)")
    ap.add_argument("--destino", default=os.path.join(DIRECTORIO_BACKEND, "models"))
    args = ap.parse_args(argv)

    import tensorflow as tf
    from app.motor.entrenamiento import entrenar_modelos_nemesis
    from app.motor.preparacion_datos import preparar_datos_con_reales_y_base

    random.seed(args.semilla)
    np.random.seed(args.semilla)
    tf.keras.utils.set_random_seed(args.semilla)

    reales = []
    if args.con_reales:
        from app.motor.base_datos import init_db, obtener_capturas_etiquetadas
        init_db()
        reales = obtener_capturas_etiquetadas()
        print(f"Muestras reales confirmadas incluidas: {len(reales)}")

    datos = preparar_datos_con_reales_y_base(reales, seed=args.semilla)
    resultado = entrenar_modelos_nemesis(datos, args.destino, epochs=args.epochs)
    for nombre in ("metricas_mlp", "metricas_rnn"):
        m = resultado[nombre]
        print(f"{m['modelo']:12s} Recall {m['recall']:.4f} | Precisión {m['precision']:.4f} | F1 {m['f1_score']:.4f}")
    print(f"Modelos guardados en: {args.destino}")
    return resultado


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [NEMESIS-ENTRENAMIENTO] %(message)s")
    main()
