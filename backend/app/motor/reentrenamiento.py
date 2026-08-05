"""
reentrenamiento.py -- Reentrena los modelos MLP/RNN combinando el dataset
base NSL-KDD con tráfico real ya confirmado/corregido por un analista
humano (aprendizaje activo / human-in-the-loop).

Por qué NO se usa la propia predicción del modelo como etiqueta:
Si entrenáramos con lo que el modelo ya predijo, estaríamos reforzando sus
propios errores (por ejemplo, seguiría "aprendiendo" que las ráfagas de
descarga son DoS, cada vez con más confianza). Por eso solo se usan las
muestras que un analista marcó explícitamente como "Confirmar" (el modelo
acertó) o "Falso positivo" (el modelo se equivocó, era tráfico normal) desde
el Centro de Alertas -- esa es la etiqueta verdadera.
"""

import os
import json
import logging
import threading
from datetime import datetime

import joblib

from app.motor.preparacion_datos import preparar_datos_con_reales_y_base
from app.motor.redes_neuronales import (
    construir_mlp, construir_rnn, crear_ventanas_temporales,
    entrenar_modelo, evaluar_modelo,
)
from app.motor.base_datos import obtener_capturas_etiquetadas, guardar_metricas
from app.motor.procesador_nemesis import obtener_procesador

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TAMANO_VENTANA_RNN = 10

logger = logging.getLogger("nemesis.reentrenamiento")


class GestorReentrenamiento:
    """Corre el reentrenamiento en un hilo de fondo y expone su progreso
    para que el cliente lo consulte por streaming/polling."""

    def __init__(self):
        self.activo = False
        self.progreso = {"paso": "", "porcentaje": 0}
        self.error = None
        self.resultado = None

    def iniciar(self, epochs: int = 20):
        if self.activo:
            return False, "Ya hay un reentrenamiento en curso."
        self.activo = True
        self.error = None
        self.resultado = None
        self.progreso = {"paso": "Iniciando...", "porcentaje": 0}
        hilo = threading.Thread(target=self._ejecutar, args=(epochs,), daemon=True)
        hilo.start()
        return True, "Reentrenamiento iniciado."

    def _ejecutar(self, epochs):
        try:
            self.progreso = {"paso": "Recolectando muestras reales confirmadas...", "porcentaje": 5}
            muestras_reales = obtener_capturas_etiquetadas()
            logger.info("Muestras reales confirmadas disponibles: %s", len(muestras_reales))

            self.progreso = {"paso": "Preparando datos (base NSL-KDD + reales confirmadas)...", "porcentaje": 15}
            datos = preparar_datos_con_reales_y_base(muestras_reales)

            X_train, y_train = datos["X_train"], datos["y_train"]
            X_val, y_val = datos["X_val"], datos["y_val"]
            X_test, y_test = datos["X_test"], datos["y_test"]
            clases = datos["clases"]
            n_features, n_clases = datos["n_features"], datos["n_clases"]

            directorio_modelos = os.path.join(DIRECTORIO_BACKEND, "models")
            os.makedirs(directorio_modelos, exist_ok=True)

            joblib.dump(datos["scaler"], os.path.join(directorio_modelos, "scaler.pkl"))
            joblib.dump(datos["encoders"], os.path.join(directorio_modelos, "encoders.pkl"))
            joblib.dump(datos["le_target"], os.path.join(directorio_modelos, "le_target.pkl"))
            with open(os.path.join(directorio_modelos, "config.json"), "w") as archivo:
                json.dump({"n_features": n_features, "n_clases": n_clases, "clases": clases}, archivo, indent=2)

            self.progreso = {"paso": f"Entrenando MLP ({epochs} épocas)...", "porcentaje": 30}
            mlp = construir_mlp(n_features=n_features, n_clases=n_clases)
            entrenar_modelo(mlp, X_train, y_train, X_val, y_val, epochs=epochs, ruta_guardado=directorio_modelos)

            self.progreso = {"paso": f"Entrenando RNN ({epochs} épocas)...", "porcentaje": 60}
            X_seq_train, y_seq_train = crear_ventanas_temporales(X_train, y_train, TAMANO_VENTANA_RNN)
            X_seq_val, y_seq_val = crear_ventanas_temporales(X_val, y_val, TAMANO_VENTANA_RNN)
            X_seq_test, y_seq_test = crear_ventanas_temporales(X_test, y_test, TAMANO_VENTANA_RNN)
            rnn = construir_rnn(n_features=n_features, n_clases=n_clases, window_size=TAMANO_VENTANA_RNN)
            entrenar_modelo(rnn, X_seq_train, y_seq_train, X_seq_val, y_seq_val, epochs=epochs, ruta_guardado=directorio_modelos)

            self.progreso = {"paso": "Evaluando modelos...", "porcentaje": 85}
            metricas_mlp = evaluar_modelo(mlp, X_test, y_test, clases, directorio_modelos)
            guardar_metricas("Nemesis_MLP", metricas_mlp["recall"], metricas_mlp["precision"],
                              metricas_mlp["f1_score"], metricas_mlp)
            metricas_rnn = evaluar_modelo(rnn, X_seq_test, y_seq_test, clases, directorio_modelos)
            guardar_metricas("Nemesis_RNN", metricas_rnn["recall"], metricas_rnn["precision"],
                              metricas_rnn["f1_score"], metricas_rnn)

            self.progreso = {"paso": "Recargando modelos en el sistema en vivo...", "porcentaje": 95}
            obtener_procesador().cargar_modelos()

            self.resultado = {
                "n_muestras_reales": datos["n_muestras_reales"],
                "n_muestras_base": datos["n_muestras_base"],
                "metricas_mlp": metricas_mlp,
                "metricas_rnn": metricas_rnn,
                "completado_en": datetime.now().isoformat(),
            }
            self.progreso = {"paso": "Completado", "porcentaje": 100}
            logger.info("Reentrenamiento completado: %s", self.resultado)

        except Exception as error:
            logger.exception("Error durante el reentrenamiento")
            self.error = str(error)
        finally:
            self.activo = False

    def obtener_estado(self):
        return {"activo": self.activo, "progreso": self.progreso,
                "error": self.error, "resultado": self.resultado}


_gestor_global: "GestorReentrenamiento | None" = None


def obtener_gestor_reentrenamiento() -> GestorReentrenamiento:
    global _gestor_global
    if _gestor_global is None:
        _gestor_global = GestorReentrenamiento()
    return _gestor_global
