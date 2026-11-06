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
import shutil
import tempfile
import logging
import threading
from datetime import datetime

from app.motor.preparacion_datos import preparar_datos_con_reales_y_base
from app.motor.entrenamiento import entrenar_modelos_nemesis
from app.motor.base_datos import obtener_capturas_etiquetadas, guardar_metricas
from app.motor.procesador_nemesis import obtener_procesador

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

            directorio_modelos = os.path.join(DIRECTORIO_BACKEND, "models")
            os.makedirs(directorio_modelos, exist_ok=True)

            # Se entrena en un directorio de PREPARACIÓN (dentro de models/, para que el reemplazo
            # final sea atómico en el mismo sistema de archivos). Si algo falla a mitad, los modelos
            # que están sirviendo tráfico quedan intactos (Sección 4.2: sin interrumpir el servicio).
            preparacion = tempfile.mkdtemp(prefix=".reentrenando_", dir=directorio_modelos)
            try:
                def avance(paso, porcentaje):
                    self.progreso = {"paso": paso, "porcentaje": porcentaje}

                entrenados = entrenar_modelos_nemesis(datos, preparacion, epochs=epochs, callback_progreso=avance)
                metricas_mlp, metricas_rnn = entrenados["metricas_mlp"], entrenados["metricas_rnn"]

                self.progreso = {"paso": "Publicando los nuevos modelos...", "porcentaje": 90}
                for nombre in os.listdir(preparacion):
                    os.replace(os.path.join(preparacion, nombre), os.path.join(directorio_modelos, nombre))
            finally:
                shutil.rmtree(preparacion, ignore_errors=True)

            guardar_metricas("Nemesis_MLP", metricas_mlp["recall"], metricas_mlp["precision"],
                             metricas_mlp["f1_score"], metricas_mlp)
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
