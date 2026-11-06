"""
procesador_nemesis.py – Motor de Predicción en Tiempo Real
Sistema Nemesis Cyber Defense
Implementa: inferencia, sistema de alertas (Sección 3.3) y análisis de drift
"""

import os
import json
import logging
import numpy as np
import joblib
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Umbrales de alerta (Tabla 6 de la tesis, Sección 4.4)
UMBRAL_CRITICO     = 0.90
UMBRAL_ADVERTENCIA = 0.70
UMBRAL_INFO        = 0.50

# Tiempo de respuesta objetivo por nivel de severidad (Tabla 6). Es un objetivo de diseño del
# sistema para priorizar la atención del analista; se muestra junto a cada alerta.
TIEMPO_RESPUESTA_OBJETIVO = {
    "CRÍTICO": "< 5 min",
    "ADVERTENCIA": "< 30 min",
    "INFORMACIÓN": "< 2 horas",
    "NORMAL": None,
}

# Ventana de confirmación (Sección 3.3.2)
VENTANA_CONFIRMACION = 3  # N predicciones consecutivas
COOLDOWN_SEGUNDOS    = 60 * 15  # 15 minutos


class ProcesadorNemesis:
    """
    Motor principal de inferencia y generación de alertas.
    Carga los modelos entrenados y procesa datos en tiempo real.
    """

    def __init__(self, ruta_modelos="models"):
        self.ruta_modelos = ruta_modelos
        self.modelo_mlp   = None
        self.modelo_rnn   = None
        self.scaler       = None
        self.encoders     = None
        self.le_target    = None
        self.config       = {}
        self.buffer_predicciones = []  # Para ventana de confirmación
        self.ultima_alerta = {}        # Control de cooldown por tipo
        self._cargado     = False

    def cargar_modelos(self) -> bool:
        """Carga modelos y objetos de transformación desde disco."""
        try:
            import tensorflow as tf
            os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

            config_path = os.path.join(self.ruta_modelos, "config.json")
            if not os.path.exists(config_path):
                logger.error("No se encontró config.json. Ejecuta `python -m app.motor.entrenar_nemesis` primero.")
                return False

            with open(config_path) as f:
                self.config = json.load(f)

            self.scaler    = joblib.load(os.path.join(self.ruta_modelos, "scaler.pkl"))
            self.encoders  = joblib.load(os.path.join(self.ruta_modelos, "encoders.pkl"))
            self.le_target = joblib.load(os.path.join(self.ruta_modelos, "le_target.pkl"))

            mlp_path = os.path.join(self.ruta_modelos, "Nemesis_MLP.keras")
            rnn_path = os.path.join(self.ruta_modelos, "Nemesis_RNN.keras")

            if os.path.exists(mlp_path):
                self.modelo_mlp = tf.keras.models.load_model(mlp_path)
                logger.info("Modelo MLP cargado ✓")
            if os.path.exists(rnn_path):
                self.modelo_rnn = tf.keras.models.load_model(rnn_path)
                logger.info("Modelo RNN cargado ✓")

            self._cargado = True
            logger.info(f"Procesador listo. Clases: {self.config.get('clases', [])}")
            return True

        except Exception as e:
            logger.error(f"Error cargando modelos: {e}")
            return False

    def preprocesar_muestra(self, muestra: dict) -> Optional[np.ndarray]:
        """
        Preprocesa una muestra individual de tráfico de red.
        Aplica los mismos encoders y scaler usados en el entrenamiento.
        """
        try:
            from app.motor.preparacion_datos import vectorizar_muestras
            return vectorizar_muestras(muestra, self.scaler, self.encoders)
        except Exception as e:
            logger.error(f"Error preprocesando muestra: {e}")
            return None

    def analizar_trafico(self, muestra: dict) -> dict:
        """
        Analiza una muestra de tráfico de red y retorna predicción + alerta.
        Método principal del procesador.
        """
        if not self._cargado:
            return {"error": "Modelos no cargados. Ejecuta `python -m app.motor.entrenar_nemesis`"}

        X = self.preprocesar_muestra(muestra)
        if X is None:
            return {"error": "Error en preprocesamiento"}

        # ── Predicción MLP (principal) ──────────────────────────────
        probs_mlp = self.modelo_mlp.predict(X, verbose=0)[0]
        idx_mlp   = int(np.argmax(probs_mlp))
        clase_mlp = self.le_target.inverse_transform([idx_mlp])[0]
        conf_mlp  = float(probs_mlp[idx_mlp])

        # ── Predicción RNN (si hay buffer suficiente) ───────────────
        clase_rnn = None
        conf_rnn  = 0.0
        self.buffer_predicciones.append(X[0])
        WINDOW_SIZE = 10
        if len(self.buffer_predicciones) >= WINDOW_SIZE and self.modelo_rnn:
            seq = np.array(self.buffer_predicciones[-WINDOW_SIZE:])[np.newaxis, :]
            probs_rnn = self.modelo_rnn.predict(seq, verbose=0)[0]
            idx_rnn   = int(np.argmax(probs_rnn))
            clase_rnn = self.le_target.inverse_transform([idx_rnn])[0]
            conf_rnn  = float(probs_rnn[idx_rnn])
            # Mantener buffer en tamaño razonable
            if len(self.buffer_predicciones) > 100:
                self.buffer_predicciones = self.buffer_predicciones[-50:]

        # ── Consenso MLP + RNN ─────────────────────────────────────
        clase_final = clase_mlp
        conf_final  = conf_mlp
        if clase_rnn and clase_rnn == clase_mlp:
            conf_final = max(conf_mlp, conf_rnn)  # Ambos coinciden → más confianza
        elif clase_rnn and clase_rnn != "NORMAL" and clase_mlp == "NORMAL":
            clase_final = clase_rnn  # RNN detecta anomalía que MLP no vio
            conf_final  = conf_rnn * 0.85  # Reducir confianza al no coincidir

        # ── Determinar severidad ────────────────────────────────────
        if clase_final == "NORMAL":
            severidad = "NORMAL"
        elif conf_final >= UMBRAL_CRITICO:
            severidad = "CRÍTICO"
        elif conf_final >= UMBRAL_ADVERTENCIA:
            severidad = "ADVERTENCIA"
        elif conf_final >= UMBRAL_INFO:
            severidad = "INFORMACIÓN"
        else:
            severidad = "NORMAL"

        # ── Generar alerta si corresponde ───────────────────────────
        alerta = self._evaluar_alerta(clase_final, severidad, conf_final, muestra)

        # ── Explicabilidad: features más influyentes ────────────────
        features_influyentes = self._features_influyentes(muestra, clase_final)

        resultado = {
            "timestamp":   datetime.now().isoformat(),
            "clase":       clase_final,
            "severidad":   severidad,
            "tiempo_respuesta_objetivo": TIEMPO_RESPUESTA_OBJETIVO[severidad],
            "confianza":   round(conf_final * 100, 2),
            "mlp": {"clase": clase_mlp, "confianza": round(conf_mlp * 100, 2)},
            "rnn": {"clase": clase_rnn, "confianza": round(conf_rnn * 100, 2)},
            "probabilidades": {
                self.le_target.inverse_transform([j])[0]: round(float(p) * 100, 2)
                for j, p in enumerate(probs_mlp)
            },
            "alerta_generada": alerta is not None,
            "alerta": alerta,
            "features_influyentes": features_influyentes
        }

        # Guardar en BD
        try:
            from app.motor.base_datos import guardar_prediccion, guardar_alerta
            guardar_prediccion("Nemesis_MLP+RNN", clase_final, severidad,
                               conf_final, resultado)
            if alerta:
                guardar_alerta(alerta["nivel"], clase_final,
                               conf_final * 100, alerta["descripcion"])
        except Exception as e:
            logger.warning(f"No se pudo guardar en BD: {e}")

        return resultado

    def _evaluar_alerta(self, clase: str, severidad: str,
                         confianza: float, muestra: dict) -> Optional[dict]:
        """Sección 3.3.2 – Reglas de activación de alertas."""
        if severidad in ("NORMAL", "INFORMACIÓN"):
            return None

        # Control de cooldown
        ahora = datetime.now().timestamp()
        if clase in self.ultima_alerta:
            if ahora - self.ultima_alerta[clase] < COOLDOWN_SEGUNDOS:
                return None

        self.ultima_alerta[clase] = ahora

        descripciones = {
            "DoS":   f"Tráfico anómalo detectado: posible ataque de Denegación de Servicio. "
                     f"Tasa de errores elevada, {int(muestra.get('count',0))} conexiones/seg.",
            "Probe": f"Actividad de reconocimiento detectada: posible escaneo de puertos. "
                     f"Destinos únicos: {int(muestra.get('dst_host_count',0))}.",
            "R2L":   f"Intento de acceso remoto no autorizado. "
                     f"Intentos de login fallidos: {int(muestra.get('num_failed_logins',0))}.",
            "U2R":   f"Posible escalada de privilegios detectada. "
                     f"Actividad root sospechosa registrada.",
        }

        return {
            "nivel":       severidad,
            "descripcion": descripciones.get(clase, f"Amenaza {clase} detectada."),
            "confianza":   round(confianza * 100, 2),
            "timestamp":   datetime.now().isoformat(),
            "acciones_recomendadas": self._acciones_recomendadas(clase, severidad)
        }

    def _acciones_recomendadas(self, clase: str, severidad: str) -> list:
        acciones = {
            "DoS":   ["Bloquear IPs de origen", "Activar rate limiting", "Notificar al ISP"],
            "Probe": ["Revisar logs de firewall", "Verificar IDS/IPS", "Bloquear IP sospechosa"],
            "R2L":   ["Cambiar credenciales comprometidas", "Revisar accesos SSH/FTP", "Auditar usuarios"],
            "U2R":   ["Aislar el sistema afectado", "Revocar privilegios", "Análisis forense inmediato"],
        }
        return acciones.get(clase, ["Investigar el incidente", "Revisar logs del sistema"])

    def _features_influyentes(self, muestra: dict, clase: str) -> list:
        """Explicabilidad simplificada (Sección 3.3.3)."""
        indicadores = []

        src = muestra.get("src_bytes", 0)
        if src > 50000:
            indicadores.append({
                "feature": "Volumen de datos enviados",
                "valor":   f"{src/1024:.1f} KB",
                "normal":  "< 10 KB",
                "impacto": "+alto"
            })

        fails = muestra.get("num_failed_logins", 0)
        if fails > 3:
            indicadores.append({
                "feature": "Intentos de login fallidos",
                "valor":   str(int(fails)),
                "normal":  "0-2",
                "impacto": "+crítico"
            })

        cnt = muestra.get("count", 0)
        if cnt > 400:
            indicadores.append({
                "feature": "Conexiones por segundo",
                "valor":   str(int(cnt)),
                "normal":  "< 100",
                "impacto": "+alto"
            })

        serr = muestra.get("serror_rate", 0)
        if serr > 0.5:
            indicadores.append({
                "feature": "Tasa de errores SYN",
                "valor":   f"{serr:.2%}",
                "normal":  "< 5%",
                "impacto": "+moderado"
            })

        return indicadores if indicadores else [
            {"feature": "Comportamiento general", "valor": clase, "normal": "NORMAL", "impacto": "+bajo"}
        ]

    def generar_trafico_demo(self, tipo: str = "aleatorio") -> dict:
        """Muestra de tráfico para los botones de simulación del dashboard.

        Se genera con el MISMO perfil estadístico por clase que el dataset con el que se
        entrenaron los modelos (generador_dataset_base, calibrado según Tavallaee et al.,
        2009). Antes usaba perfiles propios, calibrados para un dataset anterior, y tras
        reentrenar con NSL_KDD_train.csv el modelo ya no reconocía el 'DoS' simulado."""
        from app.motor.generador_dataset_base import _generar_clase
        clases = {"normal": "NORMAL", "dos": "DoS", "probe": "Probe", "r2l": "R2L", "u2r": "U2R"}
        rng = np.random.default_rng()
        if tipo not in clases:  # "aleatorio" o cualquier valor desconocido
            tipo = str(rng.choice(list(clases)))
        fila = _generar_clase(clases[tipo], 1, rng).iloc[0].to_dict()
        fila.pop("label", None)
        return {k: (v.item() if hasattr(v, "item") else v) for k, v in fila.items()}


# Instancia global del procesador
_procesador_global: Optional[ProcesadorNemesis] = None


def obtener_procesador() -> ProcesadorNemesis:
    global _procesador_global
    if _procesador_global is None:
        _procesador_global = ProcesadorNemesis()
        _procesador_global.cargar_modelos()
    return _procesador_global
