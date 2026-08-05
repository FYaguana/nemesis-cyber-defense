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

# Umbrales de alerta (Sección 3.3.1)
UMBRAL_CRITICO     = 0.90
UMBRAL_ADVERTENCIA = 0.70
UMBRAL_INFO        = 0.50

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
                logger.error("No se encontró config.json. Ejecuta entrenar_nemesis.py primero.")
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
            from app.motor.preparacion_datos import COLUMNAS_CATEGORICAS, COLUMNAS_NUMERICAS
            import pandas as pd

            df = pd.DataFrame([muestra])

            # Encoding categórico
            for col in COLUMNAS_CATEGORICAS:
                if col in df.columns and col in self.encoders:
                    le = self.encoders[col]
                    df[col] = df[col].astype(str).apply(
                        lambda x: le.transform([x])[0] if x in le.classes_ else 0
                    )
                elif col not in df.columns:
                    df[col] = 0

            # Features de ingeniería
            df["ratio_src_dst"]       = df.get("src_bytes", pd.Series([0])) / \
                                         (df.get("dst_bytes", pd.Series([1])) + 1)
            df["tasa_errores"]        = df.get("serror_rate", pd.Series([0])) + \
                                         df.get("rerror_rate", pd.Series([0]))
            df["intentos_fallo_norm"] = df.get("num_failed_logins", pd.Series([0])) / \
                                         (df.get("count", pd.Series([1])) + 1)
            df["actividad_root"]      = df.get("root_shell", pd.Series([0])) + \
                                         df.get("num_root", pd.Series([0])) + \
                                         df.get("num_compromised", pd.Series([0]))

            # Asegurar columnas numéricas
            for col in COLUMNAS_NUMERICAS:
                if col not in df.columns:
                    df[col] = 0

            excluir = ["label"]
            columnas_X = [c for c in df.columns if c not in excluir]
            X = df[columnas_X].values.astype(np.float32)

            # Ajustar dimensiones al scaler
            n_esperado = self.scaler.n_features_in_
            if X.shape[1] < n_esperado:
                pad = np.zeros((X.shape[0], n_esperado - X.shape[1]), dtype=np.float32)
                X = np.hstack([X, pad])
            elif X.shape[1] > n_esperado:
                X = X[:, :n_esperado]

            return self.scaler.transform(X)

        except Exception as e:
            logger.error(f"Error preprocesando muestra: {e}")
            return None

    def analizar_trafico(self, muestra: dict) -> dict:
        """
        Analiza una muestra de tráfico de red y retorna predicción + alerta.
        Método principal del procesador.
        """
        if not self._cargado:
            return {"error": "Modelos no cargados. Ejecuta entrenar_nemesis.py"}

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
        """Genera una muestra de tráfico de red para demostración."""
        np.random.seed()

        base = {
            "duration": np.random.exponential(5),
            "protocol_type": np.random.choice(["tcp", "udp", "icmp"]),
            "service": np.random.choice(["http", "ftp", "smtp", "ssh", "dns"]),
            "flag": "SF",
            "src_bytes": 1024.0,
            "dst_bytes": 4096.0,
            "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 1,
            "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
            "root_shell": 0, "su_attempted": 0, "num_root": 0,
            "num_file_creations": 0, "num_shells": 0, "num_access_files": 1,
            "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
            "count": float(np.random.randint(10, 100)),
            "srv_count": float(np.random.randint(10, 80)),
            "serror_rate": 0.02, "srv_serror_rate": 0.01,
            "rerror_rate": 0.01, "srv_rerror_rate": 0.01,
            "same_srv_rate": 0.9, "diff_srv_rate": 0.05,
            "srv_diff_host_rate": 0.1,
            "dst_host_count": float(np.random.randint(20, 100)),
            "dst_host_srv_count": float(np.random.randint(20, 80)),
            "dst_host_same_srv_rate": 0.8, "dst_host_diff_srv_rate": 0.05,
            "dst_host_same_src_port_rate": 0.5, "dst_host_srv_diff_host_rate": 0.1,
            "dst_host_serror_rate": 0.02, "dst_host_srv_serror_rate": 0.01,
            "dst_host_rerror_rate": 0.01, "dst_host_srv_rerror_rate": 0.01,
        }

        if tipo == "dos":
            base.update({
                "src_bytes": float(np.random.randint(50000, 200000)),
                "count": float(np.random.randint(450, 511)),
                "serror_rate": float(np.random.uniform(0.7, 1.0)),
                "flag": "S0",
                "duration": 0.1,
            })
        elif tipo == "probe":
            base.update({
                "dst_host_count": float(np.random.randint(220, 255)),
                "diff_srv_rate": float(np.random.uniform(0.6, 0.9)),
                "logged_in": 0,
                "srv_diff_host_rate": float(np.random.uniform(0.5, 0.9)),
            })
        elif tipo == "r2l":
            base.update({
                "num_failed_logins": float(np.random.randint(10, 30)),
                "logged_in": 0,
                "hot": float(np.random.randint(10, 40)),
            })
        elif tipo == "u2r":
            base.update({
                "root_shell": 1,
                "num_root": float(np.random.randint(5, 20)),
                "num_compromised": float(np.random.randint(3, 15)),
            })

        return base


# Instancia global del procesador
_procesador_global: Optional[ProcesadorNemesis] = None


def obtener_procesador() -> ProcesadorNemesis:
    global _procesador_global
    if _procesador_global is None:
        _procesador_global = ProcesadorNemesis()
        _procesador_global.cargar_modelos()
    return _procesador_global
