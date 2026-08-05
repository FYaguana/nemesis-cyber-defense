"""
limpieza.py – Módulo de Limpieza y Preprocesamiento de Datos
Sistema Nemesis Cyber Defense
Tesis: Predicción y Prevención de Ciberataques con Deep Learning
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
import logging
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NEMESIS-LIMPIEZA] %(message)s")
logger = logging.getLogger(__name__)

# ─── Columnas principales del dataset NSL-KDD / CIC-IDS sintético ───────────
COLUMNAS_BASE = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label"
]

COLUMNAS_NUMERICAS = [c for c in COLUMNAS_BASE if c not in
    ["protocol_type", "service", "flag", "label"]]

COLUMNAS_CATEGORICAS = ["protocol_type", "service", "flag"]

# Mapeo de etiquetas a clases de ataque (simplificado)
MAPA_ETIQUETAS = {
    "normal": "NORMAL",
    "neptune": "DoS", "back": "DoS", "land": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "mailbomb": "DoS",
    "apache2": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L", "warezclient": "R2L",
    "warezmaster": "R2L", "sendmail": "R2L", "named": "R2L",
    "snmpgetattack": "R2L", "snmpguess": "R2L", "xlock": "R2L",
    "xsnoop": "R2L", "worm": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "httptunnel": "U2R", "ps": "U2R",
    "sqlattack": "U2R", "xterm": "U2R",
}


def generar_dataset_sintetico(n_samples: int = 5000, seed: int = 42) -> pd.DataFrame:
    """
    Genera un dataset sintético de tráfico de red con las variables críticas
    descritas en la tesis (tcprtt, synack, etc.) para pruebas del prototipo.
    """
    np.random.seed(seed)
    logger.info(f"Generando dataset sintético con {n_samples} muestras...")

    n_normal = int(n_samples * 0.65)
    n_dos    = int(n_samples * 0.15)
    n_probe  = int(n_samples * 0.10)
    n_r2l    = int(n_samples * 0.05)
    n_u2r    = n_samples - n_normal - n_dos - n_probe - n_r2l

    def muestra(label, n, overrides=None):
        base = {
            "duration":              np.random.exponential(5, n),
            "protocol_type":         np.random.choice(["tcp","udp","icmp"], n, p=[0.7,0.2,0.1]),
            "service":               np.random.choice(["http","ftp","smtp","ssh","dns"], n),
            "flag":                  np.random.choice(["SF","S0","REJ","RSTO"], n, p=[0.8,0.1,0.07,0.03]),
            "src_bytes":             np.random.exponential(1000, n),
            "dst_bytes":             np.random.exponential(5000, n),
            "land":                  np.zeros(n),
            "wrong_fragment":        np.random.poisson(0.1, n),
            "urgent":                np.zeros(n),
            "hot":                   np.random.poisson(1, n),
            "num_failed_logins":     np.zeros(n),
            "logged_in":             np.ones(n),
            "num_compromised":       np.zeros(n),
            "root_shell":            np.zeros(n),
            "su_attempted":          np.zeros(n),
            "num_root":              np.zeros(n),
            "num_file_creations":    np.random.poisson(0.2, n),
            "num_shells":            np.zeros(n),
            "num_access_files":      np.random.poisson(0.5, n),
            "num_outbound_cmds":     np.zeros(n),
            "is_host_login":         np.zeros(n),
            "is_guest_login":        np.zeros(n),
            "count":                 np.random.randint(1, 512, n).astype(float),
            "srv_count":             np.random.randint(1, 512, n).astype(float),
            "serror_rate":           np.random.beta(1, 9, n),
            "srv_serror_rate":       np.random.beta(1, 9, n),
            "rerror_rate":           np.random.beta(1, 9, n),
            "srv_rerror_rate":       np.random.beta(1, 9, n),
            "same_srv_rate":         np.random.beta(9, 1, n),
            "diff_srv_rate":         np.random.beta(1, 9, n),
            "srv_diff_host_rate":    np.random.beta(1, 5, n),
            "dst_host_count":        np.random.randint(1, 256, n).astype(float),
            "dst_host_srv_count":    np.random.randint(1, 256, n).astype(float),
            "dst_host_same_srv_rate":    np.random.beta(7, 3, n),
            "dst_host_diff_srv_rate":    np.random.beta(1, 9, n),
            "dst_host_same_src_port_rate":   np.random.beta(5, 5, n),
            "dst_host_srv_diff_host_rate":   np.random.beta(1, 5, n),
            "dst_host_serror_rate":  np.random.beta(1, 9, n),
            "dst_host_srv_serror_rate":  np.random.beta(1, 9, n),
            "dst_host_rerror_rate":  np.random.beta(1, 9, n),
            "dst_host_srv_rerror_rate":  np.random.beta(1, 9, n),
            "label":                 [label] * n
        }
        if overrides:
            for k, v in overrides.items():
                base[k] = v
        return pd.DataFrame(base)

    normal = muestra("NORMAL", n_normal)

    dos = muestra("DoS", n_dos, {
        "src_bytes":     np.random.exponential(50000, n_dos),
        "count":         np.random.randint(400, 512, n_dos).astype(float),
        "serror_rate":   np.random.beta(8, 2, n_dos),
        "flag":          np.random.choice(["S0","REJ"], n_dos),
        "duration":      np.random.exponential(0.5, n_dos),
    })

    probe = muestra("Probe", n_probe, {
        "dst_host_count":    np.random.randint(200, 256, n_probe).astype(float),
        "diff_srv_rate":     np.random.beta(7, 3, n_probe),
        "srv_diff_host_rate": np.random.beta(6, 4, n_probe),
        "logged_in":         np.zeros(n_probe),
    })

    r2l = muestra("R2L", n_r2l, {
        "num_failed_logins": np.random.randint(3, 20, n_r2l).astype(float),
        "logged_in":         np.zeros(n_r2l),
        "hot":               np.random.randint(5, 30, n_r2l).astype(float),
    })

    u2r = muestra("U2R", n_u2r, {
        "root_shell":        np.ones(n_u2r),
        "num_root":          np.random.randint(1, 10, n_u2r).astype(float),
        "num_compromised":   np.random.randint(1, 10, n_u2r).astype(float),
    })

    df = pd.concat([normal, dos, probe, r2l, u2r], ignore_index=True)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    logger.info(f"Dataset generado: {df.shape} | Distribución:\n{df['label'].value_counts()}")
    return df


def limpiar_datos(df: pd.DataFrame) -> pd.DataFrame:
    """Fase 3.2.3 – Limpieza y validación de datos."""
    logger.info("Iniciando limpieza de datos...")
    df = df.copy()

    # 1. Eliminar duplicados
    antes = len(df)
    df.drop_duplicates(inplace=True)
    logger.info(f"Duplicados eliminados: {antes - len(df)}")

    # 2. Tratar valores nulos
    nulos = df.isnull().sum().sum()
    if nulos > 0:
        logger.warning(f"Valores nulos detectados: {nulos}")
        for col in COLUMNAS_NUMERICAS:
            if col in df.columns:
                df[col].fillna(df[col].median(), inplace=True)
        for col in COLUMNAS_CATEGORICAS:
            if col in df.columns:
                df[col].fillna(df[col].mode()[0], inplace=True)

    # 3. Detectar outliers (no se eliminan – pueden ser ataques)
    for col in ["src_bytes", "dst_bytes", "count", "num_failed_logins"]:
        if col in df.columns:
            q99 = df[col].quantile(0.999)
            outliers = (df[col] > q99).sum()
            if outliers > 0:
                logger.info(f"  Outliers en '{col}': {outliers} registros (conservados – posibles ataques)")

    # 4. Asegurar tipos correctos
    for col in COLUMNAS_NUMERICAS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    logger.info(f"Limpieza completada. Shape final: {df.shape}")
    return df


def transformar_features(df: pd.DataFrame, scaler=None, encoders=None, fit=True):
    """
    Fase 3.2.4 – Feature Engineering y transformación.
    Retorna (X_array, y_array, scaler, label_encoders, label_encoder_target)
    """
    logger.info("Iniciando transformación de features...")
    df = df.copy()

    # ── Encoding de variables categóricas (One-Hot simplificado con LabelEncoder) ──
    if encoders is None:
        encoders = {}

    for col in COLUMNAS_CATEGORICAS:
        if col in df.columns:
            if fit:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                encoders[col] = le
            else:
                le = encoders[col]
                df[col] = df[col].astype(str).apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else 0
                )

    # ── Feature Engineering: indicadores de seguridad adicionales ──
    df["ratio_src_dst"] = df["src_bytes"] / (df["dst_bytes"] + 1)
    df["tasa_errores"]  = df["serror_rate"] + df["rerror_rate"]
    df["intentos_fallo_norm"] = df["num_failed_logins"] / (df["count"] + 1)
    df["actividad_root"] = df["root_shell"] + df["num_root"] + df["num_compromised"]

    # ── Preparar X e y ──
    excluir = ["label"]
    columnas_X = [c for c in df.columns if c not in excluir]
    X = df[columnas_X].values.astype(np.float32)

    # ── Normalización Z-score ──
    if fit:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
    else:
        X = scaler.transform(X)

    # ── Encoding de etiqueta objetivo ──
    le_target = LabelEncoder()
    if "label" in df.columns:
        y = le_target.fit_transform(df["label"].astype(str))
    else:
        y = np.array([])

    logger.info(f"Features generadas: {X.shape[1]} columnas | Clases: {le_target.classes_}")
    return X, y, scaler, encoders, le_target


def preparar_datos_completo(n_samples=5000, test_size=0.2, val_size=0.1, seed=42):
    """
    Pipeline completo: generar → limpiar → transformar → dividir.
    Retorna diccionario con todos los splits y objetos de transformación.
    """
    df_crudo = generar_dataset_sintetico(n_samples=n_samples, seed=seed)
    df_limpio = limpiar_datos(df_crudo)

    X, y, scaler, encoders, le_target = transformar_features(df_limpio, fit=True)

    # Split: train / val / test
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val,
        test_size=val_size / (1 - test_size),
        random_state=seed, stratify=y_train_val)

    logger.info(f"Split → Train: {X_train.shape[0]} | Val: {X_val.shape[0]} | Test: {X_test.shape[0]}")

    return {
        "X_train": X_train, "y_train": y_train,
        "X_val":   X_val,   "y_val":   y_val,
        "X_test":  X_test,  "y_test":  y_test,
        "scaler":  scaler,
        "encoders": encoders,
        "le_target": le_target,
        "n_clases": len(le_target.classes_),
        "n_features": X_train.shape[1],
        "clases": list(le_target.classes_),
        "df_crudo": df_crudo,
    }


def preparar_datos_con_reales(muestras_reales: list, n_samples_sinteticos=5000,
                               test_size=0.2, val_size=0.1, seed=42):
    """
    Igual que preparar_datos_completo(), pero además incorpora tráfico REAL
    ya confirmado/corregido por un analista humano (ver database_manager.
    obtener_capturas_etiquetadas()). Esta es la pieza clave del "aprendizaje
    activo" (human-in-the-loop) del sistema: nunca se reentrena con las
    propias predicciones del modelo como si fueran verdad — solo con
    etiquetas puestas por una persona — para no reforzar sus propios errores.

    muestras_reales: lista de dicts, cada uno con las features crudas del
    flujo real capturado + una clave "label" con la etiqueta humana
    (NORMAL/DoS/Probe/R2L/U2R). Las columnas que NSL-KDD tiene pero que no
    son derivables de paquetes de red (num_compromised, root_shell, etc.)
    ya vienen en 0 desde el propio flujo de captura — es la misma limitación
    documentada en la Sección de resultados sobre datos reales.
    """
    df_sintetico = generar_dataset_sintetico(n_samples=n_samples_sinteticos, seed=seed)

    if muestras_reales:
        df_reales = pd.DataFrame(muestras_reales)
        # Asegurar que estén TODAS las columnas esperadas, en el mismo orden;
        # cualquier columna faltante en los datos reales se rellena con 0.
        for col in COLUMNAS_BASE:
            if col not in df_reales.columns:
                df_reales[col] = 0
        df_reales = df_reales[COLUMNAS_BASE]
        df_combinado = pd.concat([df_sintetico, df_reales], ignore_index=True)
        logger.info(f"Dataset combinado: {len(df_sintetico)} sintéticas + "
                    f"{len(df_reales)} reales confirmadas = {len(df_combinado)} muestras")
    else:
        df_combinado = df_sintetico
        logger.info("No había muestras reales confirmadas todavía; se entrena solo con datos sintéticos.")

    df_limpio = limpiar_datos(df_combinado)
    X, y, scaler, encoders, le_target = transformar_features(df_limpio, fit=True)

    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val,
        test_size=val_size / (1 - test_size),
        random_state=seed, stratify=y_train_val)

    logger.info(f"Split → Train: {X_train.shape[0]} | Val: {X_val.shape[0]} | Test: {X_test.shape[0]}")

    return {
        "X_train": X_train, "y_train": y_train,
        "X_val":   X_val,   "y_val":   y_val,
        "X_test":  X_test,  "y_test":  y_test,
        "scaler":  scaler,
        "encoders": encoders,
        "le_target": le_target,
        "n_clases": len(le_target.classes_),
        "n_features": X_train.shape[1],
        "clases": list(le_target.classes_),
        "df_crudo": df_combinado,
        "n_muestras_reales": len(muestras_reales) if muestras_reales else 0,
    }


def preparar_datos_con_reales_y_base(muestras_reales: list, ruta_train: str = None,
                                       ruta_test: str = None, val_size: float = 0.15, seed: int = 42):
    """
    Usa como FUNDAMENTO los CSV NSL-KDD ya generados del proyecto
    (data/NSL_KDD_train.csv y NSL_KDD_test.csv, calibrados según las
    distribuciones publicadas por Tavallaee et al. 2009 — ver
    dataset_nslkdd.py), en vez de generar un dataset sintético nuevo en
    memoria cada vez. Esto le da continuidad y solidez al entrenamiento:
    siempre parte de la misma base validada, no de datos distintos en
    cada corrida.

    Las muestras reales confirmadas por un analista (ver
    database_manager.obtener_capturas_etiquetadas()) se agregan SOLO al
    conjunto de ENTRENAMIENTO. El conjunto de TEST (NSL_KDD_test.csv)
    se mantiene intacto como benchmark limpio, para poder comparar de
    forma justa el desempeño del modelo antes y después de cada
    reentrenamiento contra el mismo estándar de siempre — en vez de un
    split aleatorio distinto cada vez, que haría las métricas no
    comparables entre sí.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if ruta_train is None:
        ruta_train = os.path.join(base_dir, "data", "NSL_KDD_train.csv")
    if ruta_test is None:
        ruta_test = os.path.join(base_dir, "data", "NSL_KDD_test.csv")

    df_train = pd.read_csv(ruta_train)
    df_test = pd.read_csv(ruta_test)
    logger.info(f"Base cargada: {len(df_train)} filas de train, {len(df_test)} filas de test "
                f"(desde {os.path.basename(ruta_train)} / {os.path.basename(ruta_test)})")

    n_reales = 0
    if muestras_reales:
        df_reales = pd.DataFrame(muestras_reales)
        for col in COLUMNAS_BASE:
            if col not in df_reales.columns:
                df_reales[col] = 0
        df_reales = df_reales[COLUMNAS_BASE]
        df_train = pd.concat([df_train, df_reales], ignore_index=True)
        n_reales = len(df_reales)
        logger.info(f"Agregadas {n_reales} muestras reales confirmadas al conjunto de entrenamiento")

    df_train_limpio = limpiar_datos(df_train)
    df_test_limpio = limpiar_datos(df_test)

    # Se ajustan scaler/encoders/le_target SOLO con el conjunto de entrenamiento.
    X_trainval, y_trainval, scaler, encoders, le_target = transformar_features(df_train_limpio, fit=True)

    # El test se transforma con los MISMOS objetos ya ajustados (fit=False),
    # nunca ajustando nada nuevo con datos de test — así la evaluación es válida.
    X_test, _, _, _, _ = transformar_features(df_test_limpio, scaler=scaler, encoders=encoders, fit=False)
    y_test = le_target.transform(df_test_limpio["label"].astype(str))

    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=val_size, random_state=seed, stratify=y_trainval)

    logger.info(f"Split final → Train: {X_train.shape[0]} | Val: {X_val.shape[0]} | "
                f"Test (benchmark fijo): {X_test.shape[0]}")

    return {
        "X_train": X_train, "y_train": y_train,
        "X_val":   X_val,   "y_val":   y_val,
        "X_test":  X_test,  "y_test":  y_test,
        "scaler":  scaler,
        "encoders": encoders,
        "le_target": le_target,
        "n_clases": len(le_target.classes_),
        "n_features": X_train.shape[1],
        "clases": list(le_target.classes_),
        "n_muestras_reales": n_reales,
        "n_muestras_base": len(df_train) - n_reales,
    }


if __name__ == "__main__":
    datos = preparar_datos_completo(n_samples=3000)
    print("\n✅ Pipeline de datos ejecutado correctamente")
    print(f"   Features: {datos['n_features']} | Clases: {datos['clases']}")
    print(f"   Train: {datos['X_train'].shape[0]} | Val: {datos['X_val'].shape[0]} | Test: {datos['X_test'].shape[0]}")