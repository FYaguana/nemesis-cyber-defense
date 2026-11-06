"""
preparacion_datos.py -- Pipeline de datos de Nemesis (Secciones 3.3 y 4.1 de la tesis)

    Dataset base -> Limpieza -> Feature Engineering -> Normalización -> División Train/Val/Test

- Limpieza: eliminación de duplicados, imputación de nulos y CONSERVACIÓN de valores atípicos
  (en src_bytes o count pueden ser evidencia de un ataque en curso).
- Feature Engineering: cuatro variables derivadas (ratio_bytes, tasa_errores,
  intentos_fallo_norm, actividad_root) sobre las 41 variables base: 45 entradas en total.
- Normalización Z-score (StandardScaler) con media y desviación calculadas EXCLUSIVAMENTE
  sobre el conjunto de entrenamiento, para evitar fuga de información hacia validación y prueba.
- División: el conjunto base de entrenamiento (15,000) se parte 85 % / 15 % de forma
  estratificada; el de prueba (4,000) viene de un archivo separado y fijo.

La MISMA función (`vectorizar_muestras`) se usa en entrenamiento, inferencia en vivo y captura
de red, de modo que una muestra produce exactamente el mismo vector sin importar el orden en
que lleguen sus claves ni qué variables falten.
"""

import logging
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

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

# Orden FIJO de las variables de entrada (sin la etiqueta). Es el orden del CSV de entrenamiento
# y, por lo tanto, el que espera el escalador y los modelos.
COLUMNAS_ENTRADA = [c for c in COLUMNAS_BASE if c != "label"]

# Variables derivadas (Sección 4.1): conocimiento de dominio de ciberseguridad (Berjawi et al., 2023).
VARIABLES_DERIVADAS = ["ratio_bytes", "tasa_errores", "intentos_fallo_norm", "actividad_root"]

N_VARIABLES_ENTRADA = len(COLUMNAS_ENTRADA) + len(VARIABLES_DERIVADAS)  # 41 + 4 = 45

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
        # Asignación explícita: `df[col].fillna(..., inplace=True)` no modifica el DataFrame
        # con pandas >= 3 (copy-on-write) y la imputación se perdería en silencio.
        for col in COLUMNAS_NUMERICAS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")
                df[col] = df[col].fillna(df[col].median())
        for col in COLUMNAS_CATEGORICAS:
            if col in df.columns and df[col].notna().any():
                df[col] = df[col].fillna(df[col].mode()[0])

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


def agregar_variables_derivadas(df: pd.DataFrame) -> pd.DataFrame:
    """Sección 4.1: cuatro variables derivadas. Se aplica igual en entrenamiento e inferencia.

        ratio_bytes         = src_bytes / (dst_bytes + 1)
        tasa_errores        = serror_rate + rerror_rate
        intentos_fallo_norm = num_failed_logins / (count + 1)
        actividad_root      = root_shell + num_root + num_compromised
    """
    df = df.copy()
    df["ratio_bytes"] = df["src_bytes"] / (df["dst_bytes"] + 1)
    df["tasa_errores"] = df["serror_rate"] + df["rerror_rate"]
    df["intentos_fallo_norm"] = df["num_failed_logins"] / (df["count"] + 1)
    df["actividad_root"] = df["root_shell"] + df["num_root"] + df["num_compromised"]
    return df


def transformar_features(df: pd.DataFrame, scaler=None, encoders=None, fit=True):
    """
    Fase 3.2.4 – Feature Engineering y transformación (uso en ENTRENAMIENTO/evaluación).
    Retorna (X_array, y_array, scaler, label_encoders, label_encoder_target)

    - fit=True : ajusta encoders y scaler con ESTE dataframe (debe ser solo el de entrenamiento).
    - fit=False: reutiliza los objetos ya ajustados (validación, prueba), sin ajustar nada nuevo.
    """
    logger.info("Iniciando transformación de features...")
    df = df.copy()

    # ── Encoding de variables categóricas ──
    if encoders is None:
        encoders = {}
    for col in COLUMNAS_CATEGORICAS:
        if fit:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
        else:
            df[col] = _codificar_categoria(df[col], encoders[col])

    # ── Feature Engineering y selección explícita (orden fijo) ──
    df = agregar_variables_derivadas(df)
    X = df[COLUMNAS_ENTRADA + VARIABLES_DERIVADAS].values.astype(np.float32)

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


def _codificar_categoria(serie: pd.Series, encoder: LabelEncoder) -> pd.Series:
    """Categoría -> entero con el encoder del entrenamiento. Una categoría nunca vista
    (p. ej. un servicio que no estaba en el dataset) se codifica como 0."""
    indice = {valor: i for i, valor in enumerate(encoder.classes_)}
    return serie.astype(str).map(lambda valor: indice.get(valor, 0))


def vectorizar_muestras(muestras, scaler, encoders) -> np.ndarray:
    """Convierte muestras crudas en vectores listos para el modelo (uso en INFERENCIA).

    `muestras` puede ser un dict, una lista de dicts o un DataFrame. Garantiza:
      * el orden de columnas es SIEMPRE el del entrenamiento, sin importar el orden de las claves;
      * las variables que no vienen en la muestra (p. ej. las de auditoría de host que no se
        derivan de paquetes de red) se completan con 0 -- sin aproximarlas (Sección 4.5);
      * las columnas extra (timestamp, IPs...) se ignoran;
      * si el número de variables no coincide con el del escalador se lanza un error explícito,
        en vez de rellenar o recortar en silencio.
    """
    if isinstance(muestras, dict):
        muestras = [muestras]
    df = muestras.copy() if isinstance(muestras, pd.DataFrame) else pd.DataFrame(list(muestras))

    for col in COLUMNAS_ENTRADA:
        if col not in df.columns:
            df[col] = 0
    df = df[COLUMNAS_ENTRADA].copy()

    for col in COLUMNAS_CATEGORICAS:
        df[col] = _codificar_categoria(df[col], encoders[col])
    for col in COLUMNAS_NUMERICAS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df = agregar_variables_derivadas(df)
    X = df[COLUMNAS_ENTRADA + VARIABLES_DERIVADAS].to_numpy(dtype=np.float32)
    if X.shape[1] != scaler.n_features_in_:
        raise ValueError(f"El escalador espera {scaler.n_features_in_} variables y la muestra produce "
                         f"{X.shape[1]}: los modelos no corresponden al pipeline actual (reentrenar).")
    return scaler.transform(X)


def preparar_datos_con_reales_y_base(muestras_reales: list, ruta_train: str = None,
                                       ruta_test: str = None, val_size: float = 0.15, seed: int = 42):
    """
    Pipeline de la tesis (Sección 4.1). Usa como FUNDAMENTO los CSV con la estructura y las
    proporciones de clase del NSL-KDD (data/NSL_KDD_train.csv y NSL_KDD_test.csv; generados por
    generador_dataset_base.py, calibrados únicamente en las proporciones publicadas por
    Tavallaee et al., 2009).

    Las muestras reales confirmadas por un analista (ver base_datos.obtener_capturas_etiquetadas)
    se agregan SOLO al conjunto de ENTRENAMIENTO: D_entrenamiento = D_base ∪ D_real_confirmado.
    El conjunto de PRUEBA (NSL_KDD_test.csv) se mantiene intacto como benchmark fijo, para que
    las métricas sean comparables entre reentrenamientos sucesivos.

    Orden de las operaciones (evita fuga de información):
      1) limpieza de cada archivo;  2) división estratificada 85/15 train/validación;
      3) los encoders y el escalador se ajustan SOLO con el 85 % de entrenamiento;
      4) validación y prueba se transforman con esos mismos objetos (fit=False).
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

    df_trainval = limpiar_datos(df_train)
    df_test_limpio = limpiar_datos(df_test)

    # 2) División estratificada ANTES de ajustar ningún transformador.
    df_tr, df_va = train_test_split(df_trainval, test_size=val_size, random_state=seed,
                                    stratify=df_trainval["label"])

    # 3) Ajuste exclusivamente con el conjunto de entrenamiento.
    X_train, y_train, scaler, encoders, le_target = transformar_features(df_tr, fit=True)

    # 4) Validación y prueba con los MISMOS objetos ya ajustados.
    X_val, _, _, _, _ = transformar_features(df_va, scaler=scaler, encoders=encoders, fit=False)
    y_val = le_target.transform(df_va["label"].astype(str))
    X_test, _, _, _, _ = transformar_features(df_test_limpio, scaler=scaler, encoders=encoders, fit=False)
    y_test = le_target.transform(df_test_limpio["label"].astype(str))

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
    datos = preparar_datos_con_reales_y_base([])
    print("\n✅ Pipeline de datos ejecutado correctamente")
    print(f"   Features: {datos['n_features']} | Clases: {datos['clases']}")
    print(f"   Train: {datos['X_train'].shape[0]} | Val: {datos['X_val'].shape[0]} | Test: {datos['X_test'].shape[0]}")
