"""
NEMESIS - Captura de tráfico real (red doméstica)
==================================================
Objetivo (Sección 3.x de la tesis, "validación con datos cercanos a producción"):
Capturar el tráfico real que entra y sale de ESTA máquina en la red doméstica,
extraer un subconjunto de features compatibles con el esquema NSL-KDD usado
en el entrenamiento, y alimentar el pipeline de limpieza.py / procesador_nemesis.py
ya construido, en lugar de los datos sintéticos.

LIMITACIÓN METODOLÓGICA (documentar en la tesis, no ocultar):
En una red doméstica con router ISP estándar (switch + NAT, sin puerto SPAN),
la captura en modo promiscuo desde una PC normal solo ve:
  - El tráfico unicast propio de esa PC (su IP/MAC).
  - Tráfico broadcast/multicast de la red (ARP, mDNS, DHCP, etc.).
No ve el tráfico unicast de OTROS dispositivos de la casa; eso requeriría
un puerto espejo, ARP spoofing (no recomendado, fuera de alcance ético/técnico
de este prototipo) o acceso admin al router (fuera de alcance en este caso).
Esto se documenta como limitación explícita frente al entorno simulado
100% sintético: aun así es un salto real hacia datos de tráfico genuino.

Requisitos:
    pip install scapy pandas joblib
    Windows: instalar Npcap (https://npcap.com) y ejecutar como Administrador.
    Linux/Mac: ejecutar con sudo.

Ubicación: este script vive en src/, junto a limpieza.py y procesador_nemesis.py.

Uso (desde la raíz del proyecto, E:\\Nemesis_Cyber_Defense):
    python src\\sniffer_nemesis.py --iface "Wi-Fi" --ventana 5 --duracion 300
"""

import argparse
import csv
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime

import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP

# backend/app/motor/captura_paquetes.py -> subir 3 niveles llega a backend/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NEMESIS-SNIFFER] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOGS_DIR, "captura_real.log"), mode="a", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ── Categorías EXACTAS que el modelo conoce (confirmado con models/encoders.pkl) ──
# protocol_type -> ['icmp', 'tcp', 'udp']
# service       -> ['dns', 'ftp', 'http', 'smtp', 'ssh']
# flag          -> ['REJ', 'RSTO', 'S0', 'SF']
#
# Cualquier valor fuera de estas listas cae a índice 0 en limpieza.py
# (fallback "else 0" en transformar_features), así que el sniffer solo
# debe producir categorías dentro de este conjunto.
SERVICE_MAP = {
    21: "ftp", 20: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http", 8080: "http", 443: "http",
}


def resolver_service(puerto):
    # Puerto fuera del mapa -> "http" como categoría por defecto (la más
    # genérica/frecuente en tráfico doméstico), en vez de una etiqueta
    # inexistente que el encoder no reconocería. Limitación documentada:
    # el modelo solo conoce 5 servicios de NSL-KDD, insuficiente para
    # todo el tráfico real doméstico moderno (streaming, mensajería, etc.).
    return SERVICE_MAP.get(puerto, "http")


class AgregadorFlujos:
    """
    Agrega paquetes en 'flujos' (5-tupla) y calcula, por ventana de tiempo,
    un subconjunto de features NSL-KDD-like que SÍ son derivables de
    la captura de paquetes en vivo:

        duration, protocol_type, service, flag, src_bytes, dst_bytes,
        count, srv_count, same_srv_rate, diff_srv_rate, land

    Nota honesta para la tesis: features como num_failed_logins, root_shell,
    num_compromised, etc. del NSL-KDD original vienen de auditoría a nivel
    de host/aplicación (logs de SO, logs de autenticación), NO de la captura
    de paquetes de red. Este módulo NO los inventa; si el modelo los requiere,
    se rellenan con 0 y se documenta la limitación en el capítulo de resultados.
    """

    def __init__(self, ventana_segundos=5):
        self.ventana_segundos = ventana_segundos
        self.flujos = defaultdict(lambda: {
            "inicio": None, "fin": None,
            "src_bytes": 0, "dst_bytes": 0,
            "protocol_type": None, "service": None,
            "flag": "SF",  # SF = "conexión establecida normal", el default más razonable
            "land": 0,
        })
        self.historial_srv = deque(maxlen=200)  # para same_srv_rate / diff_srv_rate

    def procesar_paquete(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        # protocol_type solo conoce icmp/tcp/udp -> cualquier otro protocolo IP
        # (ej. GRE, ESP de VPNs) se aproxima a "tcp" en vez de una categoría inexistente.
        proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else "icmp" if ICMP in pkt else "tcp"
        sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0

        clave = (ip.src, ip.dst, sport, dport, proto)
        f = self.flujos[clave]
        ahora = time.time()
        if f["inicio"] is None:
            f["inicio"] = ahora
        f["fin"] = ahora
        f["protocol_type"] = proto
        f["service"] = resolver_service(dport)
        f["src_bytes"] += len(pkt)
        f["land"] = 1 if ip.src == ip.dst else 0

        if TCP in pkt:
            flags = pkt[TCP].flags
            # Orden de evaluación importa: SYN sin ACK primero (intento de conexión),
            # luego RST (rechazo), luego ACK (conexión establecida = SF).
            # Todas las categorías usadas están dentro de ['REJ','RSTO','S0','SF'].
            if flags & 0x04 and flags & 0x10:   # RST+ACK
                f["flag"] = "RSTO"
            elif flags & 0x04:                  # RST solo
                f["flag"] = "REJ"
            elif flags & 0x02 and not (flags & 0x10):  # SYN sin ACK
                f["flag"] = "S0"
            elif flags & 0x10:                  # ACK
                f["flag"] = "SF"

        self.historial_srv.append(f["service"])

    def construir_filas(self):
        """
        Calcula same_srv_rate / diff_srv_rate sobre el historial reciente y
        retorna la lista de filas (dict) de los flujos activos en la ventana,
        SIN escribir a ningún lado. Reutilizable tanto por el CLI (que las
        vuelca a CSV) como por la integración en vivo con el dashboard
        (que las pasa directo a procesador_nemesis.analizar_trafico()).
        """
        total = len(self.historial_srv) or 1
        filas = []
        for clave, f in list(self.flujos.items()):
            same_srv = self.historial_srv.count(f["service"]) / total
            diff_srv = 1 - same_srv
            duracion = round((f["fin"] or 0) - (f["inicio"] or 0), 4)

            filas.append({
                "timestamp": datetime.now().isoformat(),
                "src_ip": clave[0], "dst_ip": clave[1],
                "src_port": clave[2], "dst_port": clave[3],
                "duration": duracion,
                "protocol_type": f["protocol_type"],
                "service": f["service"],
                "flag": f["flag"],
                "src_bytes": f["src_bytes"],
                "dst_bytes": f["dst_bytes"],
                "land": f["land"],
                "count": len(self.flujos),
                "srv_count": self.historial_srv.count(f["service"]),
                "same_srv_rate": round(same_srv, 4),
                "diff_srv_rate": round(diff_srv, 4),
                # Placeholders explícitos y documentados (no derivables de red pura):
                "num_failed_logins": 0,
                "root_shell": 0,
                "logged_in": 0,
            })
        self.flujos.clear()
        return filas

    def volcar_features(self, writer):
        """Uso por CLI: construye las filas y las escribe a un csv.DictWriter."""
        for fila in self.construir_filas():
            writer.writerow(fila)


def transformar_con_modelo_real(csv_captura, salida_npy=None):
    """
    Toma el CSV crudo generado por el sniffer y lo deja listo para el modelo,
    usando los MISMOS encoders.pkl y scaler.pkl con los que se entrenó
    (equivalente a transformar_features(df, fit=False) de limpieza.py).

    Columnas del NSL-KDD que NO son derivables de la captura de paquetes
    (num_compromised, root_shell, su_attempted, num_root, num_shells,
    hot, serror_rate, etc.) se rellenan con 0 — son variables de auditoría
    a nivel de host/aplicación, no de red. Esto se documenta como
    limitación metodológica explícita en la tesis.
    """
    import numpy as np
    import pandas as pd

    # Import local: limpieza.py vive en el mismo directorio (src/)
    from app.motor.preparacion_datos import COLUMNAS_BASE, COLUMNAS_NUMERICAS, COLUMNAS_CATEGORICAS

    df_captura = pd.read_csv(csv_captura)

    # Armar DataFrame con TODAS las columnas que espera el modelo,
    # en el mismo orden que COLUMNAS_BASE (sin "label", que no aplica aquí).
    df_modelo = pd.DataFrame()
    for col in COLUMNAS_BASE:
        if col == "label":
            continue
        if col in df_captura.columns:
            df_modelo[col] = df_captura[col]
        else:
            df_modelo[col] = 0  # placeholder documentado: no derivable de la red

    encoders = joblib.load(os.path.join(MODELS_DIR, "encoders.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))

    # Encoding categórico idéntico al "else" de transformar_features en limpieza.py
    for col in COLUMNAS_CATEGORICAS:
        le = encoders[col]
        df_modelo[col] = df_modelo[col].astype(str).apply(
            lambda x: le.transform([x])[0] if x in le.classes_ else 0
        )

    # Mismo feature engineering que limpieza.py
    df_modelo["ratio_src_dst"] = df_modelo["src_bytes"] / (df_modelo["dst_bytes"] + 1)
    df_modelo["tasa_errores"] = df_modelo["serror_rate"] + df_modelo["rerror_rate"]
    df_modelo["intentos_fallo_norm"] = df_modelo["num_failed_logins"] / (df_modelo["count"] + 1)
    df_modelo["actividad_root"] = df_modelo["root_shell"] + df_modelo["num_root"] + df_modelo["num_compromised"]

    X = df_modelo.values.astype(np.float32)
    X_scaled = scaler.transform(X)

    logger.info("Transformación completa: %s filas, %s features -> listo para el modelo",
                X_scaled.shape[0], X_scaled.shape[1])

    if salida_npy:
        np.save(salida_npy, X_scaled)
        logger.info("Array guardado en: %s", salida_npy)

    return X_scaled


def main():
    parser = argparse.ArgumentParser(description="Captura de tráfico real para Nemesis")
    parser.add_argument("--iface", required=True, help='Nombre de interfaz (ej. "Wi-Fi", "eth0")')
    parser.add_argument("--ventana", type=int, default=5, help="Segundos por ventana de agregación")
    parser.add_argument("--duracion", type=int, default=300, help="Duración total de captura en segundos")
    parser.add_argument("--salida", default=os.path.join(DATA_DIR, "trafico_real.csv"), help="CSV de salida")
    parser.add_argument("--transformar", action="store_true",
                         help="Al terminar la captura, aplica encoders/scaler reales y guarda un .npy listo para el modelo")
    args = parser.parse_args()

    columnas = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "duration",
        "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
        "count", "srv_count", "same_srv_rate", "diff_srv_rate",
        "num_failed_logins", "root_shell", "logged_in",
    ]
    nuevo = not os.path.exists(args.salida)
    f_out = open(args.salida, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(f_out, fieldnames=columnas)
    if nuevo:
        writer.writeheader()

    agregador = AgregadorFlujos(ventana_segundos=args.ventana)
    logger.info("Iniciando captura en interfaz '%s' por %ss (ventanas de %ss)",
                args.iface, args.duracion, args.ventana)
    logger.info("Guardando en: %s", args.salida)

    tiempo_inicio = time.time()
    tiempo_ultima_ventana = tiempo_inicio

    def callback(pkt):
        nonlocal tiempo_ultima_ventana
        agregador.procesar_paquete(pkt)
        if time.time() - tiempo_ultima_ventana >= args.ventana:
            agregador.volcar_features(writer)
            f_out.flush()
            tiempo_ultima_ventana = time.time()
            logger.info("Ventana volcada a CSV (%ss transcurridos)",
                        round(time.time() - tiempo_inicio))

    try:
        sniff(iface=args.iface, prn=callback, store=False,
              timeout=args.duracion, filter="ip")
    except PermissionError:
        logger.error("Permiso denegado. Ejecuta como Administrador/root (y con Npcap en Windows).")
    finally:
        agregador.volcar_features(writer)
        f_out.close()
        logger.info("Captura finalizada. Archivo: %s", args.salida)

        if args.transformar:
            npy_salida = os.path.splitext(args.salida)[0] + "_transformado.npy"
            try:
                transformar_con_modelo_real(args.salida, salida_npy=npy_salida)
            except Exception as e:
                logger.error("No se pudo transformar con encoders/scaler reales: %s", e)


if __name__ == "__main__":
    main()