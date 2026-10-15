"""
captura_psutil.py -- Monitoreo de RESPALDO sin Npcap/libpcap (modo degradado).
==============================================================================
La tesis (Secciones 3.7 y 4.5) define la captura con Scapy, que observa paquetes.
En Windows eso exige instalar Npcap. Este módulo existe para que el sistema siga
mostrando actividad de red en equipos donde Scapy NO puede capturar, usando
`psutil`, que lee las conexiones y contadores que el sistema operativo ya expone
(no abre sockets en modo promiscuo ni intercepta paquetes).

DIFERENCIA CON LA TESIS (documentar, no ocultar): la tesis establece que las
variables no derivables de la observación pasiva NO se aproximan artificialmente.
En este modo, al no haber paquetes, dos variables SÍ son aproximaciones:
- "flag" (S0/REJ/RSTO/SF) se infiere del ESTADO de la conexión, no de banderas TCP reales.
- src_bytes/dst_bytes NO son por conexión: se reparte el delta de bytes de la interfaz
  entre las conexiones activas de la ventana.
Por eso (1) cada resultado lleva `_backend = "psutil"` y la interfaz lo muestra como
"modo de respaldo", y (2) sus capturas NO se usan para reentrenar el modelo (ver
base_datos.obtener_capturas_etiquetadas). Para resultados comparables con el Capítulo 5
debe usarse Scapy.

Solo ve conexiones de ESTA máquina, igual que el modo Scapy sin puerto SPAN.
Requisitos: `pip install psutil`. En Windows puede requerir Administrador para ver
conexiones de otros procesos, pero NUNCA pide instalar Npcap.
"""

import logging
import socket
import time
from collections import deque
from datetime import datetime

import psutil

logger = logging.getLogger(__name__)

# Mismo mapeo que captura_paquetes.py (servicios que el encoder conoce)
SERVICE_MAP = {
    21: "ftp", 20: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http", 8080: "http", 443: "http",
}


def _macs_locales() -> dict:
    """IP local -> MAC de la interfaz que la tiene (para identificar el fabricante del equipo)."""
    mapa = {}
    for _nombre, direcciones in psutil.net_if_addrs().items():
        mac = next((d.address for d in direcciones if d.family == psutil.AF_LINK), None)
        for d in direcciones:
            if d.family == socket.AF_INET:
                mapa[d.address] = mac
    return mapa


def resolver_service(puerto):
    return SERVICE_MAP.get(puerto, "http")


def _flag_desde_estado(estado: str) -> str:
    """Traduce el estado de psutil a una de las 4 categorías que el
    encoder conoce: REJ, RSTO, S0, SF."""
    mapa = {
        "ESTABLISHED": "SF",
        "SYN_SENT": "S0",
        "SYN_RECV": "S0",
        "CLOSE_WAIT": "SF",
        "TIME_WAIT": "SF",
        "CLOSE": "RSTO",
        "CLOSING": "RSTO",
        "LAST_ACK": "RSTO",
        "FIN_WAIT1": "SF",
        "FIN_WAIT2": "SF",
        "NONE": "SF",  # típico en UDP, que no tiene estado de conexión
    }
    return mapa.get(estado, "SF")


class AgregadorFlujosPsutil:
    """
    Equivalente a AgregadorFlujos (captura_paquetes.py) pero alimentado
    por snapshots de psutil en vez de paquetes capturados. Se usa igual:
    se llama a `tomar_muestra()` al inicio y al final de la ventana, y
    `construir_filas()` arma las filas listas para procesador_nemesis.
    """

    def __init__(self, ventana_segundos=5):
        self.ventana_segundos = ventana_segundos
        self.historial_srv = deque(maxlen=200)
        self._io_inicio = None
        self._inicio = None

    def iniciar_ventana(self):
        self._inicio = time.time()
        self._io_inicio = psutil.net_io_counters()

    def construir_filas(self):
        """Toma un snapshot de conexiones activas y arma filas
        NSL-KDD-like, repartiendo el delta de bytes de la interfaz
        entre ellas (aproximación agregada, ver docstring del módulo)."""
        if self._inicio is None:
            self.iniciar_ventana()

        duracion = round(time.time() - self._inicio, 4)
        io_fin = psutil.net_io_counters()
        delta_sent = max(io_fin.bytes_sent - self._io_inicio.bytes_sent, 0)
        delta_recv = max(io_fin.bytes_recv - self._io_inicio.bytes_recv, 0)

        try:
            conexiones = [
                c for c in psutil.net_connections(kind="inet")
                if c.raddr and c.laddr
            ]
        except (psutil.AccessDenied, PermissionError):
            logger.warning(
                "Permiso denegado leyendo conexiones. En Windows, corré el "
                "backend como Administrador; en Linux/Mac, con sudo."
            )
            conexiones = []

        n = len(conexiones) or 1
        macs = _macs_locales()
        bytes_src_por_flujo = delta_sent // n
        bytes_dst_por_flujo = delta_recv // n

        filas = []
        for c in conexiones:
            proto = "tcp" if c.type == 1 else "udp"  # SOCK_STREAM=1, SOCK_DGRAM=2
            servicio = resolver_service(c.raddr.port)
            self.historial_srv.append(servicio)

        total = len(self.historial_srv) or 1
        for c in conexiones:
            proto = "tcp" if c.type == 1 else "udp"
            servicio = resolver_service(c.raddr.port)
            same_srv = self.historial_srv.count(servicio) / total
            filas.append({
                "timestamp": datetime.now().isoformat(),
                "src_ip": c.laddr.ip, "dst_ip": c.raddr.ip,
                "src_port": c.laddr.port, "dst_port": c.raddr.port,
                "src_mac": macs.get(c.laddr.ip),
                "duration": duracion,
                "protocol_type": proto,
                "service": servicio,
                "flag": _flag_desde_estado(c.status),
                "src_bytes": bytes_src_por_flujo,
                "dst_bytes": bytes_dst_por_flujo,
                "land": 1 if c.laddr.ip == c.raddr.ip else 0,
                "count": len(conexiones),
                "srv_count": self.historial_srv.count(servicio),
                "same_srv_rate": round(same_srv, 4),
                "diff_srv_rate": round(1 - same_srv, 4),
                "num_failed_logins": 0,
                "root_shell": 0,
                "logged_in": 0,
            })

        # Reinicia la ventana para el próximo ciclo
        self._inicio = None
        self._io_inicio = None
        return filas
