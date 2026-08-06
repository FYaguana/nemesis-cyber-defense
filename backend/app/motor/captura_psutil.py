"""
captura_psutil.py -- Monitoreo de red SIN dependencia de Npcap/libpcap.
========================================================================
Motivación: scapy.sniff() necesita un driver de captura a bajo nivel
(Npcap en Windows, libpcap en Linux/Mac). Eso implica instalar software
adicional y, en Windows, ejecutar como Administrador. Este módulo evita
esa dependencia por completo usando `psutil`, que lee las conexiones y
contadores de red que el sistema operativo ya expone (no abre un socket
en modo promiscuo ni intercepta paquetes ajenos).

Costo de la simplificación (documentado, no oculto):
- No hay inspección de paquete a paquete, así que "flag" (S0/REJ/RSTO/SF)
  se infiere del ESTADO de la conexión (psutil.net_connections), no de
  los flags TCP reales.
- src_bytes/dst_bytes NO son por-conexión (el SO no expone eso sin
  captura); se aproximan repartiendo el delta de bytes de la interfaz
  (psutil.net_io_counters) entre las conexiones activas de la ventana.
  Es una aproximación agregada, útil para alimentar el mismo pipeline
  de features NSL-KDD-like, pero menos preciso que la captura real.
- Solo ve conexiones de ESTA máquina (igual que el modo scapy sin
  puerto SPAN), nunca tráfico ajeno de otros dispositivos de la red.

Requisitos: `pip install psutil` (multiplataforma, sin instaladores
externos). En Windows puede necesitar ejecutar como Administrador para
ver conexiones de otros procesos, pero NUNCA pide instalar Npcap.
"""

import logging
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
