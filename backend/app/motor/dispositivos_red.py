"""
dispositivos_red.py -- Inventario de dispositivos conectados a la LAN.
========================================================================
Objetivo: mostrar en el dashboard "qué hay conectado a mi red" (IP, MAC,
hostname), NO interceptar el tráfico de esos dispositivos (eso sí
requeriría ARP spoofing / puerto SPAN, fuera de alcance ético y técnico,
como ya documenta captura_paquetes.py).

Diseño sin Npcap:
1. Ping sweep del rango /24 local usando el comando `ping` del sistema
   operativo (subprocess), NO sockets crudos -> no requiere Npcap ni
   privilegios especiales.
2. Lectura de la tabla ARP que el sistema operativo ya mantiene
   (`arp -a` en Windows/Mac, `ip neigh` en Linux) para obtener las MAC
   de los hosts que respondieron. También es 100% a través de comandos
   estándar del SO, sin captura de paquetes.
3. Resolución de hostname best-effort vía socket.gethostbyaddr (con
   timeout corto para no colgar el escaneo si el dispositivo no
   responde a resolución inversa).

Limitación documentada: solo detecta dispositivos en el MISMO segmento
L2 (misma subred/VLAN) que la máquina donde corre el backend. Como el
ping sweep + arp son la técnica estándar de descubrimiento LAN (la
misma que usan herramientas como `arp-scan` o el "Fing" doméstico), no
hace falta ningún driver de captura.
"""

import ipaddress
import logging
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil

logger = logging.getLogger(__name__)

ES_WINDOWS = platform.system().lower() == "windows"


def _obtener_redes_locales():
    """Devuelve las redes IPv4 /24-ish de las interfaces activas
    (excluye loopback y las que no tienen IPv4)."""
    redes = []
    for nombre, direcciones in psutil.net_if_addrs().items():
        ipv4 = next((d for d in direcciones if d.family == socket.AF_INET), None)
        if not ipv4 or ipv4.address.startswith("127."):
            continue
        try:
            red = ipaddress.IPv4Network(f"{ipv4.address}/{ipv4.netmask}", strict=False)
        except ValueError:
            continue
        # Evita escaneos gigantes si la máscara es muy abierta; limitamos a /22 como mucho.
        if red.num_addresses > 1024:
            continue
        redes.append((nombre, red))
    return redes


def _ping(ip: str, timeout_ms: int = 800) -> bool:
    """Un solo ping usando el binario del sistema operativo (no scapy,
    no socket crudo). Devuelve True si respondió."""
    if ES_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(timeout_ms // 1000, 1)), ip]
    try:
        resultado = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
        )
        return resultado.returncode == 0
    except Exception:
        return False


def _leer_tabla_arp():
    """Lee la tabla ARP/vecinos que el SO ya mantiene. Retorna dict ip -> mac."""
    tabla = {}
    try:
        if ES_WINDOWS:
            salida = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            ).stdout
            for linea in salida.splitlines():
                m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", linea)
                if m:
                    tabla[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            # Linux moderno: `ip neigh`. Fallback a `arp -n` (Mac / distros viejas).
            try:
                salida = subprocess.run(
                    ["ip", "neigh"], capture_output=True, text=True, timeout=5
                ).stdout
                for linea in salida.splitlines():
                    partes = linea.split()
                    if len(partes) >= 5 and partes[0].count(".") == 3:
                        ip, mac = partes[0], partes[4]
                        if re.match(r"^[0-9a-fA-F:]{17}$", mac):
                            tabla[ip] = mac.lower()
            except FileNotFoundError:
                salida = subprocess.run(
                    ["arp", "-n"], capture_output=True, text=True, timeout=5
                ).stdout
                for linea in salida.splitlines():
                    m = re.match(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})", linea)
                    if m:
                        tabla[m.group(1)] = m.group(2).lower()
    except Exception as e:
        logger.warning("No se pudo leer la tabla ARP: %s", e)
    return tabla


def _resolver_hostname(ip: str) -> str | None:
    try:
        socket.setdefaulttimeout(0.5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def escanear_dispositivos_lan(max_hilos: int = 64) -> dict:
    """
    Escanea las redes locales conectadas y devuelve la lista de
    dispositivos detectados (IP, MAC, hostname si se pudo resolver).
    No requiere Npcap ni privilegios de administrador.
    """
    redes = _obtener_redes_locales()
    if not redes:
        return {"ok": False, "mensaje": "No se detectó ninguna red local activa.", "dispositivos": []}

    hosts = []
    for _nombre_iface, red in redes:
        hosts.extend([str(ip) for ip in red.hosts()])
    hosts = list(dict.fromkeys(hosts))  # dedup preservando orden

    with ThreadPoolExecutor(max_workers=max_hilos) as pool:
        futuros = {pool.submit(_ping, ip): ip for ip in hosts}
        for f in as_completed(futuros):
            f.result()  # solo dispara el ping; el resultado real sale de la tabla ARP

    tabla_arp = _leer_tabla_arp()

    dispositivos = []
    ips_locales = {d.address for direcciones in psutil.net_if_addrs().values()
                   for d in direcciones if d.family == socket.AF_INET}

    with ThreadPoolExecutor(max_workers=max_hilos) as pool:
        futuros_hostname = {
            pool.submit(_resolver_hostname, ip): ip for ip in tabla_arp
        }
        hostnames = {}
        for f in as_completed(futuros_hostname):
            ip = futuros_hostname[f]
            hostnames[ip] = f.result()

    for ip, mac in sorted(tabla_arp.items(), key=lambda kv: tuple(int(p) for p in kv[0].split("."))):
        dispositivos.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostnames.get(ip),
            "es_este_equipo": ip in ips_locales,
        })

    return {
        "ok": True,
        "mensaje": f"{len(dispositivos)} dispositivo(s) detectado(s).",
        "redes_escaneadas": [str(r) for _n, r in redes],
        "dispositivos": dispositivos,
    }
