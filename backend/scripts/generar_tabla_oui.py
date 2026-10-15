"""
generar_tabla_oui.py -- Genera data/oui_fabricantes.json: tabla LOCAL de
prefijos OUI (primeros 3 bytes de la MAC) -> fabricante, limitada a marcas
comunes en redes domésticas y corporativas.

Fuente de los datos: registro público MA-L del IEEE, tal como lo distribuye
el paquete 'netaddr' (netaddr/eui/oui.txt). No se escribe ningún prefijo "de
memoria": cada entrada sale del archivo oficial.

Uso (solo cuando se quiera actualizar la tabla; NO es necesario en producción,
porque el JSON generado se versiona en el repositorio):
    pip install netaddr
    python scripts/generar_tabla_oui.py
"""
import json
import os
import re
import sys

# (patrón sobre el nombre de la organización en el IEEE) -> nombre que se muestra
FABRICANTES = [
    (r"^Apple", "Apple"),
    (r"^Samsung", "Samsung"),
    (r"^TP-LINK|^TP-Link", "TP-Link"),
    (r"^Xiaomi", "Xiaomi"),
    (r"^Huawei|^HUAWEI", "Huawei"),
    (r"^Google", "Google (Nest/Chromecast/Pixel)"),
    (r"^Amazon", "Amazon (Echo/Fire TV)"),
    (r"^Intel Corporate", "Intel"),
    (r"^Cisco", "Cisco"),
    (r"^NETGEAR|^Netgear", "Netgear"),
    (r"^D-Link|^D-LINK", "D-Link"),
    (r"^ASUSTek|^ASUSTEK|^ASUS", "ASUS"),
    (r"^LG Electronics|^LG Innotek", "LG"),
    (r"^Sony", "Sony"),
    (r"^Raspberry Pi", "Raspberry Pi"),
    (r"^VMware", "VMware"),
    (r"^Microsoft", "Microsoft"),
    (r"^Realtek", "Realtek"),
    (r"^Espressif", "Espressif (dispositivo IoT)"),
    (r"^Tuya", "Tuya (dispositivo IoT)"),
    (r"^Roku", "Roku"),
    (r"^Hangzhou Hikvision|^Hikvision", "Hikvision (cámara)"),
    (r"^Ubiquiti", "Ubiquiti"),
    (r"^Routerboard|^MikroTik", "MikroTik"),
    (r"^Hewlett Packard|^HP Inc", "HP"),
    (r"^Dell", "Dell"),
    (r"^Lenovo", "Lenovo"),
    (r"^Seiko Epson", "Epson"),
    (r"^Canon", "Canon"),
    (r"^Brother Industries", "Brother"),
    (r"^Philips|^Signify", "Philips/Signify"),
    (r"^Motorola", "Motorola"),
    (r"^OnePlus", "OnePlus"),
    (r"^GUANGDONG OPPO|^OPPO", "OPPO"),
    (r"^vivo Mobile|^Vivo Mobile", "vivo"),
    (r"^Zyxel|^ZyXEL", "Zyxel"),
    (r"^ZTE", "ZTE"),
    (r"^Nintendo", "Nintendo"),
    (r"^Sonos", "Sonos"),
    (r"^PCS Systemtechnik", "VirtualBox"),
    (r"^Hon Hai|^Foxconn", "Hon Hai/Foxconn (módulo de red)"),
    (r"^AzureWave", "AzureWave (módulo Wi-Fi)"),
    (r"^Liteon|^LITE-ON", "Lite-On (módulo Wi-Fi)"),
    (r"^Murata", "Murata (módulo Wi-Fi)"),
    (r"^Broadcom", "Broadcom"),
    (r"^Qualcomm", "Qualcomm"),
    (r"^MediaTek", "MediaTek"),
    (r"^Texas Instruments", "Texas Instruments"),
    (r"^Arris|^ARRIS", "Arris (módem/router)"),
    (r"^Technicolor", "Technicolor (módem/router)"),
    (r"^Fiberhome|^FiberHome", "FiberHome (ONT/router)"),
    (r"^Nokia", "Nokia"),
    (r"^Ruijie", "Ruijie"),
    (r"^Aruba", "Aruba"),
    (r"^Ring LLC", "Ring"),
    (r"^Wyze", "Wyze (cámara)"),
    (r"^Belkin", "Belkin"),
    (r"^Linksys", "Linksys"),
    (r"^Western Digital", "Western Digital"),
    (r"^Synology", "Synology (NAS)"),
    (r"^QNAP", "QNAP (NAS)"),
]


def localizar_oui_txt():
    try:
        import netaddr
    except ImportError:
        sys.exit("Falta 'netaddr' (solo para regenerar la tabla): pip install netaddr")
    ruta = os.path.join(os.path.dirname(netaddr.__file__), "eui", "oui.txt")
    if not os.path.exists(ruta):
        sys.exit(f"No se encontró {ruta}")
    return ruta, netaddr.__version__


def main():
    ruta_txt, version = localizar_oui_txt()
    patrones = [(re.compile(p, re.IGNORECASE), nombre) for p, nombre in FABRICANTES]
    tabla, total = {}, 0
    with open(ruta_txt, encoding="utf-8", errors="replace") as f:
        for linea in f:
            m = re.match(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$", linea)
            if not m:
                continue
            total += 1
            prefijo = (m.group(1) + m.group(2) + m.group(3)).upper()
            organizacion = m.group(4)
            for rx, nombre in patrones:
                if rx.search(organizacion):
                    tabla[prefijo] = nombre
                    break

    destino = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data", "oui_fabricantes.json")
    salida = {
        "_fuente": f"Registro IEEE MA-L (vía netaddr {version}). Tabla curada de fabricantes comunes.",
        "_prefijos_ieee_totales": total,
        "_prefijos_incluidos": len(tabla),
        "prefijos": dict(sorted(tabla.items())),
    }
    with open(destino, "w", encoding="utf-8") as f:
        json.dump(salida, f, ensure_ascii=False, indent=0, separators=(",", ":"))
    print(f"OK: {len(tabla)} prefijos de {total} del IEEE -> {destino}")


if __name__ == "__main__":
    main()
