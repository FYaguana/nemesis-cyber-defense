"""
identificacion_dispositivos.py -- Dos mecanismos que la tesis documenta y que
el Panel de Monitoreo de Red muestra por cada flujo (Ilustración 5):

1) Identificación del FABRICANTE del dispositivo de origen (Sección 4.5):
   prefijo OUI (primeros 3 bytes de la MAC) contra una tabla LOCAL de
   fabricantes comunes, sin consultar servicios externos. La tabla
   (data/oui_fabricantes.json) se genera desde el registro público del IEEE
   con scripts/generar_tabla_oui.py.

2) Puntaje de CONFIABILIDAD DE DESTINO (Secciones 3.6 y 4.4): evalúa el
   historial reciente de cada IP de destino observada durante la sesión de
   monitoreo. Complementa -sin reemplazar- la clasificación por evento
   individual con contexto temporal acumulado:

       tasa_anomala = conexiones_anomalas / (conexiones_normales + conexiones_anomalas)

   - menos de 3 observaciones          -> "sin historial suficiente"  (nivel 'nuevo')
   - tasa_anomala == 0                 -> "confiable"                  (nivel 'confiable')
   - tasa_anomala >= 40 %              -> "poco confiable"             (nivel 'no_confiable')
   - cualquier otro caso               -> confiabilidad mixta          (nivel 'revisar')

Los textos 'no identificado' y 'genérico' de identificar_dispositivo() son los
que el dashboard (dashboard.html) usa para ocultar etiquetas poco informativas.
"""

import json
import os
import re
import threading
from collections import OrderedDict, deque

DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUTA_TABLA_OUI = os.path.join(DIRECTORIO_BACKEND, "data", "oui_fabricantes.json")

TEXTO_NO_IDENTIFICADO = "Dispositivo no identificado"
TEXTO_MAC_PRIVADA = "Dispositivo con MAC privada (genérico)"
TEXTO_LOOPBACK = "Equipo local (loopback)"

# ─── 1) Fabricante por OUI ───────────────────────────────────────────────────

_tabla_oui = None
_candado_oui = threading.Lock()


def _cargar_tabla_oui() -> dict:
    global _tabla_oui
    if _tabla_oui is None:
        with _candado_oui:
            if _tabla_oui is None:
                try:
                    with open(RUTA_TABLA_OUI, "r", encoding="utf-8") as f:
                        _tabla_oui = json.load(f).get("prefijos", {})
                except (OSError, json.JSONDecodeError):
                    # Sin tabla el sistema sigue funcionando: todo queda "no identificado".
                    _tabla_oui = {}
    return _tabla_oui


def normalizar_mac(mac):
    """Devuelve la MAC como 12 dígitos hex en mayúsculas, o None si no es válida."""
    if not mac or not isinstance(mac, str):
        return None
    limpia = re.sub(r"[^0-9A-Fa-f]", "", mac)
    return limpia.upper() if len(limpia) == 12 else None


def es_mac_privada(mac) -> bool:
    """True si la MAC es 'localmente administrada' (bit 0x02 del primer byte).
    Los teléfonos modernos y Docker/QEMU las usan: el prefijo NO identifica un
    fabricante, así que no se debe intentar resolverlo."""
    limpia = normalizar_mac(mac)
    return bool(limpia) and bool(int(limpia[:2], 16) & 0x02)


def identificar_dispositivo(mac) -> str:
    """Fabricante del dispositivo según el OUI de su MAC (tabla local)."""
    limpia = normalizar_mac(mac)
    if limpia is None:
        return TEXTO_NO_IDENTIFICADO
    if limpia == "000000000000":
        return TEXTO_LOOPBACK  # interfaz de loopback: tráfico del propio equipo, no un fabricante
    if es_mac_privada(limpia):
        return TEXTO_MAC_PRIVADA
    return _cargar_tabla_oui().get(limpia[:6], TEXTO_NO_IDENTIFICADO)


# ─── 2) Confiabilidad de destino ─────────────────────────────────────────────

MIN_OBSERVACIONES = 3
UMBRAL_POCO_CONFIABLE = 0.40


class ReputacionDestinos:
    """Historial acotado por IP de destino (memoria limitada: sesiones largas no
    deben crecer sin control)."""

    def __init__(self, max_destinos: int = 5000, max_observaciones: int = 200):
        self._historial = OrderedDict()  # ip -> deque[bool es_anomalo]
        self._max_destinos = max_destinos
        self._max_obs = max_observaciones
        self._candado = threading.Lock()

    def evaluar(self, ip_destino) -> dict:
        """Reputación según el historial PREVIO (sin contar el flujo actual, para
        que el propio evento no se influya a sí mismo)."""
        with self._candado:
            historial = list(self._historial.get(ip_destino, ()))
        n = len(historial)
        anomalas = sum(historial)
        tasa = (anomalas / n) if n else 0.0

        if n < MIN_OBSERVACIONES:
            nivel, texto = "nuevo", f"Sin historial suficiente ({n} observaciones previas)"
        elif anomalas == 0:
            nivel, texto = "confiable", f"Sin conexiones anómalas en {n} observaciones"
        elif tasa >= UMBRAL_POCO_CONFIABLE:
            nivel, texto = "no_confiable", f"{tasa:.0%} de {n} conexiones previas fueron anómalas"
        else:
            nivel, texto = "revisar", f"{tasa:.0%} de {n} conexiones previas fueron anómalas"
        return {"nivel": nivel, "texto": texto, "observaciones": n,
                "tasa_anomala": round(tasa, 4)}

    def registrar(self, ip_destino, es_anomalo: bool) -> None:
        if not ip_destino:
            return
        with self._candado:
            cola = self._historial.get(ip_destino)
            if cola is None:
                cola = deque(maxlen=self._max_obs)
                self._historial[ip_destino] = cola
                if len(self._historial) > self._max_destinos:
                    self._historial.popitem(last=False)  # descarta el más antiguo
            else:
                self._historial.move_to_end(ip_destino)
            cola.append(bool(es_anomalo))

    def reiniciar(self) -> None:
        with self._candado:
            self._historial.clear()
