"""
captura_real_integracion.py – Monitoreo continuo de red real, integrado al
motor de inferencia/alertas ya existente (procesador_nemesis.py).

Vive en la raíz del proyecto, junto a app_v2.py y procesador_nemesis.py.

Diseño (v2 – monitoreo siempre activo, no una sesión puntual):
- Al arrancar el servidor (app_v2.py), se dispara un monitoreo CONTINUO en
  un hilo de fondo: se repiten ciclos cortos de captura (uno por "ventana")
  indefinidamente, hasta que se detiene explícitamente o se apaga el server.
  Esto es lo que hace que el Dashboard tenga datos reales apenas se entra,
  en vez de arrancar en cero esperando que alguien presione un botón.
- Cada ventana de flujos se pasa TAL CUAL a proc.analizar_trafico(fila) —
  el mismo método que ya usan los botones de simulación del dashboard.
  Reutiliza 100% de la lógica ya construida: MLP + RNN, consenso, severidad,
  cooldown de alertas, explicabilidad y guardado en BD.
- La interfaz de red se auto-detecta (ruta por defecto del sistema) si no
  hay una configurada; una vez que funciona una, se guarda en
  data/config_red_real.json para reutilizarla en el próximo arranque.
"""

import os
import json
import time
import logging
import threading

# backend/app/motor/captura_red.py -> subir 3 niveles llega a backend/
DIRECTORIO_BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(DIRECTORIO_BACKEND, "data")
CONFIG_PATH = os.path.join(DATA_DIR, "config_red_real.json")

os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NEMESIS-CAPTURA-REAL] %(message)s")
logger = logging.getLogger(__name__)


def cargar_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def guardar_config(config: dict):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.warning("No se pudo guardar la configuración de red: %s", e)


def detectar_interfaz_predeterminada():
    """
    Intenta adivinar la interfaz de red activa del equipo (la que scapy
    usaría por defecto para salir a internet). Si falla, retorna None
    y el llamador decide un fallback.
    """
    try:
        from scapy.all import conf
        iface = conf.iface
        return str(iface) if iface else None
    except Exception as e:
        logger.warning("No se pudo autodetectar la interfaz de red: %s", e)
        return None


class GestorCapturaReal:
    """
    Orquesta el MONITOREO CONTINUO de la red: repite ciclos de captura de
    'ventana' segundos indefinidamente, acumulando resultados clasificados
    para que el dashboard los consulte por polling. Pensado para UNA
    instancia de monitoreo activa por servidor (suficiente para un
    prototipo desplegado en un equipo/sede; no está diseñado para múltiples
    sensores en simultáneo dentro del mismo proceso).
    """

    def __init__(self):
        self.activa = False
        self.hilo = None
        self.resultados = []
        self.lock = threading.Lock()
        self.progreso = {"transcurrido": 0, "flujos_procesados": 0,
                          "flujos_omitidos": 0, "ultimo_error_flujo": None,
                          "ciclos_completados": 0}
        self.error = None
        self.iface_actual = None
        self.backend_actual = "psutil"
        self._detener_solicitado = threading.Event()

    def iniciar_continuo(self, iface: str = None, ventana: int = 5, backend: str = None):
        """Arranca (o re-arranca) el monitoreo continuo con la interfaz dada.
        Si no se especifica interfaz, intenta la guardada en config y luego
        la autodetectada.

        backend:
            "psutil" (default) -- NO requiere Npcap/libpcap. Lee conexiones
                y contadores que el SO ya expone. Recomendado salvo que se
                necesite inspección de paquete a paquete.
            "scapy"  -- captura real de paquetes (más preciso), requiere
                Npcap instalado en Windows (o libpcap en Linux/Mac) y
                privilegios de administrador/root.
        """
        if self.activa:
            return False, "El monitoreo ya está activo."

        config = cargar_config()
        backend = (backend or config.get("backend") or "psutil").lower()
        if backend not in ("psutil", "scapy"):
            backend = "psutil"

        if backend == "scapy":
            if not iface:
                iface = config.get("iface") or detectar_interfaz_predeterminada()
            if not iface:
                self.error = ("No se pudo determinar automáticamente la interfaz de red. "
                              "Configúrala manualmente en 'Red Real', o usá el backend "
                              "'psutil' que no necesita interfaz ni Npcap.")
                logger.warning(self.error)
                return False, self.error
        # El backend "psutil" no necesita nombre de interfaz: monitorea
        # todas las conexiones activas del equipo vía el SO.

        self.activa = True
        self.error = None
        self._detener_solicitado.clear()
        self.iface_actual = iface
        self.backend_actual = backend
        with self.lock:
            self.resultados = []
        self.progreso = {"transcurrido": 0, "flujos_procesados": 0,
                          "flujos_omitidos": 0, "ultimo_error_flujo": None,
                          "ciclos_completados": 0}

        objetivo = self._ejecutar_continuo if backend == "scapy" else self._ejecutar_continuo_psutil
        args = (iface, ventana) if backend == "scapy" else (ventana,)
        self.hilo = threading.Thread(target=objetivo, args=args, daemon=True)
        self.hilo.start()
        guardar_config({"iface": iface, "backend": backend})
        logger.info("Monitoreo continuo iniciado (backend=%s, iface=%s, ventana=%ss)",
                    backend, iface, ventana)
        return True, "Monitoreo iniciado."

    def detener(self):
        if not self.activa:
            return False, "El monitoreo no está activo."
        self._detener_solicitado.set()
        logger.info("Detención de monitoreo solicitada, se aplicará en el próximo ciclo (~unos segundos).")
        return True, "Deteniendo monitoreo..."

    def _ejecutar_continuo(self, iface, ventana):
        try:
            from scapy.all import sniff
            from app.motor.captura_paquetes import AgregadorFlujos
        except ImportError as e:
            self.error = f"Falta una dependencia: {e}. Instala con: pip install scapy"
            self.activa = False
            logger.error(self.error)
            return

        from app.motor.procesador_nemesis import obtener_procesador
        proc = obtener_procesador()

        if not proc._cargado:
            self.error = "Los modelos no están cargados. Ejecuta entrenar_nemesis.py primero."
            self.activa = False
            logger.error(self.error)
            return

        inicio_global = time.time()
        # Metadatos de captura (para mostrar en UI), NO son features del modelo.
        # Se separan antes de llamar a analizar_trafico() para que no intente
        # convertir strings (IPs, timestamps) a float32 y falle en silencio.
        CLAVES_METADATO = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port"}

        def procesar_filas(filas):
            for fila in filas:
                metadato = {k: fila[k] for k in CLAVES_METADATO if k in fila}
                muestra = {k: v for k, v in fila.items() if k not in CLAVES_METADATO}
                try:
                    resultado = proc.analizar_trafico(muestra)
                    if "error" in resultado:
                        logger.warning("Flujo real omitido (%s): %s", metadato, resultado["error"])
                        self.progreso["flujos_omitidos"] += 1
                        self.progreso["ultimo_error_flujo"] = resultado["error"]
                        continue
                    resultado["_fuente"] = "red_real"
                    resultado["_flujo"] = metadato
                    with self.lock:
                        self.resultados.append(resultado)
                        # Cap de memoria: conserva solo los últimos 500 resultados
                        # para que una sesión de varias horas no crezca sin límite.
                        if len(self.resultados) > 500:
                            self.resultados = self.resultados[-500:]
                        self.progreso["flujos_procesados"] += 1
                except Exception as e:
                    logger.error("Error analizando flujo real (%s): %s", metadato, e)
                    self.progreso["flujos_omitidos"] += 1
                    self.progreso["ultimo_error_flujo"] = str(e)

        try:
            while not self._detener_solicitado.is_set():
                agregador = AgregadorFlujos(ventana_segundos=ventana)

                def callback(pkt, _ag=agregador):
                    _ag.procesar_paquete(pkt)

                # Cada ciclo captura durante 'ventana' segundos y luego procesa
                # esas filas; el stop_filter permite cortar casi al instante
                # si se pide detener, en vez de esperar el ciclo completo.
                sniff(iface=iface, prn=callback, store=False, timeout=ventana,
                      filter="ip", stop_filter=lambda p: self._detener_solicitado.is_set())

                filas = agregador.construir_filas()
                procesar_filas(filas)
                self.progreso["ciclos_completados"] += 1
                self.progreso["transcurrido"] = round(time.time() - inicio_global, 1)

        except PermissionError:
            self.error = "Permiso denegado. Ejecuta el servidor como Administrador/root."
            logger.error(self.error)
        except Exception as e:
            self.error = str(e)
            logger.error("Error durante el monitoreo continuo: %s", e)
        finally:
            self.activa = False
            logger.info("Monitoreo continuo detenido. Flujos procesados: %s en %s ciclos",
                        self.progreso["flujos_procesados"], self.progreso["ciclos_completados"])

    def _ejecutar_continuo_psutil(self, ventana):
        """Igual que _ejecutar_continuo pero SIN scapy/Npcap: usa
        captura_psutil.AgregadorFlujosPsutil, que lee conexiones y
        contadores de red vía el sistema operativo."""
        try:
            from app.motor.captura_psutil import AgregadorFlujosPsutil
        except ImportError as e:
            self.error = f"Falta una dependencia: {e}. Instala con: pip install psutil"
            self.activa = False
            logger.error(self.error)
            return

        from app.motor.procesador_nemesis import obtener_procesador
        proc = obtener_procesador()

        if not proc._cargado:
            self.error = "Los modelos no están cargados. Ejecuta entrenar_nemesis.py primero."
            self.activa = False
            logger.error(self.error)
            return

        inicio_global = time.time()
        CLAVES_METADATO = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port"}

        def procesar_filas(filas):
            for fila in filas:
                metadato = {k: fila[k] for k in CLAVES_METADATO if k in fila}
                muestra = {k: v for k, v in fila.items() if k not in CLAVES_METADATO}
                try:
                    resultado = proc.analizar_trafico(muestra)
                    if "error" in resultado:
                        logger.warning("Flujo real omitido (%s): %s", metadato, resultado["error"])
                        self.progreso["flujos_omitidos"] += 1
                        self.progreso["ultimo_error_flujo"] = resultado["error"]
                        continue
                    resultado["_fuente"] = "red_real_psutil"
                    resultado["_flujo"] = metadato
                    with self.lock:
                        self.resultados.append(resultado)
                        if len(self.resultados) > 500:
                            self.resultados = self.resultados[-500:]
                        self.progreso["flujos_procesados"] += 1
                except Exception as e:
                    logger.error("Error analizando flujo real (%s): %s", metadato, e)
                    self.progreso["flujos_omitidos"] += 1
                    self.progreso["ultimo_error_flujo"] = str(e)

        try:
            agregador = AgregadorFlujosPsutil(ventana_segundos=ventana)
            while not self._detener_solicitado.is_set():
                agregador.iniciar_ventana()
                # Espera activa (en pasos cortos) para poder cortar casi al
                # instante si se pide detener, igual que el stop_filter de scapy.
                objetivo = time.time() + ventana
                while time.time() < objetivo and not self._detener_solicitado.is_set():
                    time.sleep(min(0.5, max(objetivo - time.time(), 0)))

                filas = agregador.construir_filas()
                procesar_filas(filas)
                self.progreso["ciclos_completados"] += 1
                self.progreso["transcurrido"] = round(time.time() - inicio_global, 1)

        except PermissionError:
            self.error = ("Permiso denegado leyendo conexiones de red. En Windows corré el "
                          "backend como Administrador; en Linux/Mac con sudo. (Esto NO "
                          "requiere instalar Npcap, solo privilegios del proceso.)")
            logger.error(self.error)
        except Exception as e:
            self.error = str(e)
            logger.error("Error durante el monitoreo continuo (psutil): %s", e)
        finally:
            self.activa = False
            logger.info("Monitoreo continuo (psutil) detenido. Flujos procesados: %s en %s ciclos",
                        self.progreso["flujos_procesados"], self.progreso["ciclos_completados"])

    def obtener_estado(self, desde_indice: int = 0):
        with self.lock:
            total = len(self.resultados)
            nuevos = self.resultados[desde_indice:] if desde_indice < total else []
        return {
            "activa": self.activa,
            "error": self.error,
            "iface": self.iface_actual,
            "backend": getattr(self, "backend_actual", "psutil"),
            "progreso": self.progreso,
            "total_resultados": total,
            "nuevos": nuevos,
        }


_gestor_global: "GestorCapturaReal | None" = None


def obtener_gestor_captura() -> GestorCapturaReal:
    global _gestor_global
    if _gestor_global is None:
        _gestor_global = GestorCapturaReal()
    return _gestor_global