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
import platform

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


def scapy_disponible() -> bool:
    """True si la captura real de paquetes con Scapy puede funcionar en este equipo.

    - Linux/macOS: Scapy usa sockets del sistema; alcanza con que el paquete esté instalado
      (y con privilegios de root al capturar).
    - Windows: Scapy necesita el driver Npcap; sin él NO puede capturar. En ese caso el
      sistema cae al modo de respaldo 'psutil' (sin Npcap, con precisión reducida)."""
    try:
        from scapy.all import conf
    except Exception:
        return False
    if platform.system().lower() == "windows":
        return bool(getattr(conf, "use_pcap", False))
    return True


def _autoinicio_habilitado() -> bool:
    """El monitoreo arranca solo en equipos propios, pero NO en plataformas cloud:
    allí el contenedor solo ve su propia red interna (no la red del usuario) y
    guardaría tráfico irrelevante. Se puede forzar con NEMESIS_MONITOREO_AUTOINICIO=true/false."""
    valor = os.environ.get("NEMESIS_MONITOREO_AUTOINICIO")
    if valor is not None:
        return valor.strip().lower() == "true"
    return not bool(os.environ.get("RENDER"))  # Render define RENDER=true en sus contenedores


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
        self.backend_actual = None
        from app.motor.identificacion_dispositivos import ReputacionDestinos
        self.reputacion = ReputacionDestinos()
        self._guardados = 0
        self._detener_solicitado = threading.Event()

    def iniciar_continuo(self, iface: str = None, ventana: int = 5, backend: str = None):
        """Arranca (o re-arranca) el monitoreo continuo.

        backend:
            "auto" (default) -- usa Scapy si puede capturar en este equipo y, si no
                (p. ej. Windows sin Npcap), cae al modo de respaldo 'psutil'.
            "scapy" -- captura real de paquetes (Sección 4.5 de la tesis). Requiere Npcap
                en Windows y privilegios de administrador/root.
            "psutil" -- respaldo SIN Npcap: lee las conexiones que el SO ya expone. NO
                observa paquetes, así que bytes y banderas son aproximaciones agregadas;
                por eso sus capturas se etiquetan y no se usan para reentrenar.
        """
        if self.activa:
            return False, "El monitoreo ya está activo."

        config = cargar_config()
        solicitado = (backend or config.get("backend") or "auto").lower()
        if solicitado not in ("auto", "scapy", "psutil"):
            solicitado = "auto"

        if solicitado == "auto":
            backend_real = "scapy" if scapy_disponible() else "psutil"
        else:
            backend_real = solicitado

        if backend_real == "scapy":
            if not scapy_disponible():
                self.error = ("La captura con Scapy no está disponible en este equipo "
                              "(en Windows requiere instalar Npcap y ejecutar como Administrador). "
                              "Usá el modo 'psutil', que no necesita Npcap.")
                logger.warning(self.error)
                return False, self.error
            if not iface:
                iface = config.get("iface") or detectar_interfaz_predeterminada()
            if not iface:
                self.error = ("No se pudo determinar automáticamente la interfaz de red. "
                              "Configúrala manualmente en 'Red Real', o usá el modo 'psutil'.")
                logger.warning(self.error)
                return False, self.error
        # El modo "psutil" no necesita interfaz: mira todas las conexiones del equipo.

        self.activa = True
        self.error = None
        self._detener_solicitado.clear()
        self.iface_actual = iface
        self.backend_actual = backend_real
        self.reputacion.reiniciar()  # la confiabilidad de destino es POR SESIÓN de monitoreo
        with self.lock:
            self.resultados = []
        self.progreso = {"transcurrido": 0, "flujos_procesados": 0,
                          "flujos_omitidos": 0, "ultimo_error_flujo": None,
                          "ciclos_completados": 0}

        objetivo = self._ejecutar_continuo if backend_real == "scapy" else self._ejecutar_continuo_psutil
        args = (iface, ventana) if backend_real == "scapy" else (ventana,)
        self.hilo = threading.Thread(target=objetivo, args=args, daemon=True)
        self.hilo.start()
        # Se guarda lo que pidió el usuario ("auto" incluido), no lo resuelto, para
        # que "auto" se vuelva a evaluar en cada arranque.
        guardar_config({"iface": iface, "backend": solicitado})
        logger.info("Monitoreo continuo iniciado (backend=%s%s, iface=%s, ventana=%ss)",
                    backend_real, " [modo de respaldo, sin Npcap]" if backend_real == "psutil" else "",
                    iface, ventana)
        return True, "Monitoreo iniciado."

    def detener(self):
        if not self.activa:
            return False, "El monitoreo no está activo."
        self._detener_solicitado.set()
        logger.info("Detención de monitoreo solicitada, se aplicará en el próximo ciclo (~unos segundos).")
        return True, "Deteniendo monitoreo..."

    # ── Procesamiento de un flujo (común a Scapy y psutil) ──────────────────

    # Metadatos de captura (para la UI), NO son features del modelo: se separan antes de
    # llamar a analizar_trafico() para que no intente convertir strings a float32.
    CLAVES_METADATO = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "src_mac"}

    def _procesar_flujo(self, proc, fila: dict, backend: str) -> None:
        from app.motor.identificacion_dispositivos import identificar_dispositivo
        from app.motor.base_datos import guardar_captura_real

        metadato = {k: fila[k] for k in self.CLAVES_METADATO if k in fila}
        muestra = {k: v for k, v in fila.items() if k not in self.CLAVES_METADATO}
        try:
            resultado = proc.analizar_trafico(muestra)
            if "error" in resultado:
                logger.warning("Flujo real omitido (%s): %s", metadato, resultado["error"])
                self.progreso["flujos_omitidos"] += 1
                self.progreso["ultimo_error_flujo"] = resultado["error"]
                return

            dispositivo = identificar_dispositivo(metadato.get("src_mac"))
            ip_destino = metadato.get("dst_ip")
            # Reputación según el historial PREVIO; después se registra este flujo.
            reputacion = self.reputacion.evaluar(ip_destino)
            self.reputacion.registrar(ip_destino, resultado.get("clase") != "NORMAL")

            resultado["_fuente"] = "red_real"      # el dashboard distingue 'red_real' de 'simulacion'
            resultado["_backend"] = backend        # 'scapy' o 'psutil' (modo de respaldo)
            resultado["_flujo"] = metadato
            resultado["_dispositivo"] = dispositivo
            resultado["_reputacion"] = reputacion

            # Etapa 1 del aprendizaje activo (Sección 4.2): guardar el flujo con la
            # predicción del modelo, sin etiqueta de verdad todavía. El id permite que el
            # Centro de Alertas muestre los botones de confirmar/corregir.
            try:
                self._guardados += 1
                if self._guardados % 500 == 0:
                    from app.motor.base_datos import purgar_capturas_no_etiquetadas
                    purgar_capturas_no_etiquetadas(int(os.environ.get("NEMESIS_MAX_CAPTURAS", "50000")))
                resultado["_captura_id"] = guardar_captura_real(
                    muestra, resultado.get("clase"), resultado.get("confianza"),
                    flujo=metadato, dispositivo=dispositivo, origen=backend)
            except Exception as e:
                logger.warning("No se pudo guardar la captura real: %s", e)

            with self.lock:
                self.resultados.append(resultado)
                # Cap de memoria: conserva solo los últimos 500 resultados
                if len(self.resultados) > 500:
                    self.resultados = self.resultados[-500:]
                self.progreso["flujos_procesados"] += 1
        except Exception as e:
            logger.error("Error analizando flujo real (%s): %s", metadato, e)
            self.progreso["flujos_omitidos"] += 1
            self.progreso["ultimo_error_flujo"] = str(e)

    def _preparar_procesador(self):
        """Devuelve el procesador con modelos cargados, o None (y deja el error en self.error)."""
        from app.motor.procesador_nemesis import obtener_procesador
        proc = obtener_procesador()
        if not proc._cargado:
            self.error = "Los modelos no están cargados. Ejecuta el entrenamiento primero."
            self.activa = False
            logger.error(self.error)
            return None
        return proc

    def _ejecutar_continuo(self, iface, ventana):
        """Monitoreo con Scapy (captura real de paquetes)."""
        try:
            from scapy.all import sniff
            from app.motor.captura_paquetes import AgregadorFlujos
        except ImportError as e:
            self.error = f"Falta una dependencia: {e}. Instala con: pip install scapy"
            self.activa = False
            logger.error(self.error)
            return

        proc = self._preparar_procesador()
        if proc is None:
            return

        inicio_global = time.time()
        # El filtro BPF "ip" es solo una optimización (AgregadorFlujos ya descarta por software
        # todo paquete sin capa IP). Compilarlo exige libpcap: si no está disponible se captura
        # sin filtro en vez de detener el monitoreo.
        filtro_bpf = "ip"
        try:
            while not self._detener_solicitado.is_set():
                agregador = AgregadorFlujos(ventana_segundos=ventana)

                def callback(pkt, _ag=agregador):
                    _ag.procesar_paquete(pkt)

                # Cada ciclo captura durante 'ventana' segundos y luego procesa esas filas;
                # el stop_filter permite cortar casi al instante si se pide detener.
                try:
                    sniff(iface=iface, prn=callback, store=False, timeout=ventana,
                          filter=filtro_bpf, stop_filter=lambda p: self._detener_solicitado.is_set())
                except Exception as error_sniff:
                    if filtro_bpf and "filter" in str(error_sniff).lower():
                        logger.warning("No se pudo compilar el filtro BPF (%s). Se captura sin filtro y "
                                       "los paquetes no-IP se descartan por software.", error_sniff)
                        filtro_bpf = None
                        continue  # reintenta este ciclo sin filtro
                    raise

                for fila in agregador.construir_filas():
                    self._procesar_flujo(proc, fila, "scapy")
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
        """Monitoreo de RESPALDO sin Npcap (ver captura_psutil.py para sus límites)."""
        try:
            from app.motor.captura_psutil import AgregadorFlujosPsutil
        except ImportError as e:
            self.error = f"Falta una dependencia: {e}. Instala con: pip install psutil"
            self.activa = False
            logger.error(self.error)
            return

        proc = self._preparar_procesador()
        if proc is None:
            return

        inicio_global = time.time()
        try:
            agregador = AgregadorFlujosPsutil(ventana_segundos=ventana)
            while not self._detener_solicitado.is_set():
                agregador.iniciar_ventana()
                # Espera en pasos cortos para poder cortar casi al instante al detener.
                limite = time.time() + ventana
                while time.time() < limite and not self._detener_solicitado.is_set():
                    time.sleep(min(0.5, max(limite - time.time(), 0)))

                for fila in agregador.construir_filas():
                    self._procesar_flujo(proc, fila, "psutil")
                self.progreso["ciclos_completados"] += 1
                self.progreso["transcurrido"] = round(time.time() - inicio_global, 1)

        except PermissionError:
            self.error = ("Permiso denegado leyendo conexiones de red. En Windows corré el backend "
                          "como Administrador; en Linux/Mac con sudo. (Esto NO requiere Npcap.)")
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
            "backend": self.backend_actual,
            "modo_respaldo_sin_npcap": self.backend_actual == "psutil",
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