"""
src/database_manager.py – Gestión de Base de Datos
Sistema Nemesis Cyber Defense
Adaptado de la arquitectura SQL Server + MongoDB de la tesis
(usa SQLite para el prototipo local, sin necesidad de servidor externo)
"""

import sqlite3
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),  # backend/
    "data", "nemesis.db",
)


def init_db():
    """Inicializa las tablas de la base de datos del prototipo."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Tabla de predicciones
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS predicciones (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        modelo      TEXT    NOT NULL,
        clase       TEXT    NOT NULL,
        severidad   TEXT    NOT NULL,
        confianza   REAL    NOT NULL,
        detalles    TEXT,
        feedback    TEXT    DEFAULT NULL
    )""")

    # Tabla de alertas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alertas (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       TEXT NOT NULL,
        nivel           TEXT NOT NULL,
        tipo_ataque     TEXT NOT NULL,
        confianza       REAL NOT NULL,
        descripcion     TEXT,
        atendida        INTEGER DEFAULT 0,
        es_falso_positivo INTEGER DEFAULT 0
    )""")

    # Tabla de métricas de modelos
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS metricas_modelo (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        modelo      TEXT NOT NULL,
        recall      REAL,
        precision   REAL,
        f1_score    REAL,
        datos_json  TEXT
    )""")

    # Tabla de eventos de tráfico (log)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS eventos_trafico (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        features_json TEXT,
        resultado   TEXT,
        severidad   TEXT
    )""")

    # Tabla de usuarios reales (reemplaza el diccionario fijo USUARIOS_DEMO).
    # 'activo=0' + 'token_invitacion' NOT NULL = usuario invitado, pendiente
    # de activar su cuenta, definir su contraseña y configurar su MFA (TOTP).
    # Autenticación real de DOS FACTORES: password_hash (algo que sabés) +
    # totp_secret (algo que tenés, la app autenticadora).
    # 'token_invitacion' se reutiliza como token genérico de "acción pendiente"
    # (invitación, recuperar contraseña, o resetear MFA), diferenciado por
    # 'token_tipo', para no tener 3 columnas de token distintas.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        email             TEXT NOT NULL UNIQUE,
        nombre            TEXT NOT NULL,
        rol               TEXT NOT NULL DEFAULT 'Analista SOC',
        password_hash     TEXT,
        totp_secret       TEXT,
        activo            INTEGER DEFAULT 0,
        token_invitacion  TEXT,
        token_tipo        TEXT,
        token_expira      TEXT,
        intentos_fallidos INTEGER DEFAULT 0,
        creado_en         TEXT NOT NULL,
        activado_en       TEXT
    )""")

    # Migración segura: si la tabla 'usuarios' ya existía de una versión
    # anterior (sin estas columnas), se las agrega sin perder datos.
    cursor.execute("PRAGMA table_info(usuarios)")
    columnas_existentes = {fila[1] for fila in cursor.fetchall()}
    if "password_hash" not in columnas_existentes:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN password_hash TEXT")
        logger.info("Migración aplicada: columna 'password_hash' agregada a 'usuarios'.")
    if "token_tipo" not in columnas_existentes:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN token_tipo TEXT")
        logger.info("Migración aplicada: columna 'token_tipo' agregada a 'usuarios'.")
    if "intentos_fallidos" not in columnas_existentes:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN intentos_fallidos INTEGER DEFAULT 0")
        logger.info("Migración aplicada: columna 'intentos_fallidos' agregada a 'usuarios'.")

    # Tabla de capturas reales: CADA flujo real analizado por el Monitoreo de
    # Red se guarda acá (features crudas + predicción del modelo), etiquetado
    # o no. 'etiqueta_humana' es NULL hasta que un analista lo confirma o
    # corrige desde el dashboard (botones "Confirmar" / "Falso positivo").
    # Solo las filas CON etiqueta_humana se usan para reentrenar — nunca se
    # usa la propia predicción del modelo como si fuera la verdad (eso sería
    # un ciclo de refuerzo de sus propios errores, no aprendizaje válido).
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS capturas_reales (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp             TEXT NOT NULL,
        features_json         TEXT NOT NULL,
        prediccion_clase      TEXT,
        prediccion_confianza  REAL,
        etiqueta_humana       TEXT,
        etiquetado_en         TEXT,
        etiquetado_por        TEXT
    )""")

    conn.commit()
    conn.close()
    logger.info(f"Base de datos inicializada: {DB_PATH}")


# ─── Gestión de usuarios reales (TOTP + roles) ───────────────────────────────

def crear_usuario_invitado(email: str, nombre: str, rol: str, token: str, expira_iso: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO usuarios (email, nombre, rol, activo, token_invitacion, token_tipo, token_expira, creado_en)
        VALUES (?, ?, ?, 0, ?, 'invitacion', ?, ?)
    """, (email.lower().strip(), nombre, rol, token, expira_iso, datetime.now().isoformat()))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def obtener_usuario_por_email(email: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, email, nombre, rol, totp_secret, activo, token_invitacion, token_expira,
               password_hash, intentos_fallidos
        FROM usuarios WHERE email = ?
    """, (email.lower().strip(),))
    r = cursor.fetchone()
    conn.close()
    if not r:
        return None
    return {"id": r[0], "email": r[1], "nombre": r[2], "rol": r[3],
            "totp_secret": r[4], "activo": bool(r[5]),
            "token_invitacion": r[6], "token_expira": r[7], "password_hash": r[8],
            "intentos_fallidos": r[9] or 0}


def obtener_usuario_por_token(token: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, email, nombre, rol, activo, token_expira, token_tipo
        FROM usuarios WHERE token_invitacion = ?
    """, (token,))
    r = cursor.fetchone()
    conn.close()
    if not r:
        return None
    return {"id": r[0], "email": r[1], "nombre": r[2], "rol": r[3],
            "activo": bool(r[4]), "token_expira": r[5], "token_tipo": r[6]}


def crear_token_accion(usuario_id: int, tipo: str, token: str, expira_iso: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios SET token_invitacion=?, token_tipo=?, token_expira=? WHERE id=?
    """, (token, tipo, expira_iso, usuario_id))
    conn.commit()
    conn.close()


def limpiar_token(usuario_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios SET token_invitacion=NULL, token_tipo=NULL, token_expira=NULL WHERE id=?
    """, (usuario_id,))
    conn.commit()
    conn.close()


def incrementar_intentos_fallidos(email: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET intentos_fallidos = intentos_fallidos + 1 WHERE email = ?",
                   (email.lower().strip(),))
    conn.commit()
    cursor.execute("SELECT intentos_fallidos FROM usuarios WHERE email = ?", (email.lower().strip(),))
    r = cursor.fetchone()
    conn.close()
    return r[0] if r else 0


def resetear_intentos_fallidos(email: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET intentos_fallidos = 0 WHERE email = ?", (email.lower().strip(),))
    conn.commit()
    conn.close()


def actualizar_password_usuario(usuario_id: int, password_hash: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios SET password_hash=?, token_invitacion=NULL, token_tipo=NULL,
               token_expira=NULL, intentos_fallidos=0
        WHERE id=?
    """, (password_hash, usuario_id))
    conn.commit()
    conn.close()


def limpiar_totp_secret(usuario_id: int):
    """Invalida el MFA actual de inmediato (ej. teléfono perdido), hasta que
    el usuario complete el flujo de reconfiguración con un nuevo QR."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET totp_secret=NULL WHERE id=?", (usuario_id,))
    conn.commit()
    conn.close()


def guardar_nuevo_totp(usuario_id: int, totp_secret: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios SET totp_secret=?, token_invitacion=NULL, token_tipo=NULL, token_expira=NULL
        WHERE id=?
    """, (totp_secret, usuario_id))
    conn.commit()
    conn.close()


def activar_usuario(usuario_id: int, totp_secret: str, password_hash: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios SET totp_secret=?, password_hash=?, activo=1, token_invitacion=NULL,
               token_tipo=NULL, token_expira=NULL, activado_en=?
        WHERE id=?
    """, (totp_secret, password_hash, datetime.now().isoformat(), usuario_id))
    conn.commit()
    conn.close()


def listar_usuarios() -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, email, nombre, rol, activo, creado_en, activado_en
        FROM usuarios ORDER BY id ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "email": r[1], "nombre": r[2], "rol": r[3],
             "activo": bool(r[4]), "creado_en": r[5], "activado_en": r[6]} for r in rows]


def actualizar_rol_usuario(usuario_id: int, rol: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET rol=? WHERE id=?", (rol, usuario_id))
    conn.commit()
    conn.close()


def actualizar_estado_usuario(usuario_id: int, activo: bool):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET activo=? WHERE id=?", (1 if activo else 0, usuario_id))
    conn.commit()
    conn.close()


def eliminar_usuario(usuario_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id=?", (usuario_id,))
    conn.commit()
    conn.close()


def guardar_prediccion(modelo: str, clase: str, severidad: str,
                        confianza: float, detalles: dict = None) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO predicciones (timestamp, modelo, clase, severidad, confianza, detalles)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), modelo, clase, severidad, confianza,
          json.dumps(detalles or {})))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def guardar_alerta(nivel: str, tipo_ataque: str, confianza: float,
                    descripcion: str = "") -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alertas (timestamp, nivel, tipo_ataque, confianza, descripcion)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), nivel, tipo_ataque, confianza, descripcion))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def guardar_metricas(modelo: str, recall: float, precision: float,
                      f1: float, datos: dict = None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO metricas_modelo (timestamp, modelo, recall, precision, f1_score, datos_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), modelo, recall, precision, f1,
          json.dumps(datos or {})))
    conn.commit()
    conn.close()


def obtener_alertas_recientes(limite=50) -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, nivel, tipo_ataque, confianza, descripcion, atendida, es_falso_positivo
        FROM alertas ORDER BY id DESC LIMIT ?
    """, (limite,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "timestamp": r[1], "nivel": r[2],
             "tipo_ataque": r[3], "confianza": r[4], "descripcion": r[5],
             "atendida": bool(r[6]), "es_falso_positivo": bool(r[7])} for r in rows]


def obtener_estadisticas() -> dict:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alertas")
    total_alertas = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alertas WHERE atendida=0")
    pendientes = cursor.fetchone()[0]

    cursor.execute("SELECT nivel, COUNT(*) FROM alertas GROUP BY nivel")
    por_nivel = dict(cursor.fetchall())

    cursor.execute("SELECT tipo_ataque, COUNT(*) FROM alertas GROUP BY tipo_ataque ORDER BY 2 DESC LIMIT 5")
    top_ataques = dict(cursor.fetchall())

    cursor.execute("SELECT COUNT(*) FROM predicciones")
    total_preds = cursor.fetchone()[0]

    cursor.execute("""
        SELECT recall, precision, f1_score FROM metricas_modelo
        ORDER BY id DESC LIMIT 1
    """)
    row = cursor.fetchone()
    ultimas_metricas = {"recall": row[0], "precision": row[1], "f1": row[2]} if row else {}

    conn.close()
    return {
        "total_alertas": total_alertas,
        "alertas_pendientes": pendientes,
        "por_nivel": por_nivel,
        "top_ataques": top_ataques,
        "total_predicciones": total_preds,
        "ultimas_metricas": ultimas_metricas
    }


def marcar_feedback(alerta_id: int, es_falso_positivo: bool):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE alertas SET atendida=1, es_falso_positivo=?
        WHERE id=?
    """, (1 if es_falso_positivo else 0, alerta_id))
    conn.commit()
    conn.close()


# ─── Capturas reales para etiquetado humano y reentrenamiento ───────────────

def guardar_captura_real(features: dict, prediccion_clase: str, prediccion_confianza: float) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO capturas_reales (timestamp, features_json, prediccion_clase, prediccion_confianza)
        VALUES (?, ?, ?, ?)
    """, (datetime.now().isoformat(), json.dumps(features), prediccion_clase, prediccion_confianza))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def etiquetar_captura(captura_id: int, etiqueta: str, usuario_email: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE capturas_reales SET etiqueta_humana=?, etiquetado_en=?, etiquetado_por=?
        WHERE id=?
    """, (etiqueta, datetime.now().isoformat(), usuario_email, captura_id))
    conn.commit()
    conn.close()


def obtener_capturas_etiquetadas() -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT features_json, etiqueta_humana FROM capturas_reales
        WHERE etiqueta_humana IS NOT NULL
    """)
    rows = cursor.fetchall()
    conn.close()
    resultado = []
    for features_json, etiqueta in rows:
        try:
            features = json.loads(features_json)
            features["label"] = etiqueta
            resultado.append(features)
        except Exception:
            continue
    return resultado


def contar_capturas() -> dict:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM capturas_reales")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM capturas_reales WHERE etiqueta_humana IS NOT NULL")
    etiquetadas = cursor.fetchone()[0]
    cursor.execute("""
        SELECT etiqueta_humana, COUNT(*) FROM capturas_reales
        WHERE etiqueta_humana IS NOT NULL GROUP BY etiqueta_humana
    """)
    por_clase = {clase: n for clase, n in cursor.fetchall()}
    conn.close()
    return {"total": total, "etiquetadas": etiquetadas, "por_clase": por_clase}


if __name__ == "__main__":
    init_db()
    print("✅ Base de datos Nemesis inicializada correctamente")
    print(f"   Ubicación: {os.path.abspath(DB_PATH)}")