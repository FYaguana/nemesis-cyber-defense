"""
planes_referencia.py -- Planes de respuesta a incidentes predefinidos,
basados en NIST SP 800-61r2. Se usan como respaldo cuando la IA no está
disponible (sin API key, límite de uso alcanzado, error de red), para que
el usuario nunca se quede sin un plan accionable.
"""

PLANES_DE_RESPUESTA_POR_CLASE = {
    "DoS": {
        "pasos": [
            {"titulo": "Activar Rate Limiting inmediato",
             "detalle": "Limitar a 100 req/seg por IP en el firewall. iptables: -A INPUT -p tcp --dport 80 -m limit --limit 100/min -j ACCEPT"},
            {"titulo": "Identificar y bloquear IPs de origen",
             "detalle": "Revisar logs de acceso, bloquear las IPs con mayor tráfico en el WAF por 24-48 horas."},
            {"titulo": "Activar CDN / Scrubbing Center",
             "detalle": "Redirigir tráfico por Cloudflare o AWS Shield para filtrar el ataque antes de llegar al servidor."},
            {"titulo": "Notificar al ISP y equipo SOC",
             "detalle": "Contactar al proveedor de internet para filtros upstream. Escalar según el protocolo de gestión de incidentes."},
            {"titulo": "Documentar el incidente",
             "detalle": "Registrar timestamps, IPs involucradas y volumen para el análisis post-incidente y reporte de cumplimiento."},
        ],
        "tiempo_respuesta": "< 5 minutos", "prioridad": "CRÍTICA",
        "color_prioridad": "#ff4444",
        "referencia_nist": "NIST SP 800-61r2 §3.3 - Containment",
    },
    "Probe": {
        "pasos": [
            {"titulo": "Bloquear IP sospechosa en el firewall",
             "detalle": "Agregar la IP a la lista de bloqueo perimetral. Monitorear cambios de IP (posible uso de proxies/Tor)."},
            {"titulo": "Revisar logs del IDS/IPS",
             "detalle": "Verificar en Suricata o Snort los patrones detectados. Identificar qué puertos y servicios fueron sondeados."},
            {"titulo": "Auditar servicios expuestos",
             "detalle": "Ejecutar nmap -sV [tu-ip] desde red externa. Cerrar o filtrar puertos no necesarios."},
            {"titulo": "Actualizar reglas de firewall",
             "detalle": "Aplicar principio de mínimo privilegio: solo puertos estrictamente necesarios. Bloquear rangos de VPN/proxy conocidos."},
            {"titulo": "Incrementar nivel de monitoreo 24h",
             "detalle": "El reconocimiento es el preludio de un ataque más sofisticado. Aumentar verbosidad de logs por 24 horas."},
        ],
        "tiempo_respuesta": "< 30 minutos", "prioridad": "ALTA",
        "color_prioridad": "#ffaa00",
        "referencia_nist": "NIST SP 800-61r2 §3.2 - Detection & Analysis",
    },
    "R2L": {
        "pasos": [
            {"titulo": "Bloquear acceso desde la IP atacante",
             "detalle": "Deshabilitar SSH/FTP/Telnet desde la IP origen. Revisar si hay sesión activa no autorizada en ese momento."},
            {"titulo": "Forzar cambio de credenciales",
             "detalle": "Identificar cuentas que recibieron intentos de login. Forzar reset y revocar tokens de sesión activos."},
            {"titulo": "Habilitar autenticación por clave pública SSH",
             "detalle": "Deshabilitar auth por contraseña (PasswordAuthentication no en sshd_config). Usar únicamente llaves RSA/ED25519."},
            {"titulo": "Revisar cuentas con acceso privilegiado",
             "detalle": "Auditar /etc/passwd y /etc/sudoers. Verificar que no existan cuentas no autorizadas con privilegios elevados."},
            {"titulo": "Implementar fail2ban",
             "detalle": "Bloquear IPs con más de 3 intentos fallidos en 10 minutos. Reduce drásticamente el riesgo de fuerza bruta."},
        ],
        "tiempo_respuesta": "< 15 minutos", "prioridad": "CRÍTICA",
        "color_prioridad": "#ff4444",
        "referencia_nist": "NIST SP 800-61r2 §3.3 - Eradication",
    },
    "U2R": {
        "pasos": [
            {"titulo": "Aislar el sistema afectado ahora",
             "detalle": "Desconectar el equipo de la red corporativa. Con acceso root, el atacante puede instalar backdoors permanentes."},
            {"titulo": "Revocar todos los privilegios elevados",
             "detalle": "Ejecutar sudo -K. Revisar cron jobs, binarios SUID y capabilities (getcap -r /)."},
            {"titulo": "Análisis forense del sistema",
             "detalle": "Imagen forense del disco antes de intervenir. Analizar procesos en memoria con Volatility. Revisar /var/log/auth.log."},
            {"titulo": "Identificar el vector de escalada",
             "detalle": "Revisar vulnerabilidades del kernel (uname -r + searchsploit). Verificar si se explotó SUID, cron o software vulnerable."},
            {"titulo": "Reconstruir desde imagen limpia",
             "detalle": "Sistema comprometido = no confiable. Restaurar desde backup verificado. Aplicar todos los parches antes de reconectar."},
        ],
        "tiempo_respuesta": "INMEDIATO", "prioridad": "MÁXIMA",
        "color_prioridad": "#ff0000",
        "referencia_nist": "NIST SP 800-61r2 §3.4 - Recovery",
    },
    "NORMAL": {
        "pasos": [
            {"titulo": "Tráfico verificado como legítimo",
             "detalle": "El modelo clasificó este evento como normal. No se requiere acción inmediata."},
            {"titulo": "Mantener monitoreo continuo",
             "detalle": "Un baseline normal sostenido permite detectar futuras anomalías con mayor precisión."},
        ],
        "tiempo_respuesta": "Sin urgencia", "prioridad": "BAJA",
        "color_prioridad": "#00ff88",
        "referencia_nist": "NIST SP 800-137 - Monitoreo Continuo",
    },
}


def generar_plan_de_referencia(clase: str, severidad: str, confianza: float, features_influyentes: list) -> dict:
    """Arma un plan de referencia para la clase dada, agregando al inicio
    un resumen de las features que influyeron en la detección (si las hay)."""
    plan = dict(PLANES_DE_RESPUESTA_POR_CLASE.get(clase, PLANES_DE_RESPUESTA_POR_CLASE["NORMAL"]))
    plan["pasos"] = list(plan["pasos"])

    if features_influyentes and clase != "NORMAL":
        resumen_features = " | ".join(
            f"{f['feature']}: {f['valor']} (normal: {f['normal']})" for f in features_influyentes[:3]
        )
        plan["pasos"].insert(0, {
            "titulo": "Indicadores detectados por el modelo",
            "detalle": resumen_features,
        })

    return plan
