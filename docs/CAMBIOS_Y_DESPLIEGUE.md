> **Versión final de la tesis (15-10):** los ajustes entre la tesis y el sistema están en [`AJUSTES_TESIS_FINAL.md`](AJUSTES_TESIS_FINAL.md).

# Cambios, despliegue y ajustes de tesis

## 1. Qué se corrigió y por qué

| Tema | Antes | Ahora |
|---|---|---|
| **Cuentas demo** | `admin@nemesis.ec` + código fijo `123456` (Administrador), y el servidor devolvía el código | Apagadas por defecto (`NEMESIS_CUENTAS_DEMO=true` para habilitarlas). Sesiones demo antiguas dejan de valer |
| **Primer administrador** | Solo la cuenta demo | `NEMESIS_ADMIN_EMAIL`: se crea la invitación y el enlace sale **en los logs** del backend (24 h) |
| **Secretos en git** | `config_email.json` (clave Gmail), `sesiones.json`, `nemesis.db` versionados | `.gitignore` + dejaron de rastrearse |
| **Pruebas / CI** | No había pruebas; el CI solo hacía lint | 121 pruebas pytest; el CI las ejecuta y bloquea el despliegue si fallan |
| **RNN** | Entrenado para predecir el evento *siguiente*; en producción clasifica el *actual* → colapsaba (Recall 0.20) | Etiqueta = último evento de la ventana (coherente con la inferencia) |
| **Modelos entregados** | Evaluados con un split antiguo (n=1000 / 990) | Reentrenados con el benchmark fijo (15,000 / 4,000) → `docs/TABLA7_resultados.md` |
| **`experimentos.py`** | No estaba en el proyecto | `python -m app.motor.experimentos` reproduce la Tabla 7 |
| **Fabricante por OUI** | No existía | Tabla local (10,266 prefijos del IEEE) → `identificacion_dispositivos.py` |
| **Confiabilidad de destino** | El dashboard la mostraba, el backend no la generaba | Implementada (`<3` obs. = sin historial; `0 %` = confiable; `≥40 %` = poco confiable) |
| **Aprendizaje activo, etapa 1** | Los flujos no se guardaban → sin botones de etiquetado | Cada flujo se guarda con su predicción (`_captura_id`) |
| **Captura** | psutil por defecto | Scapy principal; psutil solo como **respaldo etiquetado** (sin Npcap) y excluido del reentrenamiento |
| **Scapy sin libpcap** | Se detenía con "Cannot compile filter" | Reintenta sin filtro BPF |
| **Demo de simulación** | Perfiles del dataset antiguo; el modelo nuevo no reconocía el "DoS" | Usa el generador que produjo los CSV (5/5 clases bien) |
| **Autoinicio del monitoreo** | Arrancaba también en Render (analizaba el propio contenedor) | Desactivado en la nube (`RENDER`) o con `NEMESIS_MONITOREO_AUTOINICIO=false` |
| **Validación con tráfico real** | Sin registro de totales/duración | Panel con gráfica por minuto, resumen y CSV (`/api/alertas/capturas/validacion[/csv]`) |
| **Despliegue** | Proxy, SNI, `config.js`, `.dockerignore`, minúsculas GHCR | Todo incorporado (con pruebas de regresión) |

## 2. Variables de entorno

**Backend (Render → servicio del backend → Environment)**

| Variable | Valor |
|---|---|
| `URL_FRONTEND_PUBLICA` | `https://nemesis-cyber-defense-1.onrender.com` |
| `NEMESIS_ADMIN_EMAIL` | tu correo (será el Administrador inicial) |
| `NEMESIS_ADMIN_NOMBRE` | tu nombre (opcional) |
| `GEMINI_API_KEY` | clave **nueva** de Gemini |
| `NEMESIS_CUENTAS_DEMO` | **no definir** (solo `true` en una demo controlada) |
| `COOKIE_SECURE` | no definir en producción (default `true`); `false` solo en local por HTTP |
| `NEMESIS_MONITOREO_AUTOINICIO` | opcional (`true`/`false`); en Render queda apagado solo |
| `NEMESIS_MAX_CAPTURAS` | opcional, tope de capturas sin etiquetar (default 50000) |
| `NEMESIS_GEMINI_MODELO` | opcional; nombre del modelo de Gemini si Google retira el predeterminado (`gemini-2.5-flash`) |

**Frontend (servicio del frontend)**: `NEMESIS_API_URL=https://nemesis-cyber-defense.onrender.com` (sin barra final).

**Primer ingreso:** tras desplegar, abre los *Logs* del backend, busca `ADMINISTRADOR INICIAL pendiente de activar` y usa ese enlace (define contraseña y escanea el QR TOTP).

## 3. Pasos para subir los cambios

```bash
# 0) ANTES: revoca la contraseña de aplicación de Gmail que estuvo en el repo público
#    (Cuenta de Google > Seguridad > Contraseñas de aplicaciones) y rota la clave de Gemini.
cd NemesisV3
git status                      # los 4 archivos sensibles ya figuran como "deleted" (solo del índice)
git add -A
git commit -m "Seguridad, pruebas, OUI, confiabilidad, aprendizaje activo, RNN corregido, CI con pytest"
git push
```
El historial anterior de git **sigue conteniendo** `config_email.json`. Rotar la clave es lo que cierra el riesgo; si además quieres borrar el rastro, usa `git filter-repo` o recrea el repositorio.

## 4. Ajustes que debe llevar la tesis (para que coincida con el sistema)

- **Resumen / 1.x / Tabla 7 / Conclusión 1:** llamar al conjunto "dataset sintético con la estructura y proporciones del NSL-KDD", no "NSL-KDD". Los resultados cercanos al 100 % validan el *pipeline*, no el desempeño en tráfico real.
- **4.3:** la ventana se etiqueta con la clase del **último** evento (no del siguiente).
- **4.5:** agregar el modo de respaldo `psutil` (sin Npcap; bytes y banderas aproximados; excluido del reentrenamiento).
- **3.2 / 4.9:** el frontend (Nginx) además actúa de **proxy inverso** hacia `/api`; así el navegador ve un solo origen (sin CORS, cookie `SameSite=Lax`).
- **4.6:** las cuentas demo existen solo para desarrollo/demostración y están deshabilitadas en producción.
- **4.9:** el CI ejecuta la suite pytest (121 pruebas) y el CD depende de que pase.
- **5.2 y 5.4:** actualizar la Tabla 7 con `docs/TABLA7_resultados.md`. Con estos datos el RNN iguala al MLP (no tiene "precisión ligeramente menor"); MLP supera a KNN por 1.72 pp. Reforzar 5.5: el contexto temporal no aporta información porque los registros no tienen orden temporal.
- **5.3:** usar el panel *Validación con tráfico real* (gráfica + CSV) para mostrar picos, total de conexiones, duración y dispositivos. Los falsos positivos en tráfico real son esperables (observé conexiones HTTPS normales clasificadas como Probe).
- **Objetivos / conclusiones (SC4, SC17):** una conclusión por cada objetivo específico.

## 5. Guion de demo (SC3 / SC13)

1. Mostrar la arquitectura (diagrama): frontend Nginx → proxy `/api` → backend FastAPI → modelos MLP/RNN, y los dos servicios en Render.
2. *Opcional:* para una demo sin correo, habilitar temporalmente `NEMESIS_CUENTAS_DEMO=true`; **desactivarla al terminar**.
3. Login con 2 factores (contraseña + TOTP).
4. Dashboard → "Simular tráfico" (Normal / DoS / Probe / R2L / U2R) → mostrar el semáforo y el plan de respuesta con IA.
5. Red real (en la PC/servidor propio, no en Render): iniciar monitoreo, ver dispositivo y confiabilidad de destino.
6. Centro de Alertas: confirmar un falso positivo → *Reentrenar* (Administrador) → métricas nuevas.
7. Panel de validación: gráfica de picos y descarga del CSV.
8. GitHub → Actions: pytest + build + deploy automáticos tras un cambio.

## 6. Limitaciones conocidas

- Benchmark sintético casi perfectamente separable (ver sección 4). Para resultados comparables con la literatura, evaluar con el NSL-KDD oficial.
- En Render el monitoreo de red real no tiene sentido (solo vería la red interna del contenedor): usarlo en un equipo propio.
- La captura con Scapy en Windows requiere Npcap; sin él el sistema usa el modo de respaldo.
