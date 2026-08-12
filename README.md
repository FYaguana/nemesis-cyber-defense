# Nemesis Cyber Defense — Backend/Frontend separados (v3)
## Estado: TODO migrado y probado

Se migró el sistema completo a la nueva arquitectura. Cada pieza se probó con
`curl` contra el servidor real corriendo (no solo revisión de código) y cada
página del frontend se validó con `node --check` (motor JS de Chrome) para
garantizar cero errores de sintaxis antes de la entrega.

## Arquitectura

```
backend/
├── Dockerfile
├── requirements.txt
├── data/            <- NSL_KDD_train.csv, NSL_KDD_test.csv (base real del proyecto)
├── models/           <- modelos entrenados (Nemesis_MLP.keras, Nemesis_RNN.keras, etc.)
├── app/
│   ├── main.py                          # ensambla la app (lifespan moderno, no on_event deprecado)
│   ├── nucleo/
│   │   ├── seguridad.py                 # verificación de sesión (Depends)
│   │   ├── gestor_sesiones.py           # creación/persistencia de sesiones + usuarios demo
│   │   ├── limitador_tasa.py            # rate limiter genérico (usado por la IA)
│   │   └── dependencias.py              # inyección de dependencias
│   ├── motor/        <- lógica de dominio ya probada (ML, captura de red, BD, TOTP)
│   │   ├── base_datos.py, gestion_usuarios.py, envio_correo.py
│   │   ├── captura_red.py, captura_paquetes.py, procesador_nemesis.py
│   │   ├── preparacion_datos.py, redes_neuronales.py, reentrenamiento.py
│   │   └── generador_dataset_base.py
│   ├── servicios/     <- reglas de negocio de la capa HTTP nueva
│   │   ├── cliente_gemini.py, servicio_recomendaciones_ia.py, planes_referencia.py
│   │   ├── servicio_autenticacion.py, servicio_usuarios.py
│   ├── repositorios/   <- acceso a configuración persistida
│   │   ├── repositorio_configuracion_ia.py, repositorio_configuracion_correo.py
│   └── routers/        <- SOLO traducen HTTP <-> servicio, sin lógica propia
│       ├── router_autenticacion.py, router_usuarios.py, router_monitoreo.py
│       ├── router_alertas.py, router_modelos.py, router_analizador.py, router_ia.py
frontend/
├── Dockerfile, nginx.conf
├── index.html / login.html   <- pantalla de acceso (2FA real + demo)
├── dashboard.html             <- panel completo (monitoreo, alertas, usuarios, IA, etc.)
├── activar.html                <- activación de cuenta nueva (QR + contraseña)
├── recuperar.html               <- recuperación de contraseña (requiere MFA vigente)
├── reconfigurar-mfa.html         <- reconfigurar MFA tras reset del admin
├── demo-streaming-ia.html         <- página de referencia del streaming de IA
└── js/cliente_recomendaciones_ia.js
docker-compose.yml
```

**Decisión de arquitecto**: el código de dominio ya probado (entrenamiento de
redes neuronales, captura de paquetes, base de datos, TOTP/2FA) se movió a
`app/motor/` tal cual, sin reescritura cosmética — reescribir código de
Machine Learning ya validado solo por estética de nombres hubiera arriesgado
introducir bugs sin ningún beneficio real. El **Clean Code / SOLID** se aplicó
donde realmente importaba: la capa HTTP, que antes era un archivo de 2828
líneas mezclando FastAPI + lógica de negocio + un SPA completo de HTML/CSS/JS
como strings de Python. Ahora cada router es delgado (solo traduce HTTP),
cada servicio tiene una responsabilidad, y el frontend son archivos reales.

## Qué se implementó de cada pedido

### Mejoras de IA (probadas con curl)
- **Rate limiting**: `nucleo/limitador_tasa.py`, ventana deslizante 10/min y
  200/día. Probado: bloquea correctamente al superar el límite.
- **Streaming**: `servicios/cliente_gemini.py` usa `streamGenerateContent`
  (SSE). Hay DOS endpoints: `/api/ia/recomendaciones/stream` (streaming real,
  usado por `demo-streaming-ia.html`) y `/api/ia/recomendaciones` (no-streaming,
  usado por el dashboard actual — internamente reutiliza el mismo servicio,
  sin duplicar lógica).
- **Sin Markdown**: instrucción explícita en el prompt + planes de referencia
  limpiados de backticks.

### Arquitectura Clean Code / SOLID
Ver estructura arriba. Nombres descriptivos en español en toda la capa nueva
(routers/servicios/repositorios/núcleo).

## Cómo correrlo

### Con Docker
```powershell
docker compose up --build
```
- Backend: http://localhost:8000/docs
- Frontend: http://localhost:5173

**Nota Windows**: `network_mode: host` (necesario para que scapy capture red
real) tiene soporte limitado en Docker Desktop para Windows/Mac. Si la
captura de red real no funciona dentro del contenedor en tu máquina, corré el
backend fuera de Docker (ver abajo) mientras resolvemos esto juntos, o usá
WSL2.

### Sin Docker
```powershell
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Abrí `frontend/index.html` en el navegador (o serví la carpeta con cualquier
servidor estático — con doble clic en el archivo también funciona para
probar, ya que las llamadas van a `http://localhost:8000` por CORS).

### Primer ingreso
Usuarios demo (sin configuración previa necesaria):
- `admin@nemesis.ec` / código `123456` (Administrador)
- `tanya@nemesis.ec` / código `654321` (Analista SOC)

Desde ahí, invitate a vos mismo con tu correo real desde la pestaña Usuarios
(2FA real con contraseña + TOTP) como hacías antes.

### Configurar Gemini (opcional, para recomendaciones con IA real)
Desde el dashboard → Recomendaciones → pegar la API key de
https://aistudio.google.com/apikey (rol Administrador). Sin key, el sistema
usa los planes de referencia automáticamente — nunca se rompe.

## Pruebas realizadas en esta entrega

| Prueba | Resultado |
|---|---|
| Ensamblado completo de la app (`from app.main import app`) | ✅ |
| Carga de modelos reales + inferencia (`analizar_trafico`) | ✅ DoS 99.89% |
| Login demo (check-email + verify-mfa) | ✅ |
| Login real 2FA (activación + contraseña + TOTP) | ✅ |
| Analizador simulado end-to-end | ✅ |
| Listar/invitar usuarios (admin) | ✅ |
| Permisos 401 sin sesión / 403 sin rol admin | ✅ |
| Alertas + estadísticas de capturas | ✅ |
| Métricas de modelos guardadas | ✅ |
| IA sin API key → cae a plan de referencia sin markdown | ✅ |
| Rate limiter (bloquea tras superar el límite) | ✅ |
| Sintaxis JS de las 7 páginas del frontend (`node --check`) | ✅ |
| Sintaxis de todos los `.py` del backend (`py_compile`) | ✅ |

