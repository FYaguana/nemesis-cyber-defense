# Ajustes entre la tesis final (15-10) y el sistema

Resultado de comparar la tesis, afirmación por afirmación, con el código. Cada fila indica si el
**sistema se corrigió** para coincidir con la tesis o si es la **tesis** la que debe ajustarse
(porque aplicar la frase literal habría empeorado el sistema o porque la frase no es exacta).

## A. Lo que se corrigió en el sistema para que coincida con la tesis

| Sección | La tesis dice | Antes en el código | Ahora |
|---|---|---|---|
| 4.1 | variable `ratio_bytes` | se llamaba `ratio_src_dst` (y estaba copiada en 3 módulos) | una sola función `agregar_variables_derivadas`, con el nombre de la tesis |
| 4.1 | μ y σ **exclusivamente** del entrenamiento | el escalador se ajustaba con entrenamiento **+ validación** | se divide 85/15 primero y se ajusta solo con el 85 % |
| 4.1 | imputación de nulos | `fillna(inplace=True)`: con pandas ≥ 3 (el de Render) no hace nada | asignación explícita (probado con nulos reales) |
| 4.5 | variables de red + ceros para las de host | la **inferencia** armaba el vector según el orden de las claves: con tráfico real **11 de 45 variables quedaban desalineadas** | `vectorizar_muestras`: orden fijo, ceros para las faltantes; mismo código en entrenamiento, inferencia y captura (prueba de paridad) |
| Tabla 5 | L2 (λ=10⁻⁴) en la capa de salida | solo las ocultas la tenían | las 4 capas densas llevan L2 |
| Tabla 6 | tiempos de respuesta por nivel "definidos en procesador_nemesis.py" | no existían como constantes | `TIEMPO_RESPUESTA_OBJETIVO`, se devuelve con cada análisis y se muestra en la alerta |
| Tabla 6 / 3.5 | CRÍTICO → "recomendación IA" | solo en la pantalla de simulación | botón **Plan IA** en toda alerta crítica |
| 4.8 | el prompt incluye "las alertas recientes" | el servidor nunca las recibía (el dashboard no las enviaba) | el servidor las lee de la base de datos (el cliente ya no puede inyectar contexto) |
| 3.9 | restricción "sin marcado", **verificada** antes de mostrar | solo se pedía en el prompt | además se limpia el Markdown del plan antes de mostrarlo |
| 4.2 | etapa 4: recarga en caliente **sin interrumpir el servicio** | el reentrenamiento sobrescribía `models/` mientras entrenaba | entrena en un directorio de preparación y publica al final; si falla, nada cambia |
| 4.2 | confirmación del analista → etiqueta verdadera | con la lista **filtrada**, "Confirmar" etiquetaba otra alerta | el índice se toma de la lista completa (con prueba) |
| 4.9 | CI con `py_compile`, `flake8` y `node --check` | el workflow había quedado solo con pytest | los tres pasos están, más pytest en el mismo trabajo (siguen siendo 4 trabajos) |
| (varias) | "ejecuta `entrenar_nemesis.py`" | el script **no existía** | `python -m app.motor.entrenar_nemesis` |
| 4.8 | API de Gemini por HTTP | la clave iba en la URL y los errores de `requests` la mostraban al usuario y al log | la clave va en el encabezado `x-goog-api-key` (nota 1) |

Nota 1: encabezado `x-goog-api-key`, que es el que exige la documentación oficial de la API de Gemini.

Además: el limitador de tasa fallaba con un límite de 0; `/api/ia/config/estado` era público; se eliminó
código heredado del pipeline (dataset de 5,000 muestras con la misma fuga) que nadie usaba.

## B. Lo que debe cambiar en la **tesis**

### B1. Sección 4.3 — fórmula del RNN
- **Dice:** `Entrada_i = eventos[i] … eventos[i+9] → Predicción = tipo del evento[i+10]`
- **Debe decir:** `Entrada_i = eventos[i] … eventos[i+9] → Predicción = tipo del evento[i+9] (el más reciente de la ventana)`
- **Por qué:** en producción el RNN clasifica el evento *actual* (que es el último de la ventana). Entrenarlo para
  predecir el evento *siguiente* sobre registros mezclados al azar es imposible de aprender: el modelo que entregaba
  el proyecto había colapsado a "siempre NORMAL" (Recall 0.20 = azar con 5 clases). Aplicar la frase literal
  reproduce ese fallo.

### B2. Tabla 7 y texto asociado (5.2, 5.4, Conclusión 4)
La Tabla 7 actual dice haberse obtenido "ejecutando experimentos.py" con **46** variables, y el sistema usa 45, así que
no se puede reproducir. Reemplázala por la regenerada (`docs/TABLA7_resultados.md`, semilla 42, 45 variables):

| Modelo | Recall | Precisión | F1 | Accuracy |
|---|---|---|---|---|
| MLP Nemesis | 99.99 % | 99.94 % | 99.96 % | 99.98 % |
| RNN/LSTM Nemesis (3,991 ventanas) | 100.00 % | 100.00 % | 100.00 % | 100.00 % |
| Random Forest | 100.00 % | 100.00 % | 100.00 % | 100.00 % |
| Gradient Boosting | 99.94 % | 99.99 % | 99.96 % | 99.98 % |
| SVM | 99.88 % | 99.99 % | 99.93 % | 99.98 % |
| KNN | 98.27 % | 99.64 % | 98.94 % | 99.35 % |

(Recall por clase en el archivo; KNN: R2L 93.44 %, U2R 98.12 %; SVM: U2R 99.38 %; GB: R2L 99.69 %.)
Elimina la nota de las "46 variables". Frases que cambian:
- "MLP supera al KNN en 1.67 pp" → **1.72 pp**.
- "Random Forest y Gradient Boosting obtienen métricas perfectas" → "Random Forest obtiene métricas perfectas y Gradient Boosting casi perfectas (99.94 %)".
- "KNN … R2L (92.50 % de recall)" → **93.44 %**.
- 5.4 y Conclusión 4: el RNN **ya no tiene "precisión ligeramente menor"**. Redacción sugerida: "Ambos modelos alcanzan un desempeño
  cercano al 100 %; la diferencia entre ellos no es concluyente, dado que el dataset sintético no modela relaciones
  temporales (Sección 5.5), por lo que el contexto de los eventos previos no aporta información adicional."
  Conclusión 4: "Recall de 99.99 % (MLP) y 100.00 % (RNN/LSTM)".

### B3. NIST SP 800-61 (3.5, 3.9, 4.8, Tabla 6)
- Las **cuatro fases** (preparación; detección y análisis; contención/erradicación/recuperación; actividad posterior)
  pertenecen a la **Rev. 2** (Cichonski et al., 2012). La **Rev. 3** (Nelson et al., 2025), que NIST publicó en abril de 2025,
  la reemplaza y organiza la respuesta según las funciones de CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover).
  Fuente: aviso de NIST (csrc.nist.gov/Projects/incident-response).
- Redacción sugerida (3.9 y 4.8): "…en las cuatro fases del ciclo de vida de respuesta a incidentes de NIST SP 800-61 Rev. 2
  (Cichonski et al., 2012), vigente como referencia práctica y reemplazada en 2025 por la Rev. 3, que la alinea con CSF 2.0."
  Agrega la Rev. 2 a las Referencias. El código del sistema cita la Rev. 2, que es la correcta para esas fases.
- Tabla 6 / 3.5: **no pude verificar** que NIST *sugiera* los tiempos < 5 min / < 30 min / < 2 h. Si no figuran en el
  documento, preséntalos como "objetivos de diseño del sistema, inspirados en la priorización de NIST".

### B4. Tabla 5
Agrega la L2 a las capas ocultas: `BatchNorm + Dropout(0.3) + L2(10⁻⁴)`; la salida queda `L2(10⁻⁴)`. (El código ya las tiene en las 4 capas.)

### B5. Secciones 3.10 y 4.9 y Recomendación 5 (CI)
El CI hoy ejecuta, además de `py_compile`, `flake8` y `node --check`, una **suite pytest de 121 pruebas** (autenticación,
roles en todas las rutas, motor de alertas, aprendizaje activo, pipeline, seguridad de IA, regresiones de despliegue).
- Agrega a 4.9: "…y la suite de pruebas automatizadas (pytest) sobre los módulos críticos: autenticación, control de roles,
  motor de alertas, aprendizaje activo y pipeline de datos."
- **Recomendación 5** ("incorporar una suite de pruebas… que actualmente se limita a verificaciones de sintaxis") deja de
  ser cierta: reescríbela como "ampliar la suite con pruebas de extremo a extremo con navegador y pruebas de carga".
  (Si prefieres no mencionar pytest, quita el paso `pytest` del workflow; el resto sigue válido.)

### B6. Sección 4.5 — modo sin Npcap
Agrega: "En equipos Windows sin el controlador Npcap, el sistema cae automáticamente a un **modo de respaldo** que lee las
conexiones activas del sistema operativo (psutil). Al no observar paquetes, sus bytes y banderas son aproximaciones, por lo
que cada resultado se etiqueta como modo de respaldo y esas capturas **no se usan para reentrenar**. La captura principal
y la evaluada en el Capítulo 5 es la de Scapy."

### B7. Secciones 3.2 y 4.9 — Nginx
Agrega: "El servidor Nginx del frontend actúa además como **proxy inverso**: reenvía `/api/*` al backend, de modo que el
navegador ve un único origen (sin CORS y con cookie `SameSite=Lax`)."

### B8. Tabla 2 — versiones
- "Python 3.10" → **Python 3.11** (imagen Docker y CI).
- Las versiones de TensorFlow (2.21.0) y scikit-learn (1.8.0) quedan **fijadas** en `requirements.txt` porque los
  `.pkl`/`.keras` entregados dependen de ellas.

### B9. Sección 5.3 — tráfico real
- La explicación de los falsos positivos (variables de host en cero y ráfagas) sigue siendo válida, pero había **otra causa**:
  el desalineamiento de 11 variables (sección A). Repite las sesiones de monitoreo con el sistema corregido antes de dar
  el "≈ 95 % NORMAL".
- Una prueba rápida mía (22 s, 52 flujos, 4 destinos, tráfico HTTPS a PyPI, **muestra demasiado pequeña para citarla**):
  88.5 % clasificado NORMAL y 0 alertas. En la versión anterior esas mismas conexiones generaban alertas "Probe CRÍTICO".
- Usa el panel **Validación con tráfico real** (gráfica por minuto + CSV) para reemplazar la Ilustración 14, que hoy es
  "ilustrativa", y para registrar lo que la sección admite no haber medido: total de conexiones, duración y dispositivos.

### B10. Otros
- 4.6: la contraseña/MFA son reales; las cuentas demo existen solo si `NEMESIS_CUENTAS_DEMO=true` (desactivadas por defecto).
- 4.8: la clave de la API se envía en el encabezado `x-goog-api-key`.
- 4.2 (etapa 4): la publicación de los modelos reentrenados es atómica (ver sección A).

## C. Cómo verificar todo
```bash
cd backend
pip install -r requirements-dev.txt
python -m compileall -q app                                   # py_compile
python -m flake8 app tests --select=E9,F63,F7,F82            # flake8 (como en el CI)
python -m pytest tests -v                                     # 121 pruebas
python -m app.motor.experimentos                              # reproduce la Tabla 7
python -m app.motor.entrenar_nemesis                          # reentrena MLP + RNN (--con-reales usa las capturas confirmadas)
```
