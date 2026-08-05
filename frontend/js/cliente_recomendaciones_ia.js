/**
 * cliente_recomendaciones_ia.js -- Consume el endpoint de streaming del
 * backend y muestra el texto a medida que la IA lo va generando (efecto
 * de "escritura en vivo"), renderizando el plan final ya estructurado.
 *
 * Usa fetch + ReadableStream en vez de EventSource nativo porque el
 * endpoint requiere POST con body (EventSource solo soporta GET).
 */

const URL_BASE_API = window.NEMESIS_API_URL || "http://localhost:8000";

/**
 * @param {{clase:string, severidad:string, confianza:number, features:Array, alertas_recientes:Array}} deteccion
 * @param {(textoParcial: string) => void} alRecibirFragmento
 * @param {(plan: object) => void} alCompletarPlan
 * @param {(error: string) => void} alFallar
 */
async function solicitarPlanDeRespuestaEnStreaming(deteccion, alRecibirFragmento, alCompletarPlan, alFallar) {
  let respuesta;
  try {
    respuesta = await fetch(`${URL_BASE_API}/api/ia/recomendaciones/stream`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(deteccion),
    });
  } catch (error) {
    alFallar(`Error de conexión: ${error.message}`);
    return;
  }

  if (!respuesta.ok) {
    alFallar(`El servidor respondió ${respuesta.status}`);
    return;
  }

  const lector = respuesta.body.getReader();
  const decodificador = new TextDecoder();
  let bufferSinProcesar = "";

  while (true) {
    const { value, done } = await lector.read();
    if (done) break;

    bufferSinProcesar += decodificador.decode(value, { stream: true });
    const eventosCompletos = bufferSinProcesar.split("\n\n");
    bufferSinProcesar = eventosCompletos.pop(); // el último puede estar incompleto

    for (const bloqueEvento of eventosCompletos) {
      procesarBloqueDeEventoSSE(bloqueEvento, alRecibirFragmento, alCompletarPlan);
    }
  }
}

function procesarBloqueDeEventoSSE(bloqueEvento, alRecibirFragmento, alCompletarPlan) {
  const lineas = bloqueEvento.split("\n");
  const lineaEvento = lineas.find((l) => l.startsWith("event: "));
  const lineaDatos = lineas.find((l) => l.startsWith("data: "));
  if (!lineaEvento || !lineaDatos) return;

  const nombreEvento = lineaEvento.replace("event: ", "").trim();
  const datos = JSON.parse(lineaDatos.replace("data: ", ""));

  if (nombreEvento === "fragmento") {
    alRecibirFragmento(datos.texto_parcial);
  } else if (nombreEvento === "plan_completo") {
    alCompletarPlan(datos);
  }
}

export { solicitarPlanDeRespuestaEnStreaming };
