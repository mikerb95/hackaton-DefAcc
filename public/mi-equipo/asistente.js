// Caja de preguntas en Mi equipo: la persona pregunta sobre SU equipo y el asistente responde
// con la herramienta mi_equipo. Solo consulta: aquí nunca hay propuestas ni tarjetas.
// Cada pregunta es nueva (sin historial). Usa public/asistente-nucleo.js.
"use strict";

window.cajaAsistenteEquipo = function (enlace) {
  const { el, leerSSE, turno } = window.AsistenteNucleo;
  const ATAJOS = ["¿Qué tengo que hacer hoy?", "¿Tengo que reiniciar?", "¿Mi equipo está en riesgo?"];

  const hilo = el("div", { clase: "asis-hilo", "aria-live": "polite" });
  const entrada = el("input", {
    type: "text", maxlength: "500", id: "asis-equipo-pregunta",
    placeholder: "Escribe tu pregunta", "aria-label": "Tu pregunta sobre este equipo",
  });
  const enviar = el("button", { type: "submit", texto: "Preguntar" });
  const form = el("form", { clase: "asis-form", autocomplete: "off" }, entrada, enviar);
  const atajos = el("div", { clase: "asis-atajos" });
  let ocupado = false;

  async function preguntar(texto) {
    texto = String(texto || "").trim();
    if (!texto || ocupado) return;
    ocupado = entrada.disabled = enviar.disabled = true;
    atajos.hidden = true;
    entrada.value = "";
    const t = turno(texto);
    hilo.append(t.nodo);
    t.cargando(true);
    try {
      const r = await fetch("/api/mi-equipo/asistente", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Enlace-Equipo": enlace },
        body: JSON.stringify({ pregunta: texto }),
        cache: "no-store",
      });
      if (!r.ok) {
        const cuerpo = await r.json().catch(() => ({}));
        t.error(r.status === 503 || r.status === 429
          ? "El asistente no está disponible ahora. Lo de arriba sigue siendo lo que tienes que hacer."
          : (typeof cuerpo.detail === "string" ? cuerpo.detail : "No se pudo preguntar."));
      } else {
        await leerSSE(r, (ev) => {
          if (ev.tipo === "paso") t.paso(ev.texto || "Revisando tu equipo");
          else if (ev.tipo === "texto") t.texto(ev.texto);
          else if (ev.tipo === "fin" && ev.estado === "fallida") t.error("No pude responder esta vez. Inténtalo de nuevo en un rato.");
          else if (ev.tipo === "error") t.error(ev.mensaje || "No pude responder.");
        });
      }
    } catch {
      t.error("Sin conexión con el radar.");
    }
    t.cargando(false);
    ocupado = entrada.disabled = enviar.disabled = false;
    entrada.focus();
  }

  ATAJOS.forEach((a) => atajos.append(el("button", { type: "button", clase: "asis-atajo", texto: a, onclick: () => preguntar(a) })));
  form.addEventListener("submit", (e) => { e.preventDefault(); preguntar(entrada.value); });

  return el(
    "section",
    { clase: "tarjeta asis-equipo", "aria-labelledby": "asis-equipo-titulo" },
    el("h2", { id: "asis-equipo-titulo", texto: "¿Dudas? Pregúntale al radar" }),
    el("p", { clase: "suave", texto: "Responde solo sobre este equipo, con los mismos datos de arriba. No cambia nada en tu computador." }),
    atajos,
    hilo,
    form,
  );
};
