// Núcleo del cliente del asistente (panel y Mi equipo): lector SSE, pintado seguro del texto
// del modelo y la tarjeta de aprobación.
//
// El modelo leyó texto de inventarios y agentes (no confiable): todo se pinta con nodos y
// textContent, nunca con innerHTML. Enlaces solo a rutas relativas que no salen del sitio.
"use strict";

window.AsistenteNucleo = (function () {
  const RUTA_SEGURA = /^\/(?!\/)[\w\-./?=&#%]*$/;

  function el(etiqueta, atributos, ...hijos) {
    const nodo = document.createElement(etiqueta);
    for (const [clave, valor] of Object.entries(atributos || {})) {
      if (valor == null || valor === false) continue;
      if (clave === "clase") nodo.className = valor;
      else if (clave === "texto") nodo.textContent = valor;
      else if (clave.startsWith("on")) nodo.addEventListener(clave.slice(2), valor);
      else nodo.setAttribute(clave, valor === true ? "" : valor);
    }
    // flat(Infinity): un map que devuelve [a, b] no debe pintar "[object HTMLElement]".
    for (const hijo of hijos.flat(Infinity)) {
      if (hijo == null || hijo === false) continue;
      nodo.append(hijo instanceof Node ? hijo : document.createTextNode(String(hijo)));
    }
    return nodo;
  }

  const rutaSegura = (ruta) => typeof ruta === "string" && RUTA_SEGURA.test(ruta);

  // **negrita** y [texto](/ruta). Lo demás, texto plano.
  function enLinea(texto) {
    const partes = [];
    const patron = /\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^)\s]+)\)/g;
    let ultimo = 0;
    let m;
    while ((m = patron.exec(texto))) {
      if (m.index > ultimo) partes.push(texto.slice(ultimo, m.index));
      if (m[1] != null) partes.push(el("strong", { texto: m[1] }));
      else if (rutaSegura(m[3])) partes.push(el("a", { href: m[3], texto: m[2] }));
      else partes.push(m[2]);
      ultimo = patron.lastIndex;
    }
    if (ultimo < texto.length) partes.push(texto.slice(ultimo));
    return partes;
  }

  // Párrafos y listas con "- ". Sin tablas ni títulos: el prompt no los pide.
  function pintarTexto(texto) {
    const raiz = el("div", { clase: "asis-texto" });
    for (const bloque of String(texto || "").split(/\n{2,}/)) {
      const lineas = bloque.split("\n").filter((l) => l.trim());
      if (!lineas.length) continue;
      if (lineas.every((l) => /^\s*[-*] /.test(l))) {
        raiz.append(el("ul", {}, lineas.map((l) => el("li", {}, enLinea(l.replace(/^\s*[-*] /, ""))))));
      } else {
        raiz.append(el("p", {}, lineas.map((l, i) => [i ? el("br") : null, enLinea(l)])));
      }
    }
    return raiz;
  }

  // Lee un text/event-stream y llama a `alEvento` con cada objeto. Devuelve true si llegó
  // a un evento de cierre (fin, aprobacion o error).
  async function leerSSE(respuesta, alEvento) {
    const lector = respuesta.body.getReader();
    const decodificador = new TextDecoder();
    let resto = "";
    let cerrado = false;
    for (;;) {
      const { value, done } = await lector.read();
      if (done) break;
      resto += decodificador.decode(value, { stream: true });
      let corte;
      while ((corte = resto.indexOf("\n\n")) >= 0) {
        const bloque = resto.slice(0, corte);
        resto = resto.slice(corte + 2);
        const linea = bloque.split("\n").find((l) => l.startsWith("data: "));
        if (!linea) continue;
        let evento;
        try { evento = JSON.parse(linea.slice(6)); } catch { continue; }
        if (["fin", "aprobacion", "error"].includes(evento.tipo)) cerrado = true;
        alEvento(evento);
      }
    }
    return cerrado;
  }

  // Tarjeta de aprobación. La arma el servidor desde la base; aquí solo se pinta.
  function tarjeta(vista, { origen, alDecidir, soloLectura }) {
    const v = vista || {};
    const botones = el("div", { clase: "asis-tarjeta-botones" });
    const sello = el("p", { clase: "asis-sello", hidden: true });
    const nodo = el(
      "section",
      { clase: "asis-tarjeta", "aria-label": `Propuesta: ${origen || v.titulo || ""}` },
      el("div", { clase: "asis-tarjeta-rotulo" }, el("span", { clase: "asis-punto", "aria-hidden": "true" }), v.rotulo || "Propuesta"),
      el("h3", { texto: v.titulo || origen || "" }),
      v.contexto ? el("p", { clase: "asis-tarjeta-contexto", texto: v.contexto }) : null,
      el(
        "dl",
        { clase: "asis-cambios" },
        (v.cambios || []).map((c) => [
          el("dt", { texto: c.campo }),
          el(
            "dd",
            {},
            el("del", { texto: c.antes == null ? "vacío" : c.antes }),
            el("span", { clase: "asis-flecha", "aria-hidden": "true", texto: " → " }),
            el("ins", { texto: c.despues == null ? "vacío" : c.despues }),
          ),
        ]),
      ),
      (v.avisos || []).length
        ? el("ul", { clase: "asis-avisos" }, v.avisos.map((a) => el("li", { texto: a })))
        : null,
      v.nota ? el("p", { clase: "asis-tarjeta-nota", texto: v.nota }) : null,
      botones,
      sello,
    );
    const sellar = (texto) => {
      botones.remove();
      sello.hidden = false;
      sello.textContent = texto;
    };
    if (soloLectura) {
      sellar("Propuesta pendiente de su dueño (solo lectura).");
    } else {
      const aprobar = el("button", { type: "button", clase: "asis-aprobar", texto: v.boton || "Aprobar" });
      const descartar = el("button", { type: "button", clase: "boton-texto", texto: "Descartar" });
      const decidir = (aprobado) => {
        aprobar.disabled = descartar.disabled = true;
        alDecidir(aprobado, sellar);
      };
      aprobar.addEventListener("click", () => decidir(true));
      descartar.addEventListener("click", () => decidir(false));
      botones.append(aprobar, descartar);
    }
    nodo.sellar = sellar;
    return nodo;
  }

  // Un turno del hilo: pregunta, pasos, respuesta y, si hay, la tarjeta.
  function turno(pregunta) {
    const pasos = el("ul", { clase: "asis-pasos", "aria-label": "Pasos" });
    const respuesta = el("div", { clase: "asis-respuesta" });
    const nodo = el(
      "article",
      { clase: "asis-turno" },
      el("p", { clase: "asis-pregunta", texto: pregunta }),
      pasos,
      respuesta,
    );
    return {
      nodo,
      paso(texto) {
        if ([...pasos.children].some((li) => li.textContent === texto)) return;
        pasos.append(el("li", { texto }));
      },
      texto(t) { respuesta.append(pintarTexto(t)); },
      error(t) { respuesta.append(el("p", { clase: "asis-error", role: "alert", texto: t })); },
      anexar(n) { nodo.append(n); },
      cargando(si) { nodo.classList.toggle("asis-pensando", !!si); },
    };
  }

  function hora(iso) {
    if (!iso) return "";
    return new Date(iso).toLocaleString("es-CO", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  }

  return { el, rutaSegura, pintarTexto, leerSSE, tarjeta, turno, hora };
})();
