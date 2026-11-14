// Caja del asistente en la pantalla principal del panel (docs/plan-asistente.md).
//
// - Mientras se escribe, el buscador SIN IA muestra secciones, productos, CVE y equipos.
// - Enter o "Preguntar" manda la pregunta al asistente (SSE). Los pasos se ven mientras
//   consulta; si propone un cambio, aparece la tarjeta y una persona decide.
// - Escribir con la tarjeta abierta es "pedir cambios": el asistente vuelve a proponer.
// - Recientes: las propias; el admin puede ver las de todos (en solo lectura).
// - Retomar por URL: ?c=<id>.
// admin.js llama a iniciarAsistente() cuando ya hay sesión.
"use strict";

(function () {
  const { el, leerSSE, tarjeta, turno, hora } = window.AsistenteNucleo;
  const caja = () => document.getElementById("asistente");

  let conversacionId = null;
  let ocupado = false;
  let tarjetaAbierta = null;
  let estado = null;
  let verTodas = false;

  // ---- utilidades ------------------------------------------------------------

  const $a = (id) => document.getElementById(id);

  function nota(texto, clase = "") {
    const n = $a("asistente-nota");
    n.className = `nota asis-nota ${clase}`.trim();
    n.textContent = texto || "";
    n.hidden = !texto;
  }

  function fijarUrl(id) {
    const url = new URL(location.href);
    if (id) url.searchParams.set("c", id);
    else url.searchParams.delete("c");
    history.replaceState(null, "", url);
  }

  function modoChat(si) {
    caja().classList.toggle("is-chat", !!si);
    $a("asistente-atajos").hidden = !!si || !estado?.disponible;
  }

  function bloquear(si) {
    ocupado = si;
    $a("asistente-pregunta").disabled = si;
    $a("asistente-enviar").disabled = si;
    $a("asistente-nueva").hidden = !conversacionId;
  }

  async function errorDe(respuesta) {
    const cuerpo = await respuesta.json().catch(() => ({}));
    return typeof cuerpo.detail === "string" ? cuerpo.detail : `Error ${respuesta.status}`;
  }

  // ---- transmisión ------------------------------------------------------------

  async function transmitir(ruta, cuerpo, t) {
    bloquear(true);
    t.cargando(true);
    let respuesta;
    try {
      respuesta = await fetch(ruta, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cuerpo),
      });
    } catch {
      t.error("No hubo conexión con el radar.");
      t.cargando(false);
      bloquear(false);
      return;
    }
    if (!respuesta.ok) {
      t.error(await errorDe(respuesta));
      t.cargando(false);
      bloquear(false);
      if (respuesta.status === 429 || respuesta.status === 503) cargarEstado();
      return;
    }
    let cerrado = false;
    try {
      cerrado = await leerSSE(respuesta, (ev) => alEvento(ev, t));
    } catch {
      cerrado = false;
    }
    if (!cerrado) {
      // La conversación sigue en el servidor aunque se haya cortado la conexión.
      const ver = el("button", { type: "button", clase: "boton-texto", texto: "Ver resultado" });
      ver.addEventListener("click", () => abrir(conversacionId));
      t.anexar(el("p", { clase: "asis-error" }, "Se cortó la conexión. ", ver));
    }
    t.cargando(false);
    bloquear(false);
    $a("asistente-pregunta").focus();
    cargarRecientes();
  }

  function alEvento(ev, t) {
    switch (ev.tipo) {
      case "conversacion":
        conversacionId = ev.id;
        fijarUrl(ev.id);
        break;
      case "paso":
        t.paso(ev.texto || "Consultando el radar");
        break;
      case "texto":
        t.texto(ev.texto);
        break;
      case "aprobacion":
        tarjetaAbierta = tarjeta(ev.vista, { origen: ev.origen, alDecidir: decidir });
        t.anexar(tarjetaAbierta);
        break;
      case "decision":
        break;
      case "fin":
        if (ev.estado === "fallida" && ev.error) t.error(ev.error);
        break;
      case "error":
        t.error(ev.mensaje || "El asistente tuvo un error.");
        if (ev.nueva) { conversacionId = null; fijarUrl(null); }
        break;
    }
  }

  async function preguntar(texto) {
    if (ocupado || !texto.trim()) return;
    cerrarBusqueda();
    modoChat(true);
    if (tarjetaAbierta) {
      tarjetaAbierta.sellar("Pediste cambios.");
      tarjetaAbierta = null;
    }
    const t = turno(texto);
    $a("asistente-hilo").append(t.nodo);
    $a("asistente-pregunta").value = "";
    await transmitir("/api/asistente", { pregunta: texto, id: conversacionId }, t);
  }

  function decidir(aprobado, sellar) {
    const t = turno(aprobado ? "Aprobar la propuesta" : "Descartar la propuesta");
    t.nodo.classList.add("asis-turno-decision");
    $a("asistente-hilo").append(t.nodo);
    const quien = (window.SESION_ACTUAL && window.SESION_ACTUAL.nombre) || "ti";
    const ahora = new Date().toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit" });
    sellar(aprobado ? `Aprobado por ${quien}, ${ahora}` : "Descartado");
    tarjetaAbierta = null;
    transmitir("/api/asistente/decision", { id: conversacionId, aprobado: aprobado === true }, t);
  }

  // ---- conversación guardada --------------------------------------------------

  async function abrir(id) {
    if (!id || ocupado) return;
    let d;
    try {
      const r = await fetch(`/api/asistente/conversacion/${encodeURIComponent(id)}`, { credentials: "same-origin" });
      if (!r.ok) throw new Error(await errorDe(r));
      d = await r.json();
    } catch (error) {
      nota(error.message, "error");
      fijarUrl(null);
      return;
    }
    const hilo = $a("asistente-hilo");
    hilo.replaceChildren();
    tarjetaAbierta = null;
    conversacionId = d.solo_lectura ? null : d.id;
    fijarUrl(d.id);
    modoChat(true);
    if (d.solo_lectura) {
      hilo.append(el("p", { clase: "asis-aviso-lectura", texto: `Conversación de ${d.dueno}, solo lectura.` }));
    }
    for (const x of d.turnos) {
      const t = turno(x.pregunta);
      x.pasos.forEach((p) => t.paso(p));
      if (x.respuesta) t.texto(x.respuesta);
      hilo.append(t.nodo);
    }
    if (d.propuesta) {
      const ultimo = hilo.lastElementChild;
      tarjetaAbierta = tarjeta(d.propuesta.vista, {
        origen: d.propuesta.origen, alDecidir: decidir, soloLectura: d.solo_lectura,
      });
      (ultimo || hilo).append(tarjetaAbierta);
      if (d.solo_lectura) tarjetaAbierta = null;
    }
    if (d.estado === "fallida") {
      hilo.append(el("p", { clase: "asis-error", texto: `${d.error || "La conversación se cortó."} Empieza otra para seguir.` }));
      conversacionId = null;
    }
    bloquear(false);
    $a("asistente-pregunta").focus();
  }

  function nueva() {
    if (ocupado) return;
    conversacionId = null;
    tarjetaAbierta = null;
    $a("asistente-hilo").replaceChildren();
    fijarUrl(null);
    modoChat(false);
    bloquear(false);
    $a("asistente-pregunta").focus();
  }

  async function cargarRecientes() {
    const lista = $a("asistente-recientes-lista");
    try {
      const r = await fetch(`/api/asistente/recientes${verTodas ? "?todas=1" : ""}`, { credentials: "same-origin" });
      if (!r.ok) throw new Error(await errorDe(r));
      const d = await r.json();
      lista.replaceChildren(
        ...(d.conversaciones.length
          ? d.conversaciones.map((c) => el(
            "li", {},
            el(
              "button",
              { type: "button", clase: "asis-reciente", onclick: () => abrir(c.id) },
              c.estado === "esperando_aprobacion" ? el("span", { clase: "asis-marca", texto: "por aprobar" }) : null,
              el("span", { clase: "asis-reciente-pregunta", texto: c.pregunta }),
              el("span", { clase: "asis-reciente-meta", texto: `${verTodas ? `${c.usuario_nombre} · ` : ""}${hora(c.actualizada)}` }),
            ),
          ))
          : [el("li", { clase: "vacio", texto: "Todavía no hay conversaciones." })]),
      );
    } catch {
      lista.replaceChildren(el("li", { clase: "vacio", texto: "No se pudieron leer las recientes." }));
    }
  }

  // ---- buscador sin IA --------------------------------------------------------

  let temporizador = null;

  function cerrarBusqueda() {
    const b = $a("asistente-busqueda");
    b.hidden = true;
    b.replaceChildren();
  }

  async function buscar(texto) {
    const b = $a("asistente-busqueda");
    if (texto.trim().length < 2) { cerrarBusqueda(); return; }
    try {
      const r = await fetch(`/api/asistente/buscar?q=${encodeURIComponent(texto.trim())}`, { credentials: "same-origin" });
      if (!r.ok) return;
      const d = await r.json();
      if ($a("asistente-pregunta").value !== texto) return;
      if (!d.resultados.length) { cerrarBusqueda(); return; }
      b.replaceChildren(...d.resultados.map((x) => el(
        "li", {},
        el(
          "a",
          { href: window.AsistenteNucleo.rutaSegura(x.enlace) ? x.enlace : "#", onclick: cerrarBusqueda },
          el("span", { clase: "asis-busqueda-tipo", texto: x.tipo }),
          el("span", { texto: x.titulo }),
          x.detalle ? el("span", { clase: "asis-busqueda-detalle", texto: x.detalle }) : null,
        ),
      )));
      b.hidden = false;
    } catch {
      cerrarBusqueda();
    }
  }

  // ---- estado y arranque ------------------------------------------------------

  async function cargarEstado() {
    try {
      const r = await fetch("/api/asistente/estado", { credentials: "same-origin" });
      estado = await r.json();
    } catch {
      estado = { disponible: false, motivo: "sin_red", atajos: [] };
    }
    const mensajes = {
      sin_clave: "Por ahora la caja solo busca: el asistente no tiene clave de API.",
      sin_presupuesto: "Se alcanzó el tope de gasto de hoy. Mañana vuelve a estar disponible; mientras, la caja busca.",
      sin_gasto: "No se pudo comprobar el gasto de hoy; por seguridad la caja solo busca.",
      sin_red: "No hubo conexión con el radar.",
    };
    nota(estado.disponible ? "" : mensajes[estado.motivo] || "", "asis-nota-aviso");
    $a("asistente-enviar").hidden = !estado.disponible;
    $a("asistente-pregunta").placeholder = estado.disponible ? "Pregunta o busca algo" : "Busca una sección, un producto, una CVE o un equipo";
    const atajos = $a("asistente-atajos");
    atajos.replaceChildren(...(estado.atajos || []).map((a) => el(
      "button", { type: "button", clase: "asis-atajo", texto: a, onclick: () => preguntar(a) },
    )));
    atajos.hidden = !estado.disponible || caja().classList.contains("is-chat");
    $a("asistente-saludo").textContent = `Hola, ${(estado.nombre || "").split(" ")[0] || "equipo"}.`;
    $a("asistente-sub").textContent = estado.puede_proponer
      ? "Pregunta por hallazgos, productos, equipos o cobertura. Si hay que cambiar algo, te muestro el cambio y tú decides."
      : "Pregunta por hallazgos, productos, equipos o cobertura. Con tu rol solo consulto.";
  }

  function iniciar() {
    if (!caja()) return;
    const form = $a("asistente-form");
    const entrada = $a("asistente-pregunta");
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (estado?.disponible) preguntar(entrada.value);
      else buscar(entrada.value);
    });
    entrada.addEventListener("input", () => {
      clearTimeout(temporizador);
      temporizador = setTimeout(() => buscar(entrada.value), 220);
    });
    entrada.addEventListener("keydown", (e) => { if (e.key === "Escape") cerrarBusqueda(); });
    document.addEventListener("click", (e) => { if (!form.contains(e.target)) cerrarBusqueda(); });
    $a("asistente-nueva").addEventListener("click", nueva);
    const todas = $a("asistente-todas");
    if (todas) {
      todas.addEventListener("change", () => { verTodas = todas.checked; cargarRecientes(); });
    }
    cargarEstado().then(() => {
      const id = new URL(location.href).searchParams.get("c");
      if (id) abrir(id);
    });
    cargarRecientes();
    bloquear(false);
  }

  // ---- configuración: topes y consumo (admin) --------------------------------

  async function cargarTopes() {
    const destino = document.getElementById("asistente-topes");
    if (!destino) return;
    try {
      const [t, c] = await Promise.all([
        fetch("/api/asistente/topes", { credentials: "same-origin" }).then((r) => (r.ok ? r.json() : Promise.reject(r))),
        fetch("/api/asistente/consumo", { credentials: "same-origin" }).then((r) => (r.ok ? r.json() : Promise.reject(r))),
      ]);
      const campo = (nombre, etiqueta) => el(
        "label", {}, etiqueta,
        el("input", { name: nombre, type: "number", min: "0", max: "100", step: "0.05", value: String(t.topes[nombre]), required: true }),
      );
      const resultado = el("div", { clase: "resultado", "aria-live": "polite" });
      const form = el(
        "form", { clase: "formulario-fila" },
        campo("dia", "Tope del día, todo el asistente (USD)"),
        campo("usuario", "Tope por persona al día (USD)"),
        campo("equipo", "Tope por equipo en Mi equipo (USD)"),
        el("button", { type: "submit", texto: "Guardar topes" }),
      );
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const datos = Object.fromEntries([...new FormData(form)].map(([k, v]) => [k, Number(v)]));
        const r = await fetch("/api/asistente/topes", {
          method: "PUT", credentials: "same-origin",
          headers: { "Content-Type": "application/json" }, body: JSON.stringify(datos),
        });
        resultado.className = r.ok ? "resultado ok" : "resultado error";
        resultado.textContent = r.ok ? "Topes guardados." : await errorDe(r);
      });
      const filas = c.por_usuario.length
        ? el(
          "table", { clase: "tabla" },
          el("thead", {}, el("tr", {}, ["Persona", "Conversaciones", "Llamadas", "USD"].map((h) => el("th", { texto: h })))),
          el("tbody", {}, c.por_usuario.map((u) => el(
            "tr", {},
            el("td", { texto: u.nombre || u.usuario_id }),
            el("td", { clase: "num", texto: String(u.conversaciones) }),
            el("td", { clase: "num", texto: String(u.llamadas) }),
            el("td", { clase: "num", texto: Number(u.usd).toFixed(4) }),
          ))),
        )
        : el("p", { clase: "vacio", texto: "Sin consumo este mes." });
      const auditoria = c.auditoria.length
        ? el("ul", { clase: "asis-auditoria" }, c.auditoria.map((a) => el(
          "li", {},
          el("span", { clase: "mono", texto: hora(a.fecha) }), " ",
          `${a.herramienta}: ${a.decision}${a.ok ? "" : " (falló)"}, pidió ${a.pidio}, decidió ${a.decidio}`,
        )))
        : el("p", { clase: "vacio", texto: "Ninguna propuesta decidida todavía." });
      destino.replaceChildren(
        el("p", { clase: "nota", texto: `Gasto de hoy (${t.dia}, hora de Colombia): US$ ${t.gasto_hoy.toFixed(4)}. Si se llega al tope, el asistente deja de responder hasta mañana; si no se puede leer el gasto, tampoco responde.` }),
        form, resultado,
        el("h3", { clase: "asis-subtitulo", texto: `Consumo de ${c.mes}: US$ ${Number(c.total_usd).toFixed(4)}` }),
        el("div", { clase: "tabla-envoltura" }, filas),
        el("p", { clase: "nota", texto: c.nota }),
        el("h3", { clase: "asis-subtitulo", texto: "Propuestas decididas (auditoría)" }),
        auditoria,
      );
    } catch {
      destino.replaceChildren(el("p", { clase: "vacio", texto: "No se pudieron leer los topes del asistente." }));
    }
  }

  window.iniciarAsistente = function (sesion) {
    window.SESION_ACTUAL = sesion;
    iniciar();
    if (sesion && sesion.rol === "admin") cargarTopes();
  };
})();
