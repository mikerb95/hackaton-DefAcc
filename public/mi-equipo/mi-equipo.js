// Vista de un equipo para la persona que lo usa (radar/api/mi_equipo.py).
// El enlace firmado viene en el fragmento (#t=...), que el navegador no manda al servidor;
// aquí se pasa en la cabecera X-Enlace-Equipo. Todo texto del inventario es no confiable:
// se pinta con textContent, nunca como HTML.
"use strict";

(function () {
  const hoja = document.getElementById("hoja");
  const pie = document.getElementById("pie");

  const CUANDO = {
    hoy: { titulo: "Hoy", nota: "Fallas graves o que ya se usan en ataques." },
    esta_semana: { titulo: "Esta semana", nota: "Importante, pero puede esperar unos días." },
    cuando_puedas: { titulo: "Cuando puedas", nota: "Mejoras de seguridad sin apuro." },
  };
  const BANDA = {
    critico: "Riesgo crítico",
    alto: "Riesgo alto",
    medio: "Riesgo medio",
    bajo: "Riesgo bajo",
  };

  function el(etiqueta, clase, texto) {
    const nodo = document.createElement(etiqueta);
    if (clase) nodo.className = clase;
    if (texto !== undefined && texto !== null) nodo.textContent = String(texto);
    return nodo;
  }

  function fecha(iso, conHora) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    const opciones = { day: "numeric", month: "long" };
    if (conHora) Object.assign(opciones, { hour: "2-digit", minute: "2-digit" });
    return d.toLocaleString("es", opciones);
  }

  function hace(iso) {
    const d = new Date(iso);
    if (!iso || Number.isNaN(d.getTime())) return "nunca";
    const minutos = Math.round((Date.now() - d.getTime()) / 60000);
    if (minutos < 2) return "hace un momento";
    if (minutos < 60) return `hace ${minutos} minutos`;
    const horas = Math.round(minutos / 60);
    if (horas < 24) return `hace ${horas} ${horas === 1 ? "hora" : "horas"}`;
    const dias = Math.round(horas / 24);
    return `hace ${dias} ${dias === 1 ? "día" : "días"}`;
  }

  function error(titulo, texto) {
    const t = document.getElementById("t-error").content.cloneNode(true);
    t.querySelector(".error-titulo").textContent = titulo;
    t.querySelector(".error-texto").textContent = texto;
    hoja.replaceChildren(t);
  }

  function enlace() {
    const params = new URLSearchParams(location.hash.slice(1));
    return params.get("t") || "";
  }

  // -- piezas ------------------------------------------------------------------

  function resumen(d) {
    const t = d.termometro || {};
    const conteo = { hoy: 0, esta_semana: 0, cuando_puedas: 0 };
    d.tareas.forEach((x) => { conteo[x.cuando] = (conteo[x.cuando] || 0) + 1; });

    const tarjeta = el("section", `tarjeta resumen banda-${t.banda || "sin"}`);
    const arriba = el("div", "resumen-arriba");
    const nombre = el("div", "resumen-equipo");
    nombre.append(el("h1", "", d.equipo.nombre));
    nombre.append(el("p", "suave", [d.equipo.so, `Último reporte ${hace(d.equipo.ultimo_reporte)}`].filter(Boolean).join(" · ")));
    arriba.append(nombre);
    if (t.medido) arriba.append(el("span", "pildora", BANDA[t.banda] || "Sin riesgo pendiente"));
    tarjeta.append(arriba);

    let frase;
    if (!t.medido) frase = t.motivo || "Todavía no hay una lectura de este equipo.";
    else if (conteo.hoy) frase = `Tienes ${conteo.hoy} ${conteo.hoy === 1 ? "cosa" : "cosas"} que hacer hoy.`;
    else if (conteo.esta_semana) frase = `Tienes ${conteo.esta_semana} ${conteo.esta_semana === 1 ? "pendiente" : "pendientes"} para esta semana.`;
    else if (conteo.cuando_puedas) frase = "Nada urgente. Hay algunas mejoras para cuando tengas tiempo.";
    else frase = "Todo en orden. No tienes nada pendiente.";
    tarjeta.append(el("p", "resumen-frase", frase));

    if (t.medido) {
      const medidor = el("div", "medidor");
      medidor.setAttribute("role", "meter");
      medidor.setAttribute("aria-valuemin", "0");
      medidor.setAttribute("aria-valuemax", "100");
      medidor.setAttribute("aria-valuenow", String(t.nivel));
      medidor.setAttribute("aria-label", "Exposición del equipo, de 0 a 100");
      const relleno = el("span", "medidor-relleno");
      relleno.style.width = `${Math.max(2, t.nivel)}%`;
      medidor.append(relleno);
      tarjeta.append(medidor);
      const escala = el("div", "medidor-escala");
      escala.append(el("span", "", "Sin riesgo"), el("span", "", `${t.nivel} de 100`), el("span", "", "Crítico"));
      tarjeta.append(escala);
    }
    return tarjeta;
  }

  function avisoParcheo(p) {
    const lista = [];
    if (p.reinicio_pendiente) {
      const a = el("section", "tarjeta destacado reinicio");
      a.append(el("h2", "", "Reinicia tu equipo"));
      const desde = fecha(p.reinicio_desde, true);
      a.append(el("p", "", "TI instaló actualizaciones que terminan de aplicarse al reiniciar. Guarda tu trabajo y reinicia cuando puedas hoy."));
      if (desde) a.append(el("p", "suave", `Si ya reiniciaste después del ${desde}, ignora este aviso: se borra solo en el próximo reporte.`));
      lista.push(a);
    }
    if (p.en_curso) {
      const a = el("section", "tarjeta destacado curso");
      a.append(el("h2", "", "TI va a actualizar este equipo"));
      a.append(el("p", "", "Hay actualizaciones aprobadas que se instalan solas en las próximas horas. Algún programa puede cerrarse un momento. El equipo nunca se reinicia por su cuenta."));
      lista.push(a);
    }
    return lista;
  }

  function tarea(x) {
    const art = el("article", `tarea p-${x.prioridad || "informativo"}`);
    const cabeza = el("div", "tarea-cabeza");
    const titulo = el("h3", "");
    titulo.append(el("span", "punto"), document.createTextNode(x.titulo));
    cabeza.append(titulo);
    if (x.explotada) cabeza.append(el("span", "pildora alerta", "Se usa en ataques reales"));
    else if (x.ransomware) cabeza.append(el("span", "pildora alerta", "Usada por ransomware"));
    art.append(cabeza);

    if (x.detalle) art.append(el("p", "suave", x.detalle));
    if (x.pasos) art.append(el("p", "tarea-pasos", x.pasos));

    const extra = [];
    if (x.por_que && x.por_que.length) {
      const ul = el("ul", "por-que");
      x.por_que.forEach((r) => ul.append(el("li", "", r)));
      extra.push(el("h4", "", "Por qué importa"), ul);
    }
    if (x.comandos && x.comandos.length) {
      extra.push(el("h4", "", "Si sabes usar la terminal (o para TI)"));
      x.comandos.forEach((c) => {
        const fila = el("div", "comando");
        fila.append(el("code", "", c));
        const copiar = el("button", "boton-texto", "Copiar");
        copiar.type = "button";
        copiar.addEventListener("click", () => {
          navigator.clipboard.writeText(c).then(
            () => { copiar.textContent = "Copiado"; setTimeout(() => { copiar.textContent = "Copiar"; }, 1500); },
            () => { copiar.textContent = "No se pudo"; },
          );
        });
        fila.append(copiar);
        extra.push(fila);
      });
    }
    if (extra.length) {
      const det = el("details", "tarea-mas");
      det.append(el("summary", "", x.n_fallas ? `Detalles (${x.n_fallas} ${x.n_fallas === 1 ? "falla conocida" : "fallas conocidas"})` : "Detalles"));
      extra.forEach((n) => det.append(n));
      art.append(det);
    }
    return art;
  }

  function tareas(lista) {
    const frag = document.createDocumentFragment();
    ["hoy", "esta_semana", "cuando_puedas"].forEach((cuando) => {
      const grupo = lista.filter((x) => x.cuando === cuando);
      if (!grupo.length) return;
      const sec = el("section", "grupo");
      const cab = el("div", "grupo-cabeza");
      cab.append(el("h2", "", CUANDO[cuando].titulo), el("span", "contador", grupo.length));
      sec.append(cab, el("p", "suave grupo-nota", CUANDO[cuando].nota));
      grupo.forEach((x) => sec.append(tarea(x)));
      frag.append(sec);
    });
    return frag;
  }

  function pintar(d) {
    const partes = [resumen(d), ...avisoParcheo(d.parcheo || {})];
    if (d.equipo.pendiente) {
      const a = el("section", "tarjeta destacado curso");
      a.append(el("h2", "", "Tu equipo espera la aprobación de TI"));
      a.append(el("p", "", "Cuando TI lo apruebe en el radar, aquí verás qué tienes que actualizar."));
      partes.push(a);
    }
    hoja.replaceChildren(...partes, tareas(d.tareas));
    if (window.cajaAsistenteEquipo && !d.equipo.pendiente) hoja.append(window.cajaAsistenteEquipo(enlace()));
    if (d.sin_revisar && d.sin_revisar.length) {
      const s = el("section", "tarjeta sin-revisar");
      s.append(el("h2", "", "Lo que no se pudo revisar"));
      const ul = el("ul", "");
      d.sin_revisar.forEach((r) => ul.append(el("li", "", r)));
      s.append(ul, el("p", "suave", "No significa que esté mal: el agente no pudo leerlo. TI lo tiene a la vista."));
      hoja.append(s);
    }
    pie.replaceChildren(
      el("p", "", `Este enlace vence el ${fecha(d.vence, false) || "pronto"} y se renueva solo cada vez que tu equipo reporta. Es solo para este equipo: no lo compartas.`),
      el("p", "", "¿Dudas o algo no se puede actualizar? Escríbele a TI."),
    );
    pie.hidden = false;
  }

  async function cargar() {
    const t = enlace();
    if (!t) {
      error("Falta el enlace de tu equipo", "Abre esta página desde el aviso del radar en tu equipo (botón \"Ver qué hacer\").");
      return;
    }
    let r;
    try {
      r = await fetch("/api/mi-equipo", { headers: { "X-Enlace-Equipo": t }, cache: "no-store" });
    } catch {
      error("Sin conexión con el radar", "Revisa tu conexión a internet y vuelve a abrir el aviso.");
      return;
    }
    if (r.status === 401) {
      error("Este enlace ya venció", "Se renueva solo. Espera el próximo aviso de tu equipo o pídele a TI uno nuevo.");
      return;
    }
    let datos = {};
    try { datos = await r.json(); } catch { /* respuesta vacía */ }
    if (!r.ok) {
      error("No se pudo mostrar tu equipo", datos.detail || `El radar respondió ${r.status}.`);
      return;
    }
    pintar(datos);
  }

  cargar();
})();
