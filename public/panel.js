// Panel del radar: consulta la API cada pocos segundos (sin SSE, PLAN sección 11).
// Todo texto que viene del inventario es no confiable: se escapa siempre antes de pintarlo.
"use strict";

const INTERVALO_MS = 8000;
const CLAVE_LOCAL = "radar.clave";
const ESTADOS = { nuevo: "Nuevo", en_curso: "En curso", mitigado: "Mitigado", descartado: "Descartado" };
const PRIORIDADES = { inmediato: "Inmediato", semanal: "Semanal", informativo: "Informativo", boletin: "Boletín" };
const MOTIVOS = { sin_version: "Sin versión", no_comparable: "Versión no comparable", sin_cpe: "Sin CPE" };

const $ = (sel) => document.querySelector(sel);

function esc(valor) {
  return String(valor ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function leerClave() {
  try { return localStorage.getItem(CLAVE_LOCAL) || ""; } catch { return ""; }
}
function guardarClave(valor) {
  try { localStorage.setItem(CLAVE_LOCAL, valor); } catch { /* sin almacenamiento */ }
}

function leerAprobador() {
  try { return localStorage.getItem("radar.aprobador") || ""; } catch { return ""; }
}
function guardarAprobador(valor) {
  try { localStorage.setItem("radar.aprobador", valor); } catch { /* sin almacenamiento */ }
}

class SinClave extends Error {}

async function api(ruta, opciones = {}) {
  const cabeceras = { ...(opciones.headers || {}) };
  const clave = leerClave();
  if (clave) cabeceras["X-Clave-Acceso"] = clave;
  const respuesta = await fetch(ruta, { ...opciones, headers: cabeceras });
  if (respuesta.status === 401) throw new SinClave();
  const cuerpo = await respuesta.json().catch(() => ({}));
  if (!respuesta.ok) {
    const detalle = typeof cuerpo.detail === "string" ? cuerpo.detail : "Datos inválidos.";
    throw new Error(respuesta.status === 422 ? detalle : (cuerpo.detail ? detalle : `Error ${respuesta.status}`));
  }
  return cuerpo;
}

// ---- formato ---------------------------------------------------------------

const fmtCvss = (v) => (v == null ? '<span class="sin-dato">sin dato</span>' : esc(v.toFixed(1)));
// EPSS ausente no es cero (regla 2).
const fmtEpss = (v) => (v == null ? '<span class="sin-dato">sin dato</span>' : esc((v * 100).toFixed(2) + " %"));

function fmtHora(iso) {
  if (!iso) return "sin revisión";
  const d = new Date(iso);
  return d.toLocaleString("es", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

function pildoraPrioridad(p) {
  if (!p) return "";
  return `<span class="pildora p-${esc(p)}"><span class="punto"></span>${esc(PRIORIDADES[p] || p)}</span>`;
}

// ---- pintado ---------------------------------------------------------------

function pintarResumen(r) {
  const rev = r.revision || {};
  const fuentes = Object.entries(rev.fuentes || {}).map(([nombre, ok]) =>
    `<span class="pildora ${ok ? "p-ok" : "p-caida"}"><span class="punto"></span>${esc(nombre.toUpperCase())}</span>`
  ).join("");
  // Trabajos en cola: píldora neutra. Un análisis pendiente es normal mientras el analista no corre.
  const nombres = { analizar: "Análisis en cola", descargar: "Revisión en cola" };
  const cola = Object.entries(r.trabajos || {}).map(([tipo, n]) =>
    `<span class="pildora p-respaldo" title="Lo toma el worker cuando corre; mientras tanto el detalle muestra el texto armado por código"><span class="punto"></span>${esc(nombres[tipo] || tipo)}: <span class="mono">${esc(n)}</span></span>`
  ).join("");
  $("#estado").innerHTML = `<span>Última revisión <span class="hora">${esc(fmtHora(rev.fin || rev.inicio))}</span></span>${fuentes}${cola}`;

  const aviso = $("#aviso-fuentes");
  if (rev.caidas && rev.caidas.length) {
    aviso.textContent = `No respondieron: ${rev.caidas.join(", ").toUpperCase()}. Lo que dependa de esas fuentes puede estar incompleto (no es cero).`;
    aviso.hidden = false;
  } else {
    aviso.hidden = true;
  }
  $("#aviso-memoria").hidden = r.persistente !== false;

  const c = r.cifras || {};
  const cifras = [
    ["exigen_accion", "Exigen acción", true],
    ["explotadas", "Explotadas (KEV)", false],
    ["semanal", "Al resumen semanal", false],
    ["equipos_afectados", "Equipos afectados", false],
  ];
  $("#cifras").innerHTML = cifras.map(([clave, etiqueta, destacada]) => `
    <div class="cifra${destacada ? " destacada" : ""}">
      <div class="cifra-valor">${esc(c[clave] ?? "-")}</div>
      <div class="cifra-etiqueta">${esc(etiqueta)}</div>
    </div>`).join("");

  const cob = r.cobertura || {};
  const total = (cob.cruzados || 0) + (cob.sin_evaluar || 0);
  const pct = total ? Math.round((cob.cruzados / total) * 100) : 0;
  const motivos = Object.entries(cob.por_motivo || {}).map(([m, n]) =>
    `<li><span>${esc(MOTIVOS[m] || m)}</span><span class="mono">${esc(n)}</span></li>`
  ).join("");
  $("#cobertura").innerHTML = `
    <div><span class="cobertura-cifra">${esc(cob.cruzados ?? 0)}</span>
      <span class="mono" style="color:var(--texto-3)"> / ${esc(total)}</span>
      <span style="color:var(--texto-2)"> programas cruzados</span></div>
    <div class="barra-cobertura" role="img" aria-label="${pct} % cruzado"><span style="width:${pct}%"></span></div>
    <ul class="cobertura-lista">${motivos || '<li class="vacio">Todo se pudo comparar.</li>'}</ul>`;
}

let productoAbierto = null;

function pintarProductos(datos) {
  const filas = (datos.productos || []).map((g) => `
    <tr class="clic${g.producto === productoAbierto ? " activa" : ""}" data-producto="${esc(g.producto)}" tabindex="0">
      <td><div>${esc(g.producto)}</div><div class="etiquetas">${pildoraPrioridad(g.prioridad)}${g.ransomware ? '<span class="pildora p-kev">ransomware</span>' : ""}</div></td>
      <td class="mono">${esc(g.versiones.join(", "))}</td>
      <td class="num">${esc(g.n_equipos)}</td>
      <td class="num">${esc(g.n_cves)}</td>
      <td class="num">${esc(g.en_kev.length)}</td>
      <td class="num">${fmtCvss(g.peor_cvss)}</td>
      <td class="mono objetivo">${esc(g.objetivo_texto)}</td>
    </tr>`).join("");
  $("#productos tbody").innerHTML = filas || '<tr><td colspan="7" class="vacio">Sin hallazgos.</td></tr>';
}

// Con un inventario real son cientos de hallazgos: se pintan por tandas.
const TANDA = 50;
let visibles = TANDA;
let ultimosHallazgos = null;

function pintarHallazgos(datos) {
  ultimosHallazgos = datos;
  $("#total-hallazgos").textContent = datos.total ?? "";
  const lista = datos.hallazgos || [];
  const filas = lista.slice(0, visibles).map((h) => {
    const opciones = Object.entries(ESTADOS).map(([v, t]) =>
      `<option value="${v}"${v === h.estado ? " selected" : ""}>${t}</option>`).join("");
    const etiquetas = [
      h.kev ? '<span class="pildora p-kev">KEV</span>' : "",
      h.ransomware ? '<span class="pildora p-kev">ransomware</span>' : "",
      h.preciso ? "" : '<span class="pildora">no preciso</span>',
    ].join("");
    return `
    <tr>
      <td>${pildoraPrioridad(h.prioridad)}</td>
      <td class="cve">${esc(h.cve)}<div class="etiquetas">${etiquetas}</div></td>
      <td>${esc(h.producto)} <span class="mono" style="color:var(--texto-3)">${esc(h.version_instalada)}</span></td>
      <td class="num">${esc(h.equipos.length)}</td>
      <td class="num">${fmtCvss(h.cvss)}</td>
      <td class="num">${fmtEpss(h.epss)}</td>
      <td class="por-que">${esc(h.por_que.join(" · "))}</td>
      <td><select data-hallazgo="${esc(h.id)}" aria-label="Estado de ${esc(h.cve)}">${opciones}</select>
        ${h.comentario ? `<div class="por-que">${esc(h.comentario)}</div>` : ""}</td>
    </tr>`;
  }).join("");
  $("#hallazgos tbody").innerHTML = filas || '<tr><td colspan="8" class="vacio">Ningún hallazgo con esos filtros.</td></tr>';
  const resto = lista.length - visibles;
  $("#mas-hallazgos").hidden = resto <= 0;
  $("#mas-hallazgos").textContent = `Mostrar ${Math.min(resto, TANDA)} más (quedan ${resto})`;
}

async function abrirDetalle(producto) {
  productoAbierto = producto;
  document.querySelectorAll("#productos tr[data-producto]").forEach((tr) =>
    tr.classList.toggle("activa", tr.dataset.producto === producto));
  const seccion = $("#detalle");
  seccion.hidden = false;
  $("#t-detalle").textContent = producto;
  try {
    pintarDetalle(await api(`/api/analisis/${encodeURIComponent(producto)}`));
  } catch (error) {
    $("#detalle-cuerpo").innerHTML = `<p class="vacio">${esc(error.message)}</p>`;
  }
}

// KEV primero; con cientos de CVE (Chrome) se muestran unas pocas y el total.
const MAX_CVES = 24;
function listaCves(g) {
  const kev = new Set(g.en_kev);
  const orden = [...g.en_kev, ...g.cves.filter((c) => !kev.has(c))];
  const visibles = orden.slice(0, MAX_CVES).map((c) =>
    kev.has(c) ? `<span class="pildora p-kev">${esc(c)}</span>` : `<span class="cve-item">${esc(c)}</span>`).join("");
  const resto = orden.length - MAX_CVES;
  return `<div class="lista-cves mono">${visibles}${resto > 0 ? `<span class="cve-resto">y ${esc(resto)} más</span>` : ""}</div>`;
}

function pintarDetalle(d) {
  const g = d.grupo;
  const datos = `
    <div class="datos-clave">
      ${pildoraPrioridad(g.prioridad)}
      <span class="pildora mono">${esc(g.n_equipos)} equipos</span>
      <span class="pildora mono">${esc(g.n_cves)} CVE</span>
      <span class="pildora mono">peor EPSS ${fmtEpss(g.peor_epss)}</span>
      <span class="pildora mono">${esc(g.objetivo_texto)}</span>
    </div>`;
  if (!d.analisis) {
    $("#detalle-cuerpo").innerHTML = datos + '<p class="vacio">El análisis está en cola: aparece aquí cuando el worker termine.</p>';
    return;
  }
  const a = d.analisis;
  // El respaldo es un camino normal, no un error: píldora neutra, sin rojo.
  const origen = a.origen === "agente"
    ? '<span class="pildora p-agente"><span class="punto"></span>Redactado por el agente</span>'
    : `<span class="pildora p-respaldo" title="${d.guardado ? "El verificador no aceptó el texto del agente o el agente falló" : "El agente todavía no entregó análisis para este producto"}"><span class="punto"></span>Texto armado por código</span>`;
  const aprobado = d.aprobacion
    ? `<span class="aprobado">Aprobado por ${esc(d.aprobacion.por)} · ${esc(fmtHora(d.aprobacion.aprobado))}</span>`
    : `<form id="aprobar" class="aprobar">
        <input name="por" placeholder="Quién aprueba" maxlength="100" required aria-label="Quién aprueba" value="${esc(leerAprobador())}">
        <button type="submit">Aprobar comunicado</button>
      </form>`;
  $("#detalle-cuerpo").innerHTML = datos + `
    <div class="detalle-rejilla">
      <div class="bloque">
        <h3>Resumen</h3><p>${esc(a.resumen)}</p>
        <h3>Cómo se explota</h3><p>${esc(a.como_se_explota)}</p>
        <h3>Remediación</h3><p>${esc(a.remediacion)}</p>
        ${bloqueComandos(d.comandos)}
        ${a.mitigacion_temporal ? `<h3>Mitigación temporal</h3><p>${esc(a.mitigacion_temporal)}</p>` : ""}
        <h3>CVE</h3>${listaCves(g)}
      </div>
      <div class="bloque">
        <h3>Comunicado para TI</h3><div class="comunicado">${esc(a.comunicado_ti)}</div>
        <h3>Comunicado para usuarios</h3><div class="comunicado">${esc(a.comunicado_usuarios)}</div>
        ${a.comunicado_gerencia ? `<h3>Comunicado para gerencia</h3><div class="comunicado">${esc(a.comunicado_gerencia)}</div>` : ""}
        <div class="etiquetas" style="align-items:center;gap:12px">
          <span class="pildora ${a.verificado ? "p-ok" : "p-caida"}"><span class="punto"></span>${a.verificado ? "Verificado" : "Sin verificar"}</span>
          ${origen}
          ${aprobado}
        </div>
      </div>
    </div>`;
  const formulario = $("#aprobar");
  if (formulario) {
    formulario.addEventListener("submit", async (e) => {
      e.preventDefault();
      const boton = formulario.querySelector("button");
      const por = formulario.elements.por.value.trim();
      if (!por) return;
      boton.disabled = true;
      try {
        await api(`/api/comunicado/${encodeURIComponent(g.producto)}/aprobar`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ por }),
        });
        guardarAprobador(por);
        await abrirDetalle(g.producto);
      } catch (error) {
        boton.disabled = false;
        formulario.insertAdjacentHTML("beforeend", ` <span class="clave-error">${esc(error.message)}</span>`);
      }
    });
  }
}

// ---- equipos con agente local ------------------------------------------------
// Los comandos salen de plantillas del código del radar, nunca de un modelo ni del
// inventario. Igual se escapan: van a pantalla.

const PLATAFORMAS = { windows: "Windows", debian: "Debian y Ubuntu", rhel: "RHEL y derivados" };
const POSTURA = {
  firewall: "Firewall", antivirus: "Antimalware", firmas_al_dia: "Firmas",
  cifrado_disco: "Cifrado", secure_boot: "Secure Boot", actualizaciones_automaticas: "Actualizaciones",
};
const TIPOS_EQUIPO = { postura: "Postura", so_sin_soporte: "Sistema", paquete: "Paquete" };

function bloqueComandos(comandos) {
  if (!comandos || !comandos.length) return "";
  return comandos.map((c) => {
    const texto = typeof c === "string" ? c : c.texto;
    const donde = typeof c === "string" ? "" : ` <span class="comando-donde">${esc(PLATAFORMAS[c.plataforma] || c.plataforma)}</span>`;
    return `<div class="comando"><code>${esc(texto)}</code>${donde}</div>`;
  }).join("") + '<p class="comando-nota">Comando armado por el radar a partir de una plantilla. Lo ejecuta una persona.</p>';
}

function pildorasPostura(postura) {
  if (!postura) return '<span class="sin-dato">sin reporte</span>';
  return Object.entries(POSTURA).map(([clave, etiqueta]) => {
    const valor = postura[clave];
    const clase = valor === "si" ? "p-ok" : (valor === "no" ? "p-caida" : "");
    const titulo = valor === "si" ? "bien" : (valor === "no" ? "falla" : "no se pudo revisar");
    return `<span class="pildora ${clase}" title="${esc(etiqueta)}: ${esc(titulo)}"><span class="punto"></span>${esc(etiqueta)}</span>`;
  }).join("");
}

function nombreSistema(so) {
  if (!so) return '<span class="sin-dato">sin reporte</span>';
  const version = [so.version, so.build || so.kernel].filter(Boolean).join(" · ");
  return `${esc(so.nombre)} <span class="mono" style="color:var(--texto-3)">${esc(version)}</span>`;
}

let equipoAbierto = null;

function pintarEquipos(datos) {
  const hay = datos.disponible && datos.equipos.length > 0;
  $("#panel-equipos").hidden = !hay;
  if (!hay) return;
  $("#total-equipos").textContent = datos.total;
  $("#equipos tbody").innerHTML = datos.equipos.map((e) => `
    <tr class="clic${e.id === equipoAbierto ? " activa" : ""}" data-equipo="${esc(e.id)}" tabindex="0">
      <td><div class="mono">${esc(e.nombre)}</div><div class="etiquetas">${pildoraPrioridad(e.peor_prioridad)}${e.revocado ? '<span class="pildora p-caida">revocado</span>' : ""}</div></td>
      <td>${nombreSistema(e.so)}</td>
      <td class="mono">${esc(e.ultimo_reporte ? fmtHora(e.ultimo_reporte) : "sin reporte")}</td>
      <td class="num">${esc(e.acciones.inmediato)}</td>
      <td class="num">${esc(e.acciones.semanal)}</td>
      <td><div class="etiquetas" style="margin-top:0">${pildorasPostura(e.postura)}</div></td>
    </tr>`).join("");
}

async function abrirEquipo(id) {
  equipoAbierto = id;
  document.querySelectorAll("#equipos tr[data-equipo]").forEach((tr) =>
    tr.classList.toggle("activa", tr.dataset.equipo === id));
  $("#detalle-equipo").hidden = false;
  try {
    pintarEquipo(await api(`/api/equipos/${encodeURIComponent(id)}`));
  } catch (error) {
    $("#detalle-equipo-cuerpo").innerHTML = `<p class="vacio">${esc(error.message)}</p>`;
  }
}

function accionDeProducto(p) {
  const kev = p.en_kev.length ? `<span class="pildora p-kev">${esc(p.en_kev.length)} en KEV</span>` : "";
  return `
    <li class="accion">
      <div class="accion-cabeza">${pildoraPrioridad(p.prioridad)}
        <strong>${esc(p.producto)}</strong> <span class="mono" style="color:var(--texto-3)">${esc(p.versiones.join(", "))}</span>
        <span class="pildora mono">${esc(p.n_cves)} CVE</span>${kev}${p.ransomware ? '<span class="pildora p-kev">ransomware</span>' : ""}</div>
      <div class="por-que">${esc(p.por_que.join(" · "))}</div>
      <p>${esc(p.pasos)}</p>
      ${bloqueComandos(p.comandos)}
    </li>`;
}

function accionDeEquipo(h) {
  const d = h.detalle || {};
  const kev = (d.en_kev || []).length ? `<span class="pildora p-kev">${esc(d.en_kev.length)} en KEV</span>` : "";
  const cves = d.n_cves ? `<span class="pildora mono">${esc(d.n_cves)} CVE</span>` : "";
  const arreglo = d.version_arreglo ? `<span class="pildora mono">arreglo ${esc(d.version_arreglo)}</span>` : "";
  return `
    <li class="accion">
      <div class="accion-cabeza">${pildoraPrioridad(h.prioridad)}
        <span class="pildora">${esc(TIPOS_EQUIPO[h.tipo] || h.tipo)}</span>
        <strong>${esc(h.titulo)}</strong>${cves}${kev}${arreglo}</div>
      <div class="por-que">${esc(h.por_que.join(" · "))}</div>
      <p>${esc(h.pasos)}</p>
      ${bloqueComandos(h.comandos)}
    </li>`;
}

function pintarEquipo(d) {
  const e = d.equipo;
  $("#t-detalle-equipo").textContent = e.nombre;
  const hw = d.equipo.hardware || {};
  const ficha = [
    ["Sistema", e.so ? [e.so.nombre, e.so.version, e.so.build || e.so.kernel].filter(Boolean).join(" · ") : null],
    ["Equipo", [hw.fabricante, hw.modelo].filter(Boolean).join(" ") || null],
    ["BIOS", hw.bios], ["Procesador", hw.cpu],
    ["Memoria", hw.ram_gb != null ? `${hw.ram_gb} GB` : null], ["TPM", hw.tpm],
    ["Agente", e.agente_version], ["Último reporte", e.ultimo_reporte ? fmtHora(e.ultimo_reporte) : null],
  ].filter(([, valor]) => valor).map(([nombre, valor]) =>
    `<li><span>${esc(nombre)}</span><span class="mono">${esc(valor)}</span></li>`).join("");
  const acciones = d.productos.map(accionDeProducto).join("") + d.hallazgos_equipo.map(accionDeEquipo).join("");
  const recortes = Object.entries(e.recortes || {}).map(([clave, n]) => `${clave.replace(/_/g, " ")}: ${n}`).join(", ");
  const sinRevisar = [
    ...d.sin_revisar,
    ...(d.cobertura.sin_evaluar ? [`${d.cobertura.sin_evaluar} programas sin evaluar (${Object.entries(d.cobertura.por_motivo).map(([m, n]) => `${MOTIVOS[m] || m}: ${n}`).join(", ")})`] : []),
    ...(recortes ? [`Recortado del último reporte: ${recortes}`] : []),
  ];
  $("#detalle-equipo-cuerpo").innerHTML = `
    <div class="datos-clave">${pildoraPrioridad(e.peor_prioridad)}${pildorasPostura(e.postura)}
      ${e.revocado ? '<span class="pildora p-caida">revocado</span>' : `<button type="button" class="boton-texto" id="revocar-equipo">Revocar credencial</button>`}</div>
    <div class="detalle-rejilla">
      <div class="bloque">
        <h3>Qué hacer en este equipo</h3>
        <ul class="acciones">${acciones || '<li class="vacio">Nada que hacer con lo que se pudo revisar.</li>'}</ul>
      </div>
      <div class="bloque">
        <h3>Ficha</h3><ul class="cobertura-lista">${ficha || '<li class="vacio">El equipo todavía no ha reportado.</li>'}</ul>
        <h3 style="margin-top:16px">Sin revisar</h3>
        <ul class="cobertura-lista">${sinRevisar.map((s) => `<li><span>${esc(s)}</span></li>`).join("") || '<li class="vacio">Todo se pudo revisar.</li>'}</ul>
      </div>
    </div>`;
  const revocar = $("#revocar-equipo");
  if (revocar) {
    revocar.addEventListener("click", async () => {
      if (!confirm(`¿Dejar de aceptar reportes de ${e.nombre}?`)) return;
      revocar.disabled = true;
      try {
        await api(`/api/equipos/${encodeURIComponent(e.id)}/revocar`, { method: "POST" });
        await abrirEquipo(e.id);
        refrescarAuxiliares();
      } catch (error) {
        revocar.disabled = false;
        revocar.insertAdjacentHTML("afterend", ` <span class="clave-error">${esc(error.message)}</span>`);
      }
    });
  }
}

function pintarAuxiliar(id, datos) {
  const caja = $(id);
  caja.textContent = datos.disponible ? "" : (datos.motivo || "Sin datos todavía.");
}

function pintarTrazas(datos) {
  if (!datos.disponible || !datos.trazas.length) {
    pintarAuxiliar("#trazas", datos.disponible ? { motivo: "El agente todavía no ha llamado herramientas." } : datos);
    return;
  }
  const clase = { permitida: "p-ok", negada: "p-caida", limpiada: "p-semanal", aprobacion_pedida: "p-respaldo" };
  const etiqueta = { aprobacion_pedida: "aprobación pedida" };
  $("#trazas").classList.remove("vacio");
  $("#trazas").innerHTML = `<ul class="cobertura-lista">${datos.trazas.slice(0, 30).map((t) => `
    <li class="traza"><div><span class="pildora ${clase[t.decision] || ""}"><span class="punto"></span>${esc(etiqueta[t.decision] || t.decision)}</span>
      <span class="mono">${esc(t.herramienta)}</span>
      <span class="mono traza-hora">${esc(fmtHora(t.momento))}</span></div>
      ${t.entrada ? `<div class="traza-entrada mono">${esc(String(t.entrada).slice(0, 160))}</div>` : ""}</li>`).join("")}</ul>`;
}

// ---- umbrales --------------------------------------------------------------
// Una sola serie (comunicados que saldrían según el umbral de EPSS, con el CVSS elegido) y el
// piso de KEV como referencia punteada. La celda vigente va marcada.

let barridoActual = null;
let grafica = null;

const fmtUmbralEpss = (v) => (v > 1 ? "apagado" : `${Math.round(v * 100)} %`);
const fmtUmbralCvss = (v) => (v > 10 ? "apagado" : v.toFixed(1));
const color = (nombre) => getComputedStyle(document.documentElement).getPropertyValue(nombre).trim();

function pintarUmbrales(datos) {
  const caja = $("#umbrales");
  if (!datos.disponible || !datos.celdas || !datos.celdas.length) {
    caja.className = "vacio";
    caja.textContent = datos.motivo || "Sin hallazgos para barrer.";
    return;
  }
  const primeraVez = !barridoActual;
  barridoActual = datos;
  if (primeraVez) {
    caja.className = "";
    const opciones = datos.rejilla_cvss.map((v) =>
      `<option value="${v}"${v === datos.actual.cvss ? " selected" : ""}>CVSS ≥ ${esc(fmtUmbralCvss(v))}</option>`).join("");
    caja.innerHTML = `
      <div class="umbrales-cabeza">
        <span class="filtros">
          <select id="umbral-cvss" aria-label="Umbral de CVSS">${opciones}</select>
          <select id="umbral-medida" aria-label="Qué contar">
            <option value="productos">Comunicados</option>
            <option value="hallazgos">Hallazgos</option>
            <option value="equipos">Equipos</option>
          </select>
        </span>
        <span class="umbrales-leyenda"><span class="muestra-linea"></span><span id="umbral-nombre">comunicados</span> inmediatos
          <span class="muestra-linea punteada"></span>piso por KEV</span>
      </div>
      <div class="grafica-caja"><canvas id="grafica-umbrales" role="img" aria-label="Comunicados inmediatos según el umbral de EPSS"></canvas></div>
      <p class="umbrales-resumen" id="umbrales-resumen"></p>`;
    $("#umbral-cvss").addEventListener("change", dibujarUmbrales);
    $("#umbral-medida").addEventListener("change", dibujarUmbrales);
  }
  dibujarUmbrales();
}

function dibujarUmbrales() {
  const d = barridoActual;
  const cvss = Number($("#umbral-cvss").value);
  const celdas = d.rejilla_epss.map((e) => d.celdas.find((c) => c.epss === e && c.cvss === cvss));
  const vigenteCvss = cvss === d.actual.cvss;
  const medida = $("#umbral-medida").value;
  const nombre = { productos: "comunicados", hallazgos: "hallazgos", equipos: "equipos" }[medida];
  $("#umbral-nombre").textContent = nombre;
  const piso = d.solo_kev[medida];
  const acento = color("--acento");
  const tenue = color("--texto-3");

  $("#umbrales-resumen").innerHTML = `Con los umbrales vigentes (EPSS ≥ <span class="mono">${esc(fmtUmbralEpss(d.actual.epss))}</span>,
    CVSS ≥ <span class="mono">${esc(fmtUmbralCvss(d.actual.cvss))}</span>) salen
    <span class="mono">${esc(d.actual.productos)}</span> comunicados inmediatos
    (<span class="mono">${esc(d.actual.hallazgos)}</span> hallazgos, <span class="mono">${esc(d.actual.equipos)}</span> equipos).
    El piso por KEV es <span class="mono">${esc(d.solo_kev.productos)}</span> comunicados: no baja con ningún umbral.
    ${d.sin_epss ? `<span class="mono">${esc(d.sin_epss)}</span> hallazgos sin EPSS no cruzan ese umbral.` : ""}`;

  const radios = d.rejilla_epss.map((e) => (vigenteCvss && e === d.actual.epss ? 7 : 4));
  const datos = {
    labels: d.rejilla_epss.map(fmtUmbralEpss),
    datasets: [
      {
        label: `${nombre} inmediatos`,
        data: celdas.map((c) => c[medida]),
        borderColor: acento, backgroundColor: acento, borderWidth: 2,
        pointRadius: radios, pointHoverRadius: 8,
        pointBorderColor: color("--ink-1"), pointBorderWidth: 2, tension: 0,
      },
      {
        label: "Piso por KEV",
        data: d.rejilla_epss.map(() => piso),
        borderColor: tenue, borderDash: [5, 4], borderWidth: 1.5, pointRadius: 0, pointHoverRadius: 0,
      },
    ],
  };
  if (grafica) {
    grafica.data = datos;
    grafica.update("none");
    return;
  }
  if (typeof Chart === "undefined") {
    $(".grafica-caja").innerHTML = '<p class="vacio">No cargó la librería de gráficas; el resumen de abajo tiene las cifras.</p>';
    return;
  }
  grafica = new Chart($("#grafica-umbrales"), {
    type: "line",
    data: datos,
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          filter: (item) => item.datasetIndex === 0,
          callbacks: {
            title: (items) => `EPSS ≥ ${items[0].label}`,
            label: (item) => {
              const cv = Number($("#umbral-cvss").value);
              const c = barridoActual.celdas.find((x) => x.epss === barridoActual.rejilla_epss[item.dataIndex] && x.cvss === cv);
              return [`${c.productos} comunicados`, `${c.hallazgos} hallazgos · ${c.cves} CVE`, `${c.equipos} equipos`];
            },
          },
        },
      },
      scales: {
        x: { title: { display: true, text: "Umbral de EPSS", color: tenue }, ticks: { color: tenue }, grid: { display: false } },
        y: { beginAtZero: true, ticks: { color: tenue, precision: 0 }, grid: { color: color("--ink-3") } },
      },
    },
  });
}

// ---- ciclo -----------------------------------------------------------------

function parametrosFiltro() {
  const f = new FormData($("#filtros"));
  const p = new URLSearchParams();
  if (f.get("prioridad")) p.set("prioridad", f.get("prioridad"));
  if (f.get("kev")) p.set("kev", "true");
  const texto = (f.get("texto") || "").trim();
  if (texto) p.set("texto", texto);
  return p.toString();
}

function editandoEstado() {
  const activo = document.activeElement;
  return activo && activo.matches("#hallazgos select");
}

async function refrescar() {
  try {
    const [resumen, productos, hallazgos] = await Promise.all([
      api("/api/resumen"),
      api("/api/productos"),
      api(`/api/hallazgos?${parametrosFiltro()}`),
    ]);
    $("#clave").hidden = true;
    pintarResumen(resumen);
    pintarProductos(productos);
    if (!editandoEstado()) pintarHallazgos(hallazgos);
  } catch (error) {
    if (error instanceof SinClave) {
      $("#clave").hidden = false;
      $("#estado").innerHTML = '<span class="pildora p-caida"><span class="punto"></span>Falta la clave</span>';
      return;
    }
    $("#estado").innerHTML = `<span class="pildora p-caida"><span class="punto"></span>API sin respuesta</span> <span>${esc(error.message)}</span>`;
  }
}

async function refrescarAuxiliares() {
  try {
    const [umbrales, trazas, equipos] = await Promise.all([
      api("/api/umbrales"), api("/api/trazas"), api("/api/equipos"),
    ]);
    pintarUmbrales(umbrales);
    pintarTrazas(trazas);
    pintarEquipos(equipos);
  } catch { /* se reintenta en el próximo ciclo */ }
}

// ---- eventos ---------------------------------------------------------------

$("#clave").addEventListener("submit", (e) => {
  e.preventDefault();
  guardarClave($("#clave-valor").value);
  $("#clave-valor").value = "";
  refrescar();
  refrescarAuxiliares();
});

$("#mas-hallazgos").addEventListener("click", () => {
  visibles += TANDA;
  if (ultimosHallazgos) pintarHallazgos(ultimosHallazgos);
});

let pausaFiltro;
$("#filtros").addEventListener("input", () => {
  visibles = TANDA;
  clearTimeout(pausaFiltro);
  pausaFiltro = setTimeout(refrescar, 250);
});
$("#filtros").addEventListener("submit", (e) => e.preventDefault());

$("#hallazgos").addEventListener("change", async (e) => {
  const select = e.target.closest("select[data-hallazgo]");
  if (!select) return;
  select.disabled = true;
  try {
    await api(`/api/hallazgos/${encodeURIComponent(select.dataset.hallazgo)}/estado`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ estado: select.value }),
    });
  } catch (error) {
    $("#estado").insertAdjacentHTML("beforeend", ` <span class="clave-error">${esc(error.message)}</span>`);
  } finally {
    select.disabled = false;
    select.blur();
    refrescar();
  }
});

function abrirDesdeFila(e) {
  const fila = e.target.closest("tr[data-producto]");
  if (!fila) return;
  if (e.type === "keydown" && e.key !== "Enter" && e.key !== " ") return;
  e.preventDefault();
  abrirDetalle(fila.dataset.producto);
  $("#detalle").scrollIntoView({ behavior: "smooth", block: "start" });
}
$("#productos").addEventListener("click", abrirDesdeFila);
$("#productos").addEventListener("keydown", abrirDesdeFila);

function abrirEquipoDesdeFila(e) {
  const fila = e.target.closest("tr[data-equipo]");
  if (!fila) return;
  if (e.type === "keydown" && e.key !== "Enter" && e.key !== " ") return;
  e.preventDefault();
  abrirEquipo(fila.dataset.equipo);
  $("#detalle-equipo").scrollIntoView({ behavior: "smooth", block: "start" });
}
$("#equipos").addEventListener("click", abrirEquipoDesdeFila);
$("#equipos").addEventListener("keydown", abrirEquipoDesdeFila);

$("#cerrar-equipo").addEventListener("click", () => {
  equipoAbierto = null;
  $("#detalle-equipo").hidden = true;
  document.querySelectorAll("#equipos tr.activa").forEach((tr) => tr.classList.remove("activa"));
});

$("#cerrar-detalle").addEventListener("click", () => {
  productoAbierto = null;
  $("#detalle").hidden = true;
  document.querySelectorAll("#productos tr.activa").forEach((tr) => tr.classList.remove("activa"));
});

$("#carga").addEventListener("submit", async (e) => {
  e.preventDefault();
  const archivo = $("#archivo").files[0];
  if (!archivo) return;
  const salida = $("#carga-resultado");
  const boton = e.target.querySelector("button");
  boton.disabled = true;
  salida.textContent = "Leyendo...";
  const cuerpo = new FormData();
  cuerpo.append("archivo", archivo);
  try {
    const r = await api("/api/inventario", { method: "POST", body: cuerpo });
    const l = r.lectura;
    const descartes = r.descartadas.map((d) => `<li>Fila <span class="mono">${esc(d.fila)}</span>: ${esc(d.motivo)}</li>`).join("");
    salida.innerHTML = `
      <p><span class="mono">${esc(l.filas)}</span> filas leídas (${esc(l.fuente)}${l.hoja ? ", hoja " + esc(l.hoja) : ""}),
      <span class="mono">${esc(l.sin_version)}</span> sin versión, <span class="mono">${esc(l.duplicadas)}</span> duplicadas,
      <span class="mono">${esc(l.descartadas)}</span> descartadas.
      ${r.cruce === "pendiente" ? esc(r.motivo || "El cruce todavía no está conectado.") : ""}</p>
      ${r.resultado ? `<p>Cruce: <span class="mono">${esc(r.resultado.hallazgos)}</span> hallazgos en
      <span class="mono">${esc(r.resultado.productos)}</span> productos, <span class="mono">${esc(r.resultado.en_kev)}</span> CVE en KEV,
      <span class="mono">${esc(r.resultado.cobertura)}</span> filas a cobertura. El análisis quedó en cola.</p>` : ""}
      ${descartes ? `<ul>${descartes}</ul>` : ""}`;
    refrescar();
  } catch (error) {
    salida.innerHTML = `<span class="error">${esc(error instanceof SinClave ? "Falta la clave de acceso." : error.message)}</span>`;
  } finally {
    boton.disabled = false;
  }
});

refrescar();
refrescarAuxiliares();
setInterval(refrescar, INTERVALO_MS);
setInterval(refrescarAuxiliares, INTERVALO_MS * 2);
