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

class SinClave extends Error {}

async function api(ruta, opciones = {}) {
  const cabeceras = { ...(opciones.headers || {}) };
  const clave = leerClave();
  if (clave) cabeceras["X-Clave-Acceso"] = clave;
  const respuesta = await fetch(ruta, { ...opciones, headers: cabeceras });
  if (respuesta.status === 401) throw new SinClave();
  const cuerpo = await respuesta.json().catch(() => ({}));
  if (!respuesta.ok) throw new Error(cuerpo.detail || `Error ${respuesta.status}`);
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
  $("#estado").innerHTML = `<span>Última revisión <span class="hora">${esc(fmtHora(rev.fin || rev.inicio))}</span></span>${fuentes}`;

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
      <td class="mono">${esc(g.objetivo_texto)}</td>
    </tr>`).join("");
  $("#productos tbody").innerHTML = filas || '<tr><td colspan="7" class="vacio">Sin hallazgos.</td></tr>';
}

function pintarHallazgos(datos) {
  $("#total-hallazgos").textContent = datos.total ?? "";
  const filas = (datos.hallazgos || []).map((h) => {
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
    ? `<span class="aprobado">Aprobado ${esc(fmtHora(d.aprobacion.aprobado))}</span>`
    : '<button type="button" id="aprobar">Aprobar comunicado</button>';
  $("#detalle-cuerpo").innerHTML = datos + `
    <div class="detalle-rejilla">
      <div class="bloque">
        <h3>Resumen</h3><p>${esc(a.resumen)}</p>
        <h3>Cómo se explota</h3><p>${esc(a.como_se_explota)}</p>
        <h3>Remediación</h3><p>${esc(a.remediacion)}</p>
        ${a.mitigacion_temporal ? `<h3>Mitigación temporal</h3><p>${esc(a.mitigacion_temporal)}</p>` : ""}
        <h3>CVE</h3><p class="mono">${g.cves.map((c) => esc(c)).join(", ")}</p>
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
  const boton = $("#aprobar");
  if (boton) {
    boton.addEventListener("click", async () => {
      boton.disabled = true;
      try {
        await api(`/api/comunicado/${encodeURIComponent(g.producto)}/aprobar`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
        });
        await abrirDetalle(g.producto);
      } catch (error) {
        boton.disabled = false;
        boton.insertAdjacentHTML("afterend", ` <span class="clave-error">${esc(error.message)}</span>`);
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
  const clase = { permitida: "p-ok", negada: "p-caida", limpiada: "p-semanal" };
  $("#trazas").classList.remove("vacio");
  $("#trazas").innerHTML = `<ul class="cobertura-lista">${datos.trazas.slice(0, 30).map((t) => `
    <li><span><span class="mono">${esc(t.herramienta)}</span>
      <span class="pildora ${clase[t.decision] || ""}"><span class="punto"></span>${esc(t.decision)}</span></span>
      <span class="mono">${esc(fmtHora(t.momento))}</span></li>`).join("")}</ul>`;
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
    const [umbrales, trazas] = await Promise.all([api("/api/umbrales"), api("/api/trazas")]);
    pintarAuxiliar("#umbrales", umbrales);
    pintarTrazas(trazas);
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

let pausaFiltro;
$("#filtros").addEventListener("input", () => {
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
