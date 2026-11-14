// Panel del radar: consulta la API cada pocos segundos (sin SSE, PLAN sección 11).
// Todo texto que viene del inventario es no confiable: se escapa siempre antes de pintarlo.
// La sesión va en una cookie HttpOnly (radar/api/sesion.py); este archivo no la ve ni la guarda.
// admin.js (cargado después) revisa la sesión, arma la navegación y arranca el ciclo.
"use strict";

const INTERVALO_MS = 8000;
const ESTADOS = { nuevo: "Nuevo", en_curso: "En curso", mitigado: "Mitigado", descartado: "Descartado" };
const PRIORIDADES = { inmediato: "Inmediato", semanal: "Semanal", informativo: "Informativo", boletin: "Boletín" };
const MOTIVOS = { sin_version: "Sin versión", no_comparable: "Versión no comparable", sin_cpe: "Sin CPE" };

const $ = (sel) => document.querySelector(sel);

function esc(valor) {
  return String(valor ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

// Sesión vigente: la llena admin.js con GET /api/sesion antes de arrancar.
let SESION = null;
const NIVELES = { lector: 0, analista: 1, admin: 2 };
const puede = (rol) => SESION && NIVELES[SESION.rol] >= NIVELES[rol];

class SinClave extends Error {}

function irAlLogin() {
  const volver = encodeURIComponent(location.pathname + location.hash);
  location.replace(`/entrar/?volver=${volver}`);
}

async function api(ruta, opciones = {}) {
  const respuesta = await fetch(ruta, { credentials: "same-origin", ...opciones });
  if (respuesta.status === 401) {
    irAlLogin();
    throw new SinClave("La sesión venció.");
  }
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
    ["exigen_accion", "Exigen acción", true, "acento", "Prioridad inmediata"],
    ["explotadas", "Explotadas (KEV)", false, "rojo", "Explotación confirmada por CISA"],
    ["semanal", "Al resumen semanal", false, "ambar", "Van al boletín de la semana"],
    ["equipos_afectados", "Equipos afectados", false, "gris", "Con al menos un hallazgo"],
  ];
  // Las cifras se arman una vez; después solo cambia el número, y si cambió, gira hasta el
  // valor nuevo (ej.: "Exigen acción" baja tras mitigar). Con movimiento reducido, salta.
  if (!$("#cifras").children.length) {
    $("#cifras").innerHTML = cifras.map(([clave, etiqueta, destacada, tono, nota]) => `
      <div class="cifra${destacada ? " destacada" : ""}">
        <div class="cifra-etiqueta"><span class="punto punto-${tono}"></span>${esc(etiqueta)}</div>
        <div class="cifra-valor" data-clave="${clave}">-</div>
        <div class="cifra-nota">${esc(nota)}</div>
      </div>`).join("");
  }
  cifras.forEach(([clave]) => animarCifra($(`.cifra-valor[data-clave="${clave}"]`), c[clave]));

  const cob = r.cobertura || {};
  const total = (cob.cruzados || 0) + (cob.sin_evaluar || 0);
  const pct = total ? Math.round((cob.cruzados / total) * 100) : 0;
  const sinEvaluar = cob.sin_evaluar || 0;
  const motivos = Object.entries(cob.por_motivo || {}).sort((a, b) => b[1] - a[1]).map(([m, n]) => {
    const ancho = sinEvaluar ? Math.max(2, Math.round((n / sinEvaluar) * 100)) : 0;
    return `<li><div class="motivo-fila"><span>${esc(MOTIVOS[m] || m)}</span><span class="mono">${esc(n)}</span></div>
      <div class="motivo-barra"><span style="width:${ancho}%"></span></div></li>`;
  }).join("");
  $("#cobertura").innerHTML = `
    <div class="cobertura-cabeza">
      <span class="cobertura-pct">${esc(pct)}<small>%</small></span>
      <span class="cobertura-detalle"><span class="mono">${esc(cob.cruzados ?? 0)}</span> de <span class="mono">${esc(total)}</span> programas se pudieron cruzar con NVD</span>
    </div>
    <div class="barra-cobertura" role="img" aria-label="${pct} % cruzado"><span style="width:${pct}%"></span></div>
    ${sinEvaluar ? `<h3 class="cobertura-sub">Sin evaluar <span class="mono">${esc(sinEvaluar)}</span></h3>` : ""}
    <ul class="cobertura-lista motivos">${motivos || '<li class="vacio">Todo se pudo comparar.</li>'}</ul>
    ${sinEvaluar ? '<p class="nota cobertura-nota">Sin comparación no hay hallazgo: estos programas no cuentan como sanos, quedan pendientes.</p>' : ""}`;
}

const MOVIMIENTO_REDUCIDO = window.matchMedia("(prefers-reduced-motion: reduce)");

function animarCifra(el, valor) {
  const nuevo = Number(valor);
  const previo = Number(el.dataset.valor);
  el.dataset.valor = valor ?? "";
  if (valor == null || Number.isNaN(nuevo)) { el.textContent = valor ?? "-"; return; }
  if (Number.isNaN(previo) || previo === nuevo || MOVIMIENTO_REDUCIDO.matches) {
    el.textContent = nuevo;
    return;
  }
  el.classList.remove("cambio");
  void el.offsetWidth;
  el.classList.add("cambio");
  const inicio = performance.now();
  const paso = (t) => {
    const k = Math.min((t - inicio) / 700, 1);
    const suave = 1 - Math.pow(1 - k, 3);
    el.textContent = Math.round(previo + (nuevo - previo) * suave);
    if (k < 1) requestAnimationFrame(paso);
  };
  requestAnimationFrame(paso);
}

// Destello en las filas que cambiaron desde el último pintado (nunca en el primero).
// Con `nuevas`, también las filas que no estaban (un equipo recién inscrito); sin él, una
// fila que aparece por cambiar el filtro no destella.
function marcarCambios(memoria, clave, firma, nuevas = false) {
  const previa = memoria.get(clave);
  memoria.set(clave, firma);
  if (memoria.primera || previa === firma) return "";
  if (previa === undefined && !nuevas) return "";
  return " destello";
}
const firmasHallazgos = Object.assign(new Map(), { primera: true });
const firmasEquipos = Object.assign(new Map(), { primera: true });

let productoAbierto = null;

// Versiones instaladas como chips; más de 4 se resumen en "+N" con la lista completa en el title.
function chipsVersiones(versiones) {
  const max = 4;
  const vis = versiones.slice(0, max).map((v) => `<span class="version">${esc(v)}</span>`).join("");
  const resto = versiones.length - max;
  return `<div class="versiones">${vis}${resto > 0
    ? `<span class="version version-mas" title="${esc(versiones.join(", "))}">+${resto}</span>` : ""}</div>`;
}

// Severidad por el peor CVSS. Sin dato no es cero (regla 2).
function chipCvss(v) {
  if (v == null) return '<span class="sin-dato">sin dato</span>';
  const nivel = v >= 9 ? "critica" : v >= 7 ? "alta" : v >= 4 ? "media" : "baja";
  return `<span class="sev sev-${nivel}">${esc(v.toFixed(1))}</span>`;
}

// Con versionEndIncluding no se sabe la versión corregida: "posterior a", nunca "actualizar a" (regla 5).
function celdaObjetivo(g) {
  if (g.tipo_objetivo === "exacta" && g.version_objetivo) {
    return `<span class="obj-etiqueta">Actualizar a</span><span class="obj-version">${esc(g.version_objetivo)}</span>`;
  }
  if (g.tipo_objetivo === "posterior_a" && g.version_objetivo) {
    return `<span class="obj-etiqueta">Posterior a</span><span class="obj-version obj-incierta">${esc(g.version_objetivo)}</span>`;
  }
  return '<span class="sin-dato">Sin versión objetivo conocida</span>';
}

function pintarProductos(datos) {
  const filas = (datos.productos || []).map((g) => `
    <tr class="clic${g.producto === productoAbierto ? " activa" : ""}" data-producto="${esc(g.producto)}" tabindex="0">
      <td class="producto"><div class="producto-nombre">${esc(g.producto)}</div><div class="etiquetas">${pildoraPrioridad(g.prioridad)}${g.ransomware ? '<span class="pildora p-kev">ransomware</span>' : ""}</div></td>
      <td>${chipsVersiones(g.versiones)}</td>
      <td class="num">${esc(g.n_equipos)}</td>
      <td class="num">${esc(g.n_cves)}</td>
      <td class="num">${g.en_kev.length ? `<span class="kev-n">${esc(g.en_kev.length)}</span>` : '<span class="cero">0</span>'}</td>
      <td class="num">${chipCvss(g.peor_cvss)}</td>
      <td class="objetivo">${celdaObjetivo(g)}</td>
      <td class="flecha" aria-hidden="true">›</td>
    </tr>`).join("");
  $("#productos tbody").innerHTML = filas || '<tr><td colspan="8" class="vacio">Sin hallazgos.</td></tr>';
}

// Con un inventario real son cientos de hallazgos: se pintan por tandas.
const TANDA = 50;
let visibles = TANDA;
let ultimosHallazgos = null;

function pintarHallazgos(datos) {
  ultimosHallazgos = datos;
  $("#total-hallazgos").textContent = datos.total ?? "";
  $("#nav-hallazgos").textContent = datos.total ?? "";
  const lista = datos.hallazgos || [];
  const filas = lista.slice(0, visibles).map((h) => {
    const opciones = Object.entries(ESTADOS).map(([v, t]) =>
      `<option value="${v}"${v === h.estado ? " selected" : ""}>${t}</option>`).join("");
    const etiquetas = [
      h.kev ? '<span class="pildora p-kev">KEV</span>' : "",
      h.ransomware ? '<span class="pildora p-kev">ransomware</span>' : "",
      h.preciso ? "" : '<span class="pildora">no preciso</span>',
    ].join("");
    const destello = marcarCambios(firmasHallazgos, h.id, `${h.estado}|${h.comentario || ""}`);
    return `
    <tr class="${destello.trim()}">
      <td>${pildoraPrioridad(h.prioridad)}</td>
      <td class="cve">${esc(h.cve)}<div class="etiquetas">${etiquetas}</div></td>
      <td>${esc(h.producto)} <span class="mono" style="color:var(--texto-3)">${esc(h.version_instalada)}</span></td>
      <td class="num">${esc(h.equipos.length)}</td>
      <td class="num">${fmtCvss(h.cvss)}</td>
      <td class="num">${fmtEpss(h.epss)}</td>
      <td class="por-que">${esc(h.por_que.join(" · "))}</td>
      <td><select data-hallazgo="${esc(h.id)}" aria-label="Estado de ${esc(h.cve)}"${puede("analista") ? "" : " disabled"}>${opciones}</select>
        ${h.comentario ? `<div class="por-que">${esc(h.comentario)}</div>` : ""}</td>
    </tr>`;
  }).join("");
  $("#hallazgos tbody").innerHTML = filas || '<tr><td colspan="8" class="vacio">Ningún hallazgo con esos filtros.</td></tr>';
  firmasHallazgos.primera = false;
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
  // Quien aprueba sale de la sesión: no se escribe a mano.
  const aprobado = d.aprobacion
    ? `<span class="aprobado">Aprobado por ${esc(d.aprobacion.por)}, ${esc(fmtHora(d.aprobacion.aprobado))}</span>`
    : (puede("analista")
      ? `<form id="aprobar" class="aprobar">
          <button type="submit">Aprobar comunicado</button>
          <span class="nota">como ${esc(SESION.nombre)}</span>
        </form>`
      : '<span class="nota">Sin aprobar. Lo aprueba un analista.</span>');
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
      boton.disabled = true;
      try {
        await api(`/api/comunicado/${encodeURIComponent(g.producto)}/aprobar`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}),
        });
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

// ---- termómetro de exposición ------------------------------------------------
// La lectura la calcula la API (radar/api/termometro.py) con las acciones abiertas del
// equipo. Aquí solo se dibuja. Sin lectura (pendiente o sin reporte) no se pinta un 0.

const BANDAS_TERMOMETRO = [
  { clave: "bajo", desde: 0, hasta: 24, etiqueta: "bajo" },
  { clave: "medio", desde: 25, hasta: 59, etiqueta: "medio" },
  { clave: "alto", desde: 60, hasta: 84, etiqueta: "alto" },
  { clave: "critico", desde: 85, hasta: 100, etiqueta: "crítico" },
];
const EXPOSICION = { bajo: "baja", medio: "media", alto: "alta", critico: "crítica" };

function svgTermometro(t) {
  // Escala: 0 en y=232 y 100 en y=28 dentro del tubo.
  const y = (v) => 232 - (204 * v) / 100;
  const medido = t.medido && t.nivel != null;
  const clase = medido ? `t-${t.banda}` : "t-sin";
  const tope = medido ? y(Math.max(t.nivel, 1)) : 232;
  const marcas = [];
  for (let v = 0; v <= 100; v += 5) {
    const mayor = v % 25 === 0;
    marcas.push(`<line x1="86" x2="${mayor ? 98 : 92}" y1="${y(v)}" y2="${y(v)}" class="t-marca${mayor ? " mayor" : ""}"/>`);
    if (mayor) marcas.push(`<text x="104" y="${y(v) + 4}" class="t-numero">${v}</text>`);
  }
  const franjas = BANDAS_TERMOMETRO.map((b) =>
    `<line x1="40" x2="40" y1="${y(b.hasta) + 1}" y2="${y(b.desde) - 1}" class="t-franja t-${b.clave}"/>`).join("");
  return `
    <svg class="termometro-svg ${clase}" viewBox="0 0 130 290" role="img"
      aria-label="${medido ? `Exposición ${esc(t.nivel)} de 100, ${esc(t.etiqueta)}` : esc(t.etiqueta)}">
      <defs><clipPath id="tubo-interior"><rect x="57" y="20" width="16" height="230" rx="8"/></clipPath></defs>
      ${franjas}
      <rect x="51" y="12" width="28" height="236" rx="14" class="t-vidrio"/>
      <circle cx="65" cy="254" r="28" class="t-vidrio"/>
      <rect x="57" y="20" width="16" height="230" rx="8" class="t-fondo"/>
      <g clip-path="url(#tubo-interior)">
        <rect x="57" y="${tope}" width="16" height="${252 - tope}" class="t-liquido"/>
      </g>
      <circle cx="65" cy="254" r="21" class="t-bulbo"/>
      <circle cx="58" cy="247" r="4" class="t-brillo"/>
      ${marcas.join("")}
    </svg>`;
}

function bloqueTermometro(d) {
  const t = d.equipo.termometro;
  if (!t) return "";
  const a = t.acciones;
  const total = a.inmediato + a.semanal + a.informativo;
  const kev = d.productos.reduce((n, p) => n + p.en_kev.length, 0);
  const leyenda = BANDAS_TERMOMETRO.map((b) =>
    `<span class="pildora mono${t.banda === b.clave ? " activa" : ""}"><span class="punto t-${b.clave}"></span>${b.desde}-${b.hasta} ${b.etiqueta}</span>`).join("");
  const lectura = t.medido
    ? `<div class="termometro-valor">${esc(t.nivel)}<span>/100</span></div>
       <span class="pildora termometro-banda t-${esc(t.banda)}"><span class="punto"></span>${esc(t.nivel === 0 ? "Sin acciones pendientes" : `Exposición ${EXPOSICION[t.banda] || t.etiqueta.toLowerCase()}`)}</span>
       <p class="termometro-texto">${total
         ? `Sale de ${esc(total)} ${total === 1 ? "acción abierta" : "acciones abiertas"} en este equipo. La peor prioridad fija el tramo y la cantidad lo sube dentro de él: con una sola acción inmediata ya marca alto.`
         : "Con lo que se pudo revisar no queda nada por hacer en este equipo."}</p>`
    : `<div class="termometro-valor sin">sin lectura</div>
       <span class="pildora termometro-banda"><span class="punto"></span>${esc(t.etiqueta)}</span>
       <p class="termometro-texto">${esc(t.motivo)} Un equipo sin revisar no se cuenta como sano.</p>`;
  const sinEvaluar = d.cobertura.sin_evaluar
    ? `<p class="termometro-nota">${esc(d.cobertura.sin_evaluar)} ${d.cobertura.sin_evaluar === 1 ? "programa sin evaluar no suma: está" : "programas sin evaluar no suman: están"} en "Sin revisar".</p>` : "";
  return `
    <div class="termometro">
      <div class="termometro-dibujo">${svgTermometro(t)}</div>
      <div class="termometro-cuerpo">
        <div class="termometro-titulo">Exposición del equipo</div>
        ${lectura}
        <div class="termometro-leyenda">${leyenda}</div>
        <div class="termometro-cifras">
          <div><strong>${esc(a.inmediato)}</strong><span>Inmediatas</span></div>
          <div><strong>${esc(a.semanal)}</strong><span>Semanales</span></div>
          <div><strong>${esc(a.informativo)}</strong><span>Informativas</span></div>
          <div><strong>${esc(kev)}</strong><span>CVE en KEV</span></div>
        </div>
        ${sinEvaluar}
      </div>
    </div>`;
}

function miniTermometro(t) {
  if (!t) return "";
  if (!t.medido) return `<span class="sin-dato">${esc(t.etiqueta.toLowerCase())}</span>`;
  return `<div class="mini-termometro t-${esc(t.banda)}" title="Exposición ${esc(t.nivel)} de 100: ${esc(t.etiqueta)}">
      <span class="mini-tubo"><span style="width:${Math.max(t.nivel, 2)}%"></span></span>
      <span class="mono">${esc(t.nivel)}</span></div>`;
}

function pildoraEstadoEquipo(e) {
  if (e.revocado) return '<span class="pildora p-caida"><span class="punto"></span>revocado</span>';
  if (e.pendiente) return '<span class="pildora p-semanal"><span class="punto"></span>por activar</span>';
  return "";
}

// Activación en la consola: hasta que TI escribe el código que mostró el instalador en la
// pantalla del equipo, su inventario no se cruza. El código prueba que alguien vio ese equipo.
function bloqueAprobacion(e) {
  if (e.revocado || !e.pendiente) return "";
  if (!puede("admin")) return '<div class="aprobacion-equipo"><p><strong>Por activar.</strong> Un administrador tiene que activar este equipo con su código antes de que su inventario entre al cruce.</p></div>';
  return `
    <div class="aprobacion-equipo">
      <p><strong>Por activar.</strong> El equipo se instaló y ya reporta, pero su inventario no
      entra al cruce hasta que escribas el código de activación que el instalador mostró en su
      pantalla. Si no reconoces el equipo, recházalo.</p>
      <form id="aprobar-equipo" class="aprobar">
        <input name="codigo" class="mono" placeholder="XXXX-XXXX" maxlength="9" autocomplete="off" required aria-label="Código de activación">
        <button type="submit">Activar equipo</button>
        <button type="button" class="boton-texto texto-peligro" id="rechazar-equipo">Rechazar</button>
        <span class="nota">como ${esc(SESION.nombre)}</span>
      </form>
    </div>`;
}

function conectarAprobacion(e) {
  const formulario = $("#aprobar-equipo");
  if (!formulario) return;
  const avisar = (error) => formulario.insertAdjacentHTML("beforeend", ` <span class="clave-error">${esc(error.message)}</span>`);
  formulario.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const boton = formulario.querySelector("button");
    const codigo = formulario.elements.codigo.value.trim().toUpperCase();
    if (!codigo) return;
    boton.disabled = true;
    try {
      const r = await api("/api/equipos/activar", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ codigo }),
      });
      if (r.equipo.id !== e.id) {
        // El código era de otro equipo pendiente: se activó ese, se abre su ficha.
        await abrirEquipo(r.equipo.id);
        refrescar();
        refrescarAuxiliares();
        return;
      }
      await abrirEquipo(e.id);
      refrescar();
      refrescarAuxiliares();
    } catch (error) {
      boton.disabled = false;
      avisar(error);
    }
  });
  $("#rechazar-equipo").addEventListener("click", async () => {
    if (!(await confirmar("Rechazar equipo", `Se borra ${e.nombre} y su credencial deja de servir.`, "Rechazar"))) return;
    try {
      await api(`/api/equipos/${encodeURIComponent(e.id)}`, { method: "DELETE" });
      equipoAbierto = null;
      $("#detalle-equipo").hidden = true;
      refrescarAuxiliares();
    } catch (error) {
      avisar(error);
    }
  });
}

// ---- tabla de equipos --------------------------------------------------------
// Buscador, sistema y chips filtran en el navegador sobre la última lista de la API. Cada
// fila se despliega con cuadros (exposición, sistema, postura, qué hacer); la ficha completa
// con comandos y activación sigue en el panel de abajo.

// Un equipo que no reporta en dos intervalos del agente (12 h por defecto) se da por fuera de línea.
const HORAS_FUERA_DE_LINEA = 24;
const COLUMNAS_POSTURA = [
  ["firewall", "Firewall"], ["antivirus", "Antimalware"],
  ["cifrado_disco", "Cifrado"], ["actualizaciones_automaticas", "Actualiz."],
];
const COLUMNAS_EQUIPOS = [
  ["nombre", "Equipo"], ["exposicion", "Exposición"], ["sistema", "Sistema"], ["estado", "Estado"],
  ["inmediato", "Inmed.", "num"], ["semanal", "Seman.", "num"],
  ...COLUMNAS_POSTURA.map(([clave, etiqueta]) => [`p_${clave}`, etiqueta, "centro"]),
];
const ORDEN_ESTADO = { fuera: 0, pendiente: 1, sin_reporte: 2, revocado: 3, linea: 4 };
const ORDEN_TRI = { no: 0, desconocido: 1, si: 2 };

const vistaEquipos = { lista: [], texto: "", sistema: "", chip: "todos", orden: null, desc: false, abierto: null };
const detallesEquipo = new Map();

function horasDesde(iso) {
  return iso ? (Date.now() - new Date(iso).getTime()) / 36e5 : null;
}

function fmtHace(iso) {
  const h = horasDesde(iso);
  if (h == null) return "nunca";
  if (h < 1) return `hace ${Math.max(1, Math.round(h * 60))} min`;
  if (h < 48) return `hace ${Math.round(h)} h`;
  return `hace ${Math.round(h / 24)} días`;
}

function estadoConexion(e) {
  if (e.revocado) return { clave: "revocado", texto: "Revocado", clase: "p-caida" };
  if (e.pendiente) return { clave: "pendiente", texto: "Por activar", clase: "p-semanal" };
  if (!e.ultimo_reporte) return { clave: "sin_reporte", texto: "Sin reporte", clase: "" };
  if (horasDesde(e.ultimo_reporte) > HORAS_FUERA_DE_LINEA) return { clave: "fuera", texto: "Fuera de línea", clase: "p-caida" };
  return { clave: "linea", texto: "En línea", clase: "p-ok" };
}

function compararVersiones(a, b) {
  const pa = String(a).split(/[^0-9]+/).filter(Boolean).map(Number);
  const pb = String(b).split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

function familiaSistema(e) {
  return e.so ? (e.so.familia || e.so.nombre || "otro") : "sin_reporte";
}
const FAMILIAS = { windows: "Windows", linux: "Linux", macos: "macOS", sin_reporte: "Sin reporte" };

function chipsEquipos(lista) {
  const versiones = lista.map((e) => e.agente_version).filter(Boolean);
  const ultima = versiones.length ? versiones.reduce((m, v) => (compararVersiones(v, m) > 0 ? v : m)) : null;
  const tri = (e, campo, valor) => e.postura && e.postura[campo] === valor;
  return [
    ["todos", "Todos", () => true],
    ["pendiente", "Por activar", (e) => e.pendiente && !e.revocado],
    ["inmediatas", "Con inmediatas", (e) => e.acciones.inmediato > 0],
    ["postura", "Falla de postura", (e) => e.postura && Object.values(e.postura).includes("no")],
    ["sin_cifrar", "Sin cifrar", (e) => tri(e, "cifrado_disco", "no")],
    ["antimalware", "Antimalware o firmas", (e) => tri(e, "antivirus", "no") || tri(e, "firmas_al_dia", "no")],
    ["fuera", "Fuera de línea", (e) => estadoConexion(e).clave === "fuera"],
    ["sin_reporte", "Sin reporte", (e) => !e.ultimo_reporte],
    ["agente_viejo", "Agente desactualizado", (e) => ultima && e.agente_version && compararVersiones(e.agente_version, ultima) < 0],
  ];
}

function claveOrden(e, clave) {
  if (clave === "nombre") return e.nombre.toLowerCase();
  if (clave === "exposicion") return e.termometro && e.termometro.medido ? e.termometro.nivel : -1;
  if (clave === "sistema") return e.so ? `${e.so.nombre} ${e.so.version || ""}`.toLowerCase() : "~";
  if (clave === "estado") return ORDEN_ESTADO[estadoConexion(e).clave];
  if (clave === "inmediato" || clave === "semanal") return e.acciones[clave];
  if (clave.startsWith("p_")) return ORDEN_TRI[(e.postura || {})[clave.slice(2)] || "desconocido"];
  return 0;
}

function triPostura(valor) {
  if (valor === "si") return '<span class="sn sn-si" title="Bien">Sí</span>';
  if (valor === "no") return '<span class="sn sn-no" title="Falla">No</span>';
  return '<span class="sn sn-sd" title="No se pudo revisar">Sin dato</span>';
}

function pintarEquipos(datos) {
  const hay = datos.disponible && datos.equipos.length > 0;
  const vacio = $("#equipos-vacio");
  $("#equipos").closest(".tabla-envoltura").hidden = !hay;
  $("#equipos-controles").hidden = !hay;
  $("#total-equipos").textContent = hay
    ? (datos.pendientes ? `${datos.total}, ${datos.pendientes} por activar` : datos.total) : "";
  $("#nav-equipos").textContent = hay ? datos.total : "";
  vacio.hidden = hay;
  if (!hay) {
    vacio.innerHTML = !datos.disponible
      ? `<p>${esc(datos.motivo || "Los equipos con agente necesitan una base conectada.")}</p>`
      : (puede("admin")
        ? '<p>Todavía no hay equipos con agente.</p><p class="nota">El agente levanta el software, el sistema y la postura de cada PC y lo envía al radar. Instálalo con "Agregar equipo".</p>'
        : '<p>Todavía no hay equipos con agente.</p><p class="nota">Un administrador los agrega desde esta sección.</p>');
    return;
  }
  vistaEquipos.lista = datos.equipos;
  // El selector de sistema se arma con las familias que hay en la flota.
  const select = $("#equipos-sistema");
  const familias = [...new Set(datos.equipos.map(familiaSistema))].sort();
  const firmaFamilias = familias.join("|");
  if (select.dataset.firma !== firmaFamilias) {
    select.dataset.firma = firmaFamilias;
    select.innerHTML = '<option value="">Todos los sistemas</option>' + familias.map((f) =>
      `<option value="${esc(f)}"${f === vistaEquipos.sistema ? " selected" : ""}>${esc(FAMILIAS[f] || f)}</option>`).join("");
  }
  repintarEquipos();
  if (vistaEquipos.abierto) cargarDetalleAbierto();
}

function repintarEquipos() {
  const v = vistaEquipos;
  const texto = v.texto.trim().toLowerCase();
  const base = v.lista.filter((e) => {
    if (v.sistema && familiaSistema(e) !== v.sistema) return false;
    if (!texto) return true;
    const so = e.so || {};
    return [e.nombre, so.nombre, so.version, so.build, so.kernel, so.distro, e.agente_version]
      .filter(Boolean).join(" ").toLowerCase().includes(texto);
  });
  const chips = chipsEquipos(v.lista);
  if (!chips.some(([clave]) => clave === v.chip)) v.chip = "todos";
  $("#equipos-chips").innerHTML = chips.map(([clave, etiqueta, prueba]) => {
    const n = base.filter(prueba).length;
    return `<button type="button" class="chip${clave === v.chip ? " activo" : ""}${n ? "" : " vacio-chip"}" data-chip="${clave}" aria-pressed="${clave === v.chip}">${esc(etiqueta)} <span class="chip-n">${n}</span></button>`;
  }).join("");
  const prueba = chips.find(([clave]) => clave === v.chip)[2];
  let lista = base.filter(prueba);
  if (v.orden) {
    lista = [...lista].sort((a, b) => {
      const x = claveOrden(a, v.orden), y = claveOrden(b, v.orden);
      const r = x < y ? -1 : x > y ? 1 : 0;
      return v.desc ? -r : r;
    });
  }

  $("#equipos-cabeza").innerHTML = COLUMNAS_EQUIPOS.map(([clave, etiqueta, clase]) => {
    const activa = v.orden === clave;
    const orden = activa ? (v.desc ? "descending" : "ascending") : "none";
    return `<th class="${clase || ""}" aria-sort="${orden}"><button type="button" class="orden${activa ? " activa" : ""}" data-orden="${clave}">${esc(etiqueta)}<span class="flechita" aria-hidden="true">${activa && v.desc ? "▼" : "▲"}</span></button></th>`;
  }).join("");

  $("#equipos tbody").innerHTML = lista.map((e) => {
    const est = estadoConexion(e);
    const so = e.so;
    const abierto = e.id === v.abierto;
    const sub = so ? [so.version, so.build || so.kernel].filter(Boolean).join(" · ") : "";
    const postura = e.postura || {};
    return `
    <tr class="clic fila-equipo${abierto ? " abierta" : ""}${marcarCambios(firmasEquipos, e.id, [e.pendiente, e.revocado, e.ultimo_reporte, e.acciones.inmediato, e.acciones.semanal].join("|"), true)}" data-equipo="${esc(e.id)}" tabindex="0" aria-expanded="${abierto}">
      <td class="equipo-celda"><div class="equipo-nombre"><span class="chevron" aria-hidden="true">›</span><span class="mono">${esc(e.nombre)}</span></div>
        <div class="sub">inscrito ${esc(fmtFecha(e.inscrito, true))}</div></td>
      <td>${miniTermometro(e.termometro)}${e.peor_prioridad ? `<div class="sub">${esc(PRIORIDADES[e.peor_prioridad] || e.peor_prioridad)}</div>` : ""}</td>
      <td>${so ? `<div>${esc(so.nombre)}</div><div class="sub mono">${esc(sub)}</div>` : '<span class="sin-dato">sin reporte</span>'}</td>
      <td><div class="estado-conexion ${est.clase}"><span class="punto"></span>${esc(est.texto)}</div>
        <div class="sub">${e.agente_version ? `agente ${esc(e.agente_version)} · ` : ""}${esc(fmtHace(e.ultimo_reporte))}</div></td>
      <td class="num">${e.acciones.inmediato ? `<span class="kev-n">${esc(e.acciones.inmediato)}</span>` : '<span class="cero">0</span>'}</td>
      <td class="num">${e.acciones.semanal ? esc(e.acciones.semanal) : '<span class="cero">0</span>'}</td>
      ${COLUMNAS_POSTURA.map(([clave]) => `<td class="centro">${e.postura ? triPostura(postura[clave]) : '<span class="sn sn-sd">Sin dato</span>'}</td>`).join("")}
    </tr>${abierto ? `<tr class="fila-desplegada"><td colspan="${COLUMNAS_EQUIPOS.length}">${cuerpoDesplegado(e)}</td></tr>` : ""}`;
  }).join("") || `<tr><td colspan="${COLUMNAS_EQUIPOS.length}" class="vacio">Ningún equipo cumple el filtro.</td></tr>`;
  firmasEquipos.primera = false;

  const totales = COLUMNAS_POSTURA.map(([clave]) => {
    const c = { si: 0, no: 0, sd: 0 };
    lista.forEach((e) => {
      const valor = (e.postura || {})[clave];
      c[valor === "si" ? "si" : valor === "no" ? "no" : "sd"] += 1;
    });
    return `<td class="centro"><span class="total-si">${c.si} sí</span> · <span class="total-no">${c.no} no</span><br><span class="total-sd">${c.sd} s/d</span></td>`;
  }).join("");
  $("#equipos tfoot").innerHTML = `<tr><td colspan="${COLUMNAS_EQUIPOS.length - COLUMNAS_POSTURA.length}">${lista.length} ${lista.length === 1 ? "equipo" : "equipos"}${lista.length !== v.lista.length ? ` de ${v.lista.length}` : ""}</td>${totales}</tr>`;
}

function fmtFecha(iso, corta = false) {
  if (!iso) return "sin fecha";
  return new Date(iso).toLocaleDateString("es", corta ? { day: "numeric", month: "short" } : { day: "numeric", month: "short", year: "numeric" });
}

function filasDato(pares) {
  const filas = pares.filter(([, valor]) => valor != null && valor !== "").map(([nombre, valor]) =>
    `<li><span>${esc(nombre)}</span><span class="mono">${esc(valor)}</span></li>`).join("");
  return filas ? `<ul class="datos-lista">${filas}</ul>` : '<p class="vacio">El equipo todavía no ha reportado.</p>';
}

// Cuadros de la fila desplegada. Lo de la lista se pinta al tiro; hardware y acciones
// llegan con el detalle (GET /api/equipos/{id}), que se pide al abrir y se guarda.
function cuerpoDesplegado(e) {
  const d = detallesEquipo.get(e.id);
  const t = e.termometro || {};
  const a = e.acciones;
  const postura = e.postura || {};
  const fallas = Object.values(postura).filter((x) => x === "no").length;
  const so = e.so || {};
  const hw = d && d.equipo.hardware ? d.equipo.hardware : {};
  const cargando = '<p class="vacio">Cargando...</p>';

  const exposicion = `
    <div class="cuadro">
      <div class="cuadro-cabeza"><h3>Exposición</h3>${t.medido ? `<span class="pildora termometro-banda t-${esc(t.banda)}"><span class="punto"></span>${esc(t.etiqueta)}</span>` : ""}</div>
      ${t.medido
        ? `<div class="cuadro-cifra t-${esc(t.banda)}">${esc(t.nivel)}<span>/100</span></div>`
        : `<p class="nota">${esc(t.motivo || t.etiqueta || "Sin lectura.")} Un equipo sin revisar no se cuenta como sano.</p>`}
      ${filasDato([["Inmediatas", a.inmediato], ["Semanales", a.semanal], ["Informativas", a.informativo],
        ["CVE en KEV", d ? d.productos.reduce((n, p) => n + p.en_kev.length, 0) : null]])}
      ${e.pendiente && !e.revocado ? '<p class="aviso-cuadro">Por activar: su inventario no entra al cruce hasta que un administrador escriba el código en la ficha.</p>' : ""}
    </div>`;

  const sistema = `
    <div class="cuadro">
      <div class="cuadro-cabeza"><h3>Sistema y hardware</h3></div>
      ${filasDato([
        ["Sistema", so.nombre], ["Versión", so.version], ["Build", so.build], ["Kernel", so.kernel],
        ["Arquitectura", so.arquitectura], ["Edición", so.edicion],
        ["Equipo", [hw.fabricante, hw.modelo].filter(Boolean).join(" ") || null],
        ["Procesador", hw.cpu], ["RAM", hw.ram_gb != null ? `${hw.ram_gb} GB` : null],
        ["TPM", hw.tpm], ["BIOS", hw.bios],
        ["Agente", e.agente_version], ["Último reporte", e.ultimo_reporte ? fmtHora(e.ultimo_reporte) : null],
        ["Aprobado por", e.aprobado_por],
      ])}
      ${d ? "" : cargando}
    </div>`;

  const posturaCuadro = `
    <div class="cuadro">
      <div class="cuadro-cabeza"><h3>Postura</h3>${e.postura ? (fallas ? `<span class="sn sn-no">${fallas} ${fallas === 1 ? "falla" : "fallas"}</span>` : '<span class="sn sn-si">Sin fallas</span>') : ""}</div>
      ${e.postura
        ? `<ul class="datos-lista">${Object.entries(POSTURA).map(([clave, etiqueta]) =>
            `<li><span>${esc(etiqueta)}</span>${triPostura(postura[clave])}</li>`).join("")}</ul>`
        : '<p class="vacio">El equipo todavía no ha reportado su postura.</p>'}
    </div>`;

  let quehacer = cargando;
  if (d) {
    const items = [
      ...d.productos.map((p) => ({ prioridad: p.prioridad, titulo: p.producto, extra: `${p.n_cves} CVE` })),
      ...d.hallazgos_equipo.map((h) => ({ prioridad: h.prioridad, titulo: h.titulo, extra: TIPOS_EQUIPO[h.tipo] || h.tipo })),
    ];
    quehacer = items.length
      ? `<ul class="quehacer">${items.slice(0, 6).map((i) =>
          `<li>${pildoraPrioridad(i.prioridad)}<span class="quehacer-titulo">${esc(i.titulo)}</span><span class="sub">${esc(i.extra)}</span></li>`).join("")}</ul>
         ${items.length > 6 ? `<p class="nota">y ${items.length - 6} más en la ficha.</p>` : ""}`
      : `<p class="vacio">${e.pendiente ? "Se cruza cuando el equipo esté activado." : "Nada que hacer con lo que se pudo revisar."}</p>`;
  }
  const accionesCuadro = `
    <div class="cuadro">
      <div class="cuadro-cabeza"><h3>Qué hacer</h3>${d ? `<span class="pildora mono">${d.productos.length + d.hallazgos_equipo.length}</span>` : ""}</div>
      ${quehacer}
    </div>`;

  return `
    <div class="desplegado${vistaEquipos.animar ? " entrando" : ""}">
      <div class="cuadros">${exposicion}${sistema}${posturaCuadro}${accionesCuadro}</div>
      <div class="desplegado-pie"><button type="button" class="boton-secundario" data-ficha="${esc(e.id)}">Ver ficha completa</button></div>
    </div>`;
}

async function alternarEquipo(id) {
  vistaEquipos.abierto = vistaEquipos.abierto === id ? null : id;
  vistaEquipos.animar = true;
  repintarEquipos();
  vistaEquipos.animar = false;
  if (vistaEquipos.abierto) await cargarDetalleAbierto();
}

// Pide el detalle del equipo desplegado si no está o si el equipo volvió a reportar.
async function cargarDetalleAbierto() {
  const id = vistaEquipos.abierto;
  const e = vistaEquipos.lista.find((x) => x.id === id);
  const previo = detallesEquipo.get(id);
  if (previo && previo.equipo.ultimo_reporte === (e && e.ultimo_reporte)) return;
  try {
    detallesEquipo.set(id, await api(`/api/equipos/${encodeURIComponent(id)}`));
  } catch {
    detallesEquipo.delete(id);
  }
  if (vistaEquipos.abierto === id) repintarEquipos();
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
  const vacio = e.pendiente
    ? "Se cruza cuando el equipo esté aprobado."
    : "Nada que hacer con lo que se pudo revisar.";
  $("#detalle-equipo-cuerpo").innerHTML = `
    ${bloqueAprobacion(e)}
    ${bloqueTermometro(d)}
    <div class="datos-clave">${pildoraPrioridad(e.peor_prioridad)}${pildoraEstadoEquipo(e)}${pildorasPostura(e.postura)}
      ${e.revocado ? '<span class="pildora p-caida">revocado</span>' : (puede("admin") ? '<button type="button" class="boton-texto" id="revocar-equipo">Revocar credencial</button>' : "")}
      ${puede("admin") ? '<button type="button" class="boton-texto texto-peligro" id="retirar-equipo">Retirar equipo</button>' : ""}</div>
    <div class="detalle-rejilla">
      <div class="bloque">
        <h3>Qué hacer en este equipo</h3>
        <ul class="acciones">${acciones || `<li class="vacio">${esc(vacio)}</li>`}</ul>
      </div>
      <div class="bloque">
        <h3>Ficha</h3><ul class="cobertura-lista">${ficha || '<li class="vacio">El equipo todavía no ha reportado.</li>'}</ul>
        <h3 style="margin-top:16px">Sin revisar</h3>
        <ul class="cobertura-lista">${sinRevisar.map((s) => `<li><span>${esc(s)}</span></li>`).join("") || '<li class="vacio">Todo se pudo revisar.</li>'}</ul>
      </div>
    </div>`;
  conectarAprobacion(e);
  const revocar = $("#revocar-equipo");
  if (revocar) {
    revocar.addEventListener("click", async () => {
      const ok = await confirmar("Revocar credencial",
        `${e.nombre} no podrá enviar más reportes. Sus datos quedan para la auditoría. Para volver a inscribirlo hay que retirarlo.`,
        "Revocar");
      if (!ok) return;
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
  const retirar = $("#retirar-equipo");
  if (retirar) {
    retirar.addEventListener("click", async () => {
      const ok = await confirmar("Retirar equipo",
        `Se borran ${e.nombre} y todo lo que reportó, y el inventario se vuelve a cruzar. Úsalo al desinstalar el agente.`,
        "Retirar equipo");
      if (!ok) return;
      retirar.disabled = true;
      try {
        await api(`/api/equipos/${encodeURIComponent(e.id)}`, { method: "DELETE" });
        equipoAbierto = null;
        $("#detalle-equipo").hidden = true;
        refrescarAuxiliares();
      } catch (error) {
        retirar.disabled = false;
        retirar.insertAdjacentHTML("afterend", ` <span class="clave-error">${esc(error.message)}</span>`);
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
    pintarResumen(resumen);
    pintarProductos(productos);
    if (!editandoEstado()) pintarHallazgos(hallazgos);
  } catch (error) {
    if (error instanceof SinClave) return;
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

function clicEnEquipos(e) {
  const ficha = e.target.closest("[data-ficha]");
  if (ficha) {
    if (e.type === "keydown") return;
    abrirEquipo(ficha.dataset.ficha);
    $("#detalle-equipo").scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const orden = e.target.closest("[data-orden]");
  if (orden) {
    if (e.type === "keydown") return;
    const clave = orden.dataset.orden;
    if (vistaEquipos.orden === clave) {
      // Tercer clic vuelve al orden de la API (más expuesto primero).
      if (vistaEquipos.desc) vistaEquipos.orden = null;
      vistaEquipos.desc = !vistaEquipos.desc;
    } else {
      vistaEquipos.orden = clave;
      vistaEquipos.desc = false;
    }
    repintarEquipos();
    return;
  }
  const fila = e.target.closest("tr[data-equipo]");
  if (!fila) return;
  if (e.type === "keydown" && e.key !== "Enter" && e.key !== " ") return;
  e.preventDefault();
  alternarEquipo(fila.dataset.equipo);
}
$("#equipos").addEventListener("click", clicEnEquipos);
$("#equipos").addEventListener("keydown", clicEnEquipos);
$("#equipos-buscar").addEventListener("input", (e) => { vistaEquipos.texto = e.target.value; repintarEquipos(); });
$("#equipos-sistema").addEventListener("change", (e) => { vistaEquipos.sistema = e.target.value; repintarEquipos(); });
$("#equipos-chips").addEventListener("click", (e) => {
  const chip = e.target.closest("[data-chip]");
  if (!chip) return;
  vistaEquipos.chip = chip.dataset.chip;
  repintarEquipos();
});

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
    salida.innerHTML = `<span class="error">${esc(error.message)}</span>`;
  } finally {
    boton.disabled = false;
  }
});

function iniciarCiclo() {
  refrescar();
  refrescarAuxiliares();
  setInterval(refrescar, INTERVALO_MS);
  setInterval(refrescarAuxiliares, INTERVALO_MS * 2);
}
