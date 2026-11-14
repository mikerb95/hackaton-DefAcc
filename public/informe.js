// Informe de remediación de un plan de parcheo (docs/plan-parcheo.md, sección 6).
//
// Todo el texto lo arma este código a partir de GET /api/parcheo/{id}/informe: no participa
// ningún modelo. Lo que viene del equipo (salidas de comandos, versiones, motivos) es texto
// no confiable: el servidor lo limpia y aquí se escapa siempre antes de pintarlo.
"use strict";

const $ = (sel) => document.querySelector(sel);

function esc(valor) {
  return String(valor ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

const GENERAL = {
  exito: ["ok", "Éxito", "Todas las acciones aprobadas quedaron aplicadas o ya estaban al día."],
  parcial: ["parcial", "Éxito parcial", "Algunas acciones no se aplicaron. En esas acciones el equipo quedó en su estado previo."],
  requiere_atencion: ["atencion", "Requiere atención", "Al menos una acción quedó a medias o se interrumpió. Hay que revisar el equipo."],
  rechazado: ["atencion", "Rechazado por el agente", "El agente no ejecutó el plan. El equipo no se tocó."],
  pendiente: ["neutro", "Pendiente", "El equipo todavía no envía el resultado del plan."],
  cancelado: ["neutro", "Cancelado", "El plan se canceló antes de recibir un resultado."],
};
const RESULTADO = {
  aplicado: "ok", ya_al_dia: "ok", revertido: "parcial", sin_cambios: "parcial",
  omitido: "neutro", rechazado: "atencion", fallido_sin_revertir: "atencion", interrumpido: "atencion",
};
const CORTO = {
  aplicado: "Aplicado", ya_al_dia: "Ya al día", revertido: "Revertido", sin_cambios: "Sin cambios",
  omitido: "Omitido", fallido_sin_revertir: "Falló sin revertir", interrumpido: "Interrumpido", rechazado: "Rechazado",
};
const VERIFICACION = {
  confirmada: ["ok", "Confirmada por el radar"],
  parcial: ["parcial", "Parcial"],
  sin_confirmar: ["atencion", "Sin confirmar"],
  pendiente: ["neutro", "Pendiente de inventario"],
  no_aplica: ["neutro", "No aplica"],
};
const TIPOS = { aplicacion: "Aplicación", paquetes: "Paquetes del sistema", postura: "Postura", so: "Sistema operativo" };
const PRIORIDAD = { inmediato: "Inmediato", semanal: "Semanal", informativo: "Informativo" };
const POSTURA = {
  firewall: "Firewall", antivirus: "Antivirus / control de acceso", firmas_al_dia: "Firmas al día",
  cifrado_disco: "Cifrado de disco", secure_boot: "Secure Boot", actualizaciones_automaticas: "Actualizaciones automáticas",
};

function fecha(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return esc(iso);
  return d.toLocaleString("es", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function duracion(inicio, fin) {
  if (!inicio || !fin) return "-";
  const s = Math.max(0, (new Date(fin) - new Date(inicio)) / 1000);
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}

const marca = (clase, texto) => `<span class="marca marca-${clase}"><span class="marca-punto"></span>${esc(texto)}</span>`;
const plural = (n, uno, varios) => `${n} ${n === 1 ? uno : varios}`;

function medido(m) {
  const entradas = Object.entries(m || {}).filter(([, v]) => v !== null && v !== "");
  if (!entradas.length) return '<span class="tenue">-</span>';
  return entradas.map(([k, v]) => `<span class="par"><span class="tenue">${esc(k)}</span> ${esc(v)}</span>`).join(" ");
}

// ---- secciones ------------------------------------------------------------------

function resumenEjecutivo(d) {
  const c = d.conteo;
  const total = d.acciones.length;
  const [, , explicacion] = GENERAL[d.estado_general] || GENERAL.pendiente;
  const partes = [];
  if (d.ejecucion && d.ejecucion.estado !== "rechazado") {
    partes.push(`De ${plural(total, "acción aprobada", "acciones aprobadas")}, ${plural(c.aplicado, "se aplicó y verificó", "se aplicaron y verificaron")} en el equipo` +
      (c.ya_al_dia ? ` y ${plural(c.ya_al_dia, "ya estaba al día", "ya estaban al día")}` : "") + ".");
    const otras = [];
    if (c.revertido) otras.push(`${plural(c.revertido, "se revirtió", "se revirtieron")} al estado anterior`);
    if (c.sin_cambios) otras.push(`${plural(c.sin_cambios, "falló", "fallaron")} sin cambiar nada`);
    if (c.omitido) otras.push(`${plural(c.omitido, "se omitió", "se omitieron")} por una condición de seguridad`);
    if (c.fallido_sin_revertir) otras.push(`${plural(c.fallido_sin_revertir, "falló", "fallaron")} sin poder revertirse`);
    if (c.interrumpido) otras.push(`${plural(c.interrumpido, "quedó interrumpida", "quedaron interrumpidas")}`);
    if (otras.length) partes.push(`Del resto, ${otras.join(", ")}.`);
  }
  const e = d.exposicion;
  const verificado = d.verificado_por_radar && e.cves_siguen;
  if (verificado && e.cves_en_plan) {
    const cerradas = e.cves_en_plan - e.cves_siguen.length;
    partes.push(`El inventario que envió el equipo después del plan ya no muestra ${cerradas} de las ${e.cves_en_plan} CVE del plan` +
      (e.kev_en_plan ? ` (${e.kev_en_plan - e.kev_siguen.length} de ${e.kev_en_plan} con explotación conocida según KEV)` : "") + ".");
  } else if (d.ejecucion && d.ejecucion.estado !== "rechazado") {
    partes.push("La verificación independiente del radar llega con el próximo inventario del equipo.");
  }
  if (d.ejecucion && d.ejecucion.reinicio_pendiente) {
    partes.push("El equipo tiene un reinicio pendiente. El agente no reinicia: hay que hacerlo en una ventana acordada con quien lo usa.");
  }
  if (d.ejecucion && d.ejecucion.estado === "rechazado") partes.push(`Motivo: ${d.ejecucion.motivo}.`);

  const cerradas = verificado ? e.cves_en_plan - e.cves_siguen.length : null;
  const kevCerradas = verificado ? e.kev_en_plan - e.kev_siguen.length : null;
  const atencion = c.fallido_sin_revertir + c.interrumpido;
  const cifra = (valor, de, etiqueta, clase = "") => `
    <div class="cifra ${clase}"><div class="cifra-valor">${valor ?? "-"}${de != null ? `<span class="cifra-de"> / ${de}</span>` : ""}</div>
    <div class="cifra-etiqueta">${esc(etiqueta)}</div></div>`;
  return `
    <section class="seccion">
      <h2><span class="num">1</span>Resumen ejecutivo</h2>
      <p class="lead">${esc(explicacion)}</p>
      <div class="cifras">
        ${cifra(d.ejecucion ? c.aplicado + c.ya_al_dia : null, total, "acciones resueltas")}
        ${cifra(cerradas, e.cves_en_plan, "CVE cerradas según el radar")}
        ${cifra(kevCerradas, e.kev_en_plan, "CVE de KEV cerradas", e.kev_en_plan ? "kev" : "")}
        ${cifra(d.ejecucion ? atencion : null, null, "requieren intervención", atencion ? "alerta" : "")}
      </div>
      <p>${partes.map(esc).join(" ")}</p>
    </section>`;
}

function exposicion(d) {
  const antes = d.exposicion.antes || {};
  const ahora = d.exposicion.ahora || {};
  const aa = antes.acciones_abiertas || {};
  const ah = ahora.acciones_abiertas || {};
  const fila = (etiqueta, a, b) => {
    const mejora = typeof a === "number" && typeof b === "number" && b < a;
    return `<tr><th scope="row">${esc(etiqueta)}</th><td class="num">${esc(a ?? "-")}</td><td class="num${mejora ? " mejora" : ""}">${esc(b ?? "-")}</td></tr>`;
  };
  const posturas = Object.keys(POSTURA).filter((k) => (antes.postura || {})[k] !== (ahora.postura || {})[k]);
  return `
    <section class="seccion">
      <h2><span class="num">2</span>Exposición antes y después</h2>
      <p class="tenue">"Al aprobar" es la foto del equipo cuando se firmó el plan. "Último cruce" es lo que ve el radar con el inventario más reciente del equipo (${fecha(ahora.ultimo_reporte)}).</p>
      <table class="tabla tabla-comparar">
        <thead><tr><th></th><th class="num">Al aprobar</th><th class="num">Último cruce</th></tr></thead>
        <tbody>
          ${fila("Acciones de prioridad inmediata", aa.inmediato, ah.inmediato)}
          ${fila("Acciones de prioridad semanal", aa.semanal, ah.semanal)}
          ${fila("Acciones informativas", aa.informativo, ah.informativo)}
          ${fila("Peor prioridad", PRIORIDAD[antes.peor_prioridad] || "ninguna", PRIORIDAD[ahora.peor_prioridad] || "ninguna")}
          ${posturas.map((k) => fila(POSTURA[k], (antes.postura || {})[k], (ahora.postura || {})[k])).join("")}
        </tbody>
      </table>
    </section>`;
}

function detalle(d) {
  const filas = d.acciones.map((a, i) => {
    const p = a.plan;
    const r = a.resultado;
    const v = a.verificacion;
    const kev = (p.en_kev || []).length;
    const [claseV, textoV] = v ? VERIFICACION[v.estado] || ["neutro", v.estado] : ["neutro", "-"];
    return `
      <tr>
        <td class="num">${i + 1}</td>
        <td><div class="accion-titulo">${esc(p.titulo)}</div>
          <div class="tenue">${esc(TIPOS[p.tipo] || p.tipo)} · ${esc(PRIORIDAD[p.prioridad] || "sin prioridad")}</div>
          ${r && r.motivo ? `<div class="motivo">${esc(r.motivo)}</div>` : ""}</td>
        <td class="medido">${r ? `${medido(r.antes)}<div class="flecha">→</div>${medido(r.despues)}` : '<span class="tenue">-</span>'}</td>
        <td class="num">${(p.cves || []).length}${kev ? `<div class="kev">${kev} KEV</div>` : ""}</td>
        <td>${r ? marca(RESULTADO[r.estado] || "neutro", CORTO[r.estado] || r.estado) : marca("neutro", "Sin resultado")}
          ${r && r.reinicio_pendiente ? '<div class="tenue">reinicio pendiente</div>' : ""}
          ${r && r.reversible === false ? '<div class="tenue">no reversible</div>' : ""}</td>
        <td>${v ? `${marca(claseV, textoV)}<div class="tenue">${esc(v.texto)}</div>` : '<span class="tenue">-</span>'}</td>
        <td class="num">${r ? duracion(r.inicio, r.fin) : "-"}</td>
      </tr>`;
  }).join("");
  return `
    <section class="seccion">
      <h2><span class="num">3</span>Detalle por acción</h2>
      <div class="tabla-envoltura">
      <table class="tabla tabla-acciones">
        <thead><tr><th class="num">#</th><th>Acción</th><th>Antes y después</th><th class="num">CVE</th><th>Resultado en el equipo</th><th>Verificación del radar</th><th class="num">Duración</th></tr></thead>
        <tbody>${filas}</tbody>
      </table>
      </div>
      <p class="tenue">"Resultado en el equipo" es lo que midió el agente después de cada acción. "Verificación del radar" compara el inventario que el equipo envió después con las CVE de la acción.</p>
    </section>`;
}

function pendientes(d) {
  const items = [];
  for (const a of d.acciones) {
    const r = a.resultado;
    if (r && ["fallido_sin_revertir", "interrumpido"].includes(r.estado)) {
      items.push(["atencion", `${a.plan.titulo}: ${CORTO[r.estado]}. ${r.motivo || ""}. Revisar el equipo manualmente.`]);
    } else if (r && ["revertido", "sin_cambios", "omitido"].includes(r.estado)) {
      items.push(["parcial", `${a.plan.titulo}: ${CORTO[r.estado]}. ${r.motivo || ""}`]);
    } else if (a.verificacion && ["sin_confirmar", "parcial"].includes(a.verificacion.estado)) {
      items.push(["parcial", `${a.plan.titulo}: el radar todavía ve CVE abiertas (${(a.verificacion.siguen || []).slice(0, 5).join(", ")}). ${a.verificacion.texto}`]);
    }
  }
  if (d.ejecucion && d.ejecucion.reinicio_pendiente) items.unshift(["atencion", "Reiniciar el equipo en una ventana acordada: hay cambios que se completan al reiniciar."]);
  for (const m of d.manuales || []) items.push(["neutro", `${m.titulo}: ${m.motivo}`]);
  if (!items.length) return "";
  return `
    <section class="seccion">
      <h2><span class="num">4</span>Pendientes y próximos pasos</h2>
      <ul class="pendientes">${items.map(([clase, texto]) => `<li><span class="marca-punto marca-${clase}"></span>${esc(texto)}</li>`).join("")}</ul>
    </section>`;
}

function anexos(d) {
  const eventos = [
    [d.aprobacion.creado, `Plan aprobado y firmado por ${d.aprobacion.por}`],
    [d.entrega.entregado, `Plan entregado al equipo (${plural(d.entrega.entregas, "entrega", "entregas")})`],
  ];
  if (d.ejecucion) {
    eventos.push([d.ejecucion.inicio, "El agente verificó la firma y empezó (reloj del equipo)"]);
    for (const a of d.acciones) if (a.resultado) eventos.push([a.resultado.fin, `${a.plan.titulo}: ${CORTO[a.resultado.estado]}`]);
    eventos.push([d.ejecucion.fin, "Fin de la ejecución (reloj del equipo)"]);
  }
  eventos.push([d.entrega.recibido, "Resultado recibido por el radar"]);
  const cronologia = eventos.filter(([f]) => f).map(([f, t]) => `<tr><td class="mono">${fecha(f)}</td><td>${esc(t)}</td></tr>`).join("");
  const evidencia = d.acciones.filter((a) => a.resultado && a.resultado.pasos && a.resultado.pasos.length).map((a) => `
    <div class="evidencia">
      <h4>${esc(a.plan.titulo)}</h4>
      ${a.resultado.pasos.map((p) => `
        <div class="paso">
          <div class="paso-cabeza"><code>${esc(p.orden.join(" "))}</code>
            <span class="tenue">código ${esc(p.codigo ?? "sin terminar")} · ${esc(p.duracion ?? "-")} s</span></div>
          ${p.salida ? `<pre>${esc(p.salida)}</pre>` : ""}
        </div>`).join("")}
    </div>`).join("");
  const punto = d.ejecucion && d.ejecucion.punto_restauracion;
  return `
    <section class="seccion anexo">
      <h2><span class="num">A</span>Cronología</h2>
      <table class="tabla tabla-cronologia"><tbody>${cronologia}</tbody></table>
    </section>
    <section class="seccion anexo">
      <h2><span class="num">B</span>Integridad del plan</h2>
      <dl class="datos">
        <dt>Identificador del plan</dt><dd class="mono">${esc(d.plan_id)}</dd>
        <dt>SHA-256 del plan firmado</dt><dd class="mono partir">${esc(d.aprobacion.huella_plan)}</dd>
        <dt>Clave de aprobación</dt><dd><span class="mono">${esc(d.aprobacion.clave)}</span>${d.aprobacion.clave_nombre ? ` (${esc(d.aprobacion.clave_nombre)})` : ""}</dd>
        <dt>Huella de la firma</dt><dd class="mono">${esc(d.aprobacion.huella_firma)}</dd>
        <dt>Vigencia</dt><dd>${fecha(d.aprobacion.emitido)} a ${fecha(d.aprobacion.vence)}</dd>
        ${punto ? `<dt>Punto de restauración</dt><dd>${punto.creado ? "Sí" : "No"}. ${esc(punto.detalle)}</dd>` : ""}
        ${d.aprobacion.cancelado_por ? `<dt>Cancelado por</dt><dd>${esc(d.aprobacion.cancelado_por)}</dd>` : ""}
      </dl>
      <p class="tenue">El agente solo ejecuta planes firmados con una clave de aprobación fijada en el equipo al instalarlo, vigentes, para ese equipo, no ejecutados antes y con acciones de su catálogo cerrado. La clave privada no está en el servidor.</p>
    </section>
    ${evidencia ? `<section class="seccion anexo"><h2><span class="num">C</span>Evidencia técnica</h2>
      <p class="tenue">Comandos que ejecutó el agente (sin shell), con su código de salida y el final de su salida. Es texto del equipo, limpiado por el radar.</p>${evidencia}</section>` : ""}`;
}

function pintar(d) {
  const [clase, texto] = GENERAL[d.estado_general] || GENERAL.pendiente;
  const so = d.equipo.so ? [d.equipo.so.nombre, d.equipo.so.version, d.equipo.so.build || d.equipo.so.kernel].filter(Boolean).join(" · ") : "sin dato";
  document.title = `Informe de remediación · ${d.equipo.nombre}`;
  $("#hoja").innerHTML = `
    <header class="portada">
      <div class="portada-marca"><span class="logo-punto"></span>Radar de vulnerabilidades</div>
      <h1>Informe de remediación</h1>
      <div class="portada-equipo"><span class="mono">${esc(d.equipo.nombre)}</span> ${marca(clase, texto)}</div>
      <dl class="datos datos-portada">
        <dt>Sistema</dt><dd>${esc(so)}</dd>
        <dt>Aprobado por</dt><dd>${esc(d.aprobacion.por)} · ${fecha(d.aprobacion.creado)}</dd>
        <dt>Ejecución</dt><dd>${d.ejecucion ? `${fecha(d.ejecucion.inicio)} · ${duracion(d.ejecucion.inicio, d.ejecucion.fin)}` : "sin resultado todavía"}</dd>
        <dt>Agente</dt><dd>${d.ejecucion ? esc(d.ejecucion.agente_version || "-") : "-"}</dd>
        <dt>Plan</dt><dd class="mono">${esc(d.plan_id)}</dd>
        <dt>Emitido</dt><dd>${fecha(new Date().toISOString())}</dd>
      </dl>
    </header>
    ${resumenEjecutivo(d)}
    ${exposicion(d)}
    ${detalle(d)}
    ${pendientes(d)}
    ${anexos(d)}
    <footer class="pie">Generado por el Radar de vulnerabilidades a partir del plan firmado, del resultado que midió el agente en el equipo y del cruce posterior del radar. Ningún texto de este informe lo redactó un modelo de lenguaje.</footer>`;
}

async function cargar() {
  const plan = new URLSearchParams(location.search).get("plan") || "";
  if (!/^[0-9a-f-]{36}$/.test(plan)) {
    $("#hoja").innerHTML = '<p class="cargando">Falta el identificador del plan.</p>';
    return;
  }
  const respuesta = await fetch(`/api/parcheo/${plan}/informe`, { credentials: "same-origin" });
  if (respuesta.status === 401) {
    location.replace(`/entrar/?volver=${encodeURIComponent(location.pathname + location.search)}`);
    return;
  }
  const datos = await respuesta.json().catch(() => ({}));
  if (!respuesta.ok) {
    $("#hoja").innerHTML = `<p class="cargando">${esc(datos.detail || `Error ${respuesta.status}`)}</p>`;
    return;
  }
  pintar(datos);
}

$("#imprimir").addEventListener("click", () => window.print());
cargar().catch((error) => {
  $("#hoja").innerHTML = `<p class="cargando">${esc(error.message)}</p>`;
});
