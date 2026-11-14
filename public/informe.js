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
      <div class="portada-marca"><svg class="lh" viewBox="0 0 143.2 32" fill="currentColor" role="img" aria-label="Lighthouse"><defs><linearGradient id="lh-haz" x1="12.6" x2="31" y1="0" y2="0" gradientUnits="userSpaceOnUse"><stop offset="0" class="lh-haz" stop-opacity=".95"/><stop offset="1" class="lh-haz" stop-opacity=".12"/></linearGradient></defs><path d="M12.6 9.5 31 3.6v15L12.6 11.7Z" fill="url(#lh-haz)"/><path d="M6.6 8 10 4.2 13.4 8Z"/><rect x="7.4" y="8.6" width="5.2" height="4" rx=".9" class="lh-luz"/><rect x="5.4" y="13.3" width="9.2" height="1.8" rx=".6"/><path d="M6.9 16h6.2l.84 4.6H6.06Z"/><path d="M5.69 22.6h8.62l.99 5.4H4.7Z"/><rect x="3" y="28.7" width="14" height="2.1" rx="1.05"/><path transform="translate(35.5 24.88) scale(0.205)" d="M8 0V-71H21V-4L13.9 -11.3H54.7V0ZM63.6 0V-53.4H76.4V0ZM63.4 -60.5V-71.9H76.7V-60.5ZM111.3 16.2Q104.3 16.2 99.3 14.3Q94.3 12.4 91.2 8.9Q88.2 5.5 87 1L100.2 0.1Q101.2 3.1 103.7 4.8Q106.1 6.5 111.3 6.5Q117.2 6.5 120.4 3.9Q123.6 1.2 123.6 -4.4V-11.2Q121.7 -7.3 117.5 -5Q113.3 -2.6 108.1 -2.6Q101.5 -2.6 96.3 -5.8Q91.2 -9.1 88.3 -14.9Q85.4 -20.8 85.4 -28.5Q85.4 -36.2 88.2 -42.1Q91.1 -47.9 96.2 -51.2Q101.3 -54.6 107.9 -54.6Q113.7 -54.6 117.9 -52Q122.1 -49.4 124 -45.1V-53.4H136.5V-4.7Q136.5 2.1 133.3 6.8Q130.2 11.5 124.5 13.8Q118.9 16.2 111.3 16.2ZM111.1 -12.6Q116.8 -12.6 120.2 -16.9Q123.6 -21.1 123.7 -28.6Q123.8 -33.6 122.2 -37.2Q120.7 -40.7 117.8 -42.7Q115 -44.6 111.1 -44.6Q105.2 -44.6 102 -40.2Q98.7 -35.9 98.7 -28.6Q98.7 -21.3 102.1 -17Q105.4 -12.6 111.1 -12.6ZM148.5 0V-71H161.3V-41.2H159.7Q160.5 -45.8 162.9 -48.8Q165.3 -51.7 168.8 -53.2Q172.3 -54.6 176.5 -54.6Q182.4 -54.6 186.4 -52Q190.5 -49.5 192.6 -44.9Q194.6 -40.3 194.6 -34.3V0H181.8V-31.2Q181.8 -37.7 179.6 -41Q177.4 -44.2 172.7 -44.2Q167.5 -44.2 164.4 -40.8Q161.3 -37.4 161.3 -30.9V0ZM228 0Q220 0 216.2 -3.7Q212.5 -7.4 212.5 -15.3V-65.9H225.3V-16.5Q225.3 -12.8 226.9 -11.4Q228.5 -9.9 231.9 -9.9H239.4V0ZM204.1 -43.5V-53.4H239.4V-43.5ZM247.3 0V-71H260.1V-41.2H258.5Q259.3 -45.8 261.7 -48.8Q264.1 -51.7 267.6 -53.2Q271.1 -54.6 275.3 -54.6Q281.2 -54.6 285.2 -52Q289.3 -49.5 291.4 -44.9Q293.4 -40.3 293.4 -34.3V0H280.6V-31.2Q280.6 -37.7 278.4 -41Q276.2 -44.2 271.5 -44.2Q266.3 -44.2 263.2 -40.8Q260.1 -37.4 260.1 -30.9V0ZM328.6 1.2Q320.7 1.2 314.8 -2.2Q308.8 -5.7 305.6 -12Q302.3 -18.3 302.3 -26.7Q302.3 -35.2 305.6 -41.5Q308.8 -47.7 314.8 -51.2Q320.7 -54.6 328.6 -54.6Q336.5 -54.6 342.4 -51.2Q348.3 -47.7 351.6 -41.5Q354.8 -35.2 354.8 -26.7Q354.8 -18.3 351.6 -12Q348.3 -5.7 342.4 -2.2Q336.5 1.2 328.6 1.2ZM328.6 -9.2Q334.8 -9.2 338.2 -13.8Q341.5 -18.4 341.5 -26.7Q341.5 -34.9 338.2 -39.5Q334.8 -44.2 328.6 -44.2Q322.4 -44.2 319 -39.5Q315.6 -34.9 315.6 -26.7Q315.6 -18.4 319 -13.8Q322.4 -9.2 328.6 -9.2ZM381.3 1.2Q373.2 1.2 368.5 -4.2Q363.7 -9.5 363.7 -19V-53.4H376.5V-22.2Q376.5 -15.5 378.8 -12.4Q381 -9.2 385.6 -9.2Q390.8 -9.2 393.7 -12.7Q396.5 -16.1 396.5 -22.7V-53.4H409.3V0H397.6L397.3 -14.7L398.9 -14.2Q397.7 -6.6 393.2 -2.7Q388.7 1.2 381.3 1.2ZM443.1 1.2Q435 1.2 429.7 -1.1Q424.3 -3.4 421.5 -7.5Q418.7 -11.6 418.3 -16.8L431.4 -17.4Q432.1 -13.2 434.8 -10.9Q437.5 -8.6 443.2 -8.6Q447.7 -8.6 450.1 -10.1Q452.4 -11.5 452.4 -14.6Q452.4 -16.4 451.6 -17.6Q450.7 -18.8 448.2 -19.7Q445.8 -20.6 441.1 -21.5Q433 -22.9 428.4 -25Q423.8 -27 422 -30.1Q420.1 -33.2 420.1 -37.8Q420.1 -45.3 425.9 -50Q431.6 -54.6 442.7 -54.6Q450.4 -54.6 455.4 -52.2Q460.3 -49.7 462.9 -45.7Q465.4 -41.6 465.8 -36.6L452.8 -36Q452.7 -38.5 451.6 -40.5Q450.5 -42.5 448.3 -43.7Q446.1 -44.8 442.5 -44.8Q438 -44.8 435.7 -43Q433.3 -41.2 433.3 -38.2Q433.3 -36.1 434.2 -34.7Q435.2 -33.3 437.5 -32.5Q439.8 -31.6 443.8 -30.9Q452 -29.7 456.8 -27.6Q461.6 -25.5 463.7 -22.4Q465.7 -19.2 465.7 -14.8Q465.7 -7.1 459.6 -3Q453.4 1.2 443.1 1.2ZM497.8 1.2Q489.8 1.2 483.9 -2.2Q478 -5.7 474.8 -12Q471.6 -18.3 471.6 -26.7Q471.6 -35.1 474.8 -41.4Q478 -47.6 483.9 -51.1Q489.7 -54.6 497.5 -54.6Q505.1 -54.6 510.9 -51.2Q516.6 -47.8 519.7 -41.4Q522.8 -35 522.8 -26V-23.1H484.9Q485.3 -16.1 488.8 -12.6Q492.2 -9 497.9 -9Q502.2 -9 505.1 -10.9Q507.9 -12.9 509 -16.4L522.1 -15.6Q519.9 -7.8 513.5 -3.3Q507 1.2 497.8 1.2ZM484.9 -31.7H509.6Q509.2 -38.2 505.9 -41.4Q502.6 -44.5 497.5 -44.5Q492.4 -44.5 489.1 -41.2Q485.7 -37.9 484.9 -31.7Z"/></svg><span>Radar de vulnerabilidades</span></div>
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
    <footer class="pie">Generado por Lighthouse a partir del plan firmado, del resultado que midió el agente en el equipo y del cruce posterior del radar. Ningún texto de este informe lo redactó un modelo de lenguaje.</footer>`;
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
