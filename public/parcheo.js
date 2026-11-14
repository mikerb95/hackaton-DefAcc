// Parcheo aprobado desde el panel (docs/plan-parcheo.md).
//
// La clave del aprobador es Ed25519 y vive en este navegador: se crea aquí, se descarga como
// archivo (JWK) y se vuelve a cargar en memoria para firmar. La privada nunca va al
// servidor: el servidor arma el plan canónico, el navegador firma esos bytes exactos y el
// agente verifica la firma con la clave pública que se fijó en el equipo al instalarlo.
// Se carga después de panel.js y usa sus utilidades ($, esc, api, puede, SESION, fmtHora,
// pildoraPrioridad) y confirmar() de admin.js.
"use strict";

let clavePanel = null; // { privada: CryptoKey, publica: "base64", huella: "16 hex" }

const TIPOS_PARCHEO = {
  aplicacion: "Aplicación",
  paquetes: "Paquetes",
  postura: "Postura",
  so: "Sistema",
};
// Lo que ve el admin antes de aprobar: qué tan reversible es cada tipo de acción.
const NOTAS_EJECUTOR = {
  winget: "Reversible si winget conserva la versión previa",
  windows_update: "No reversible: exige punto de restauración y puede pedir reinicio",
  apt: "Reversible si el repositorio conserva la versión previa",
  dnf: "Reversible con el historial de dnf",
  postura_windows: "Reversible al estado previo",
  postura_debian: "Reversible al estado previo",
  postura_rhel: "Reversible al estado previo",
};
const ESTADO_GENERAL = {
  exito: ["p-ok", "Éxito"],
  parcial: ["p-semanal", "Éxito parcial"],
  requiere_atencion: ["p-inmediato", "Requiere atención"],
  rechazado: ["p-caida", "Rechazado por el agente"],
  pendiente: ["p-informativo", "Pendiente"],
  cancelado: ["p-informativo", "Cancelado"],
};
const ESTADO_PLAN = {
  aprobado: "esperando al equipo",
  entregado: "en el equipo",
  ejecutado: "terminado",
  rechazado: "rechazado",
  cancelado: "cancelado",
};

// ---- utilidades de bytes y claves -------------------------------------------

function aBase64(bytes) {
  let texto = "";
  new Uint8Array(bytes).forEach((b) => { texto += String.fromCharCode(b); });
  return btoa(texto);
}

function deBase64Url(texto) {
  const normal = texto.replace(/-/g, "+").replace(/_/g, "/");
  const relleno = normal + "=".repeat((4 - (normal.length % 4)) % 4);
  return Uint8Array.from(atob(relleno), (c) => c.charCodeAt(0));
}

async function huellaDe(publica) {
  const digesto = new Uint8Array(await crypto.subtle.digest("SHA-256", publica));
  return Array.from(digesto.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function ed25519Disponible() {
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

function descargarJson(nombre, datos) {
  const blob = new Blob([JSON.stringify(datos, null, 2)], { type: "application/json" });
  const enlace = document.createElement("a");
  enlace.href = URL.createObjectURL(blob);
  enlace.download = nombre;
  document.body.append(enlace);
  enlace.click();
  enlace.remove();
  setTimeout(() => URL.revokeObjectURL(enlace.href), 1000);
}

async function crearClavePanel(nombre) {
  const par = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", par.privateKey);
  const publicaBytes = deBase64Url(jwk.x);
  const huella = await huellaDe(publicaBytes);
  const publica = aBase64(publicaBytes);
  // Primero se registra la pública: si falla, no queda un archivo de clave huérfano.
  await api("/api/parcheo/claves", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ publica, nombre }),
  });
  descargarJson(`clave-aprobacion-radar-${huella}.json`, {
    tipo: "radar-clave-aprobacion",
    aviso: "Clave PRIVADA del aprobador. Guárdala fuera del equipo y no la compartas. Quien la tenga puede aprobar parches.",
    nombre,
    huella,
    publica,
    creada: new Date().toISOString(),
    jwk,
  });
  clavePanel = {
    privada: await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]),
    publica,
    huella,
  };
}

async function cargarClavePanel(archivo) {
  const datos = JSON.parse(await archivo.text());
  const jwk = datos && datos.jwk;
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || !jwk.x) {
    throw new Error("El archivo no es una clave de aprobación del radar.");
  }
  // La pública sale de la propia clave (jwk.x), no de un campo aparte del archivo.
  const publicaBytes = deBase64Url(jwk.x);
  clavePanel = {
    privada: await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]),
    publica: aBase64(publicaBytes),
    huella: await huellaDe(publicaBytes),
  };
}

// ---- pintado ------------------------------------------------------------------

function pildoraGeneral(estado) {
  const [clase, texto] = ESTADO_GENERAL[estado] || ["p-informativo", estado];
  return `<span class="pildora ${clase}"><span class="punto"></span>${esc(texto)}</span>`;
}

function filaAccionParcheo(a, admin) {
  const kev = (a.en_kev || []).length ? `<span class="pildora p-kev">${esc(a.en_kev.length)} en KEV</span>` : "";
  const cves = (a.cves || []).length ? `<span class="pildora mono">${esc(a.cves.length)} CVE</span>` : "";
  const casilla = admin
    ? `<input type="checkbox" class="parcheo-casilla" value="${esc(a.id)}" aria-label="Incluir ${esc(a.titulo)}">`
    : "";
  return `
    <li class="parcheo-accion">
      <label class="parcheo-fila">
        ${casilla}
        <span class="parcheo-texto">
          <span class="accion-cabeza">${pildoraPrioridad(a.prioridad)}
            <span class="pildora">${esc(TIPOS_PARCHEO[a.tipo] || a.tipo)}</span>
            <strong>${esc(a.titulo)}</strong>${cves}${kev}</span>
          <span class="parcheo-nota">${esc(NOTAS_EJECUTOR[a.ejecutor] || "")}</span>
        </span>
      </label>
    </li>`;
}

function bloqueClave(datos) {
  if (!puede("admin")) return "";
  const registradas = datos.claves || [];
  if (clavePanel) {
    const conocida = registradas.some((c) => c.huella === clavePanel.huella);
    return `<div class="parcheo-clave">
      <span class="parcheo-punto ${conocida ? "ok" : "mal"}" aria-hidden="true"></span>
      Clave cargada <span class="mono">${esc(clavePanel.huella)}</span>
      ${conocida ? "" : '<span class="clave-error">no está registrada en el radar</span>'}
      <button type="button" class="boton-texto" id="olvidar-clave">Olvidar</button>
    </div>`;
  }
  return `<div class="parcheo-clave">
    <span class="parcheo-punto" aria-hidden="true"></span>
    Para firmar hace falta tu clave de aprobación.
    <label class="boton-texto parcheo-archivo">Cargar clave (.json)<input type="file" accept=".json,application/json" id="archivo-clave" hidden></label>
    <button type="button" class="boton-texto" id="crear-clave">Crear clave nueva</button>
  </div>`;
}

function bloqueHistorial(planes) {
  if (!planes.length) return '<p class="nota">Todavía no hay planes para este equipo.</p>';
  return `<table class="parcheo-historial">
    <thead><tr><th>Aprobado</th><th>Por</th><th>Acciones</th><th>Estado</th><th></th></tr></thead>
    <tbody>${planes.map((p) => `
      <tr>
        <td class="mono">${esc(fmtHora(p.creado))}</td>
        <td>${esc(p.aprobado_por)}</td>
        <td class="num">${esc(p.n_acciones)}</td>
        <td>${pildoraGeneral(p.estado_general)} <span class="nota">${esc(ESTADO_PLAN[p.estado] || p.estado)}</span>
          ${p.reinicio_pendiente ? '<span class="pildora p-semanal">reinicio pendiente</span>' : ""}</td>
        <td class="acciones-fila">
          <a class="boton-texto" href="/panel/informe/?plan=${encodeURIComponent(p.plan_id)}" target="_blank" rel="noopener">Informe</a>
          ${puede("admin") && ["aprobado", "entregado"].includes(p.estado)
            ? `<button type="button" class="boton-texto texto-peligro" data-cancelar="${esc(p.plan_id)}">Cancelar</button>` : ""}
        </td>
      </tr>`).join("")}</tbody>
  </table>`;
}

async function pintarParcheo(equipo) {
  const caja = $("#parcheo-equipo");
  if (!caja) return;
  let datos;
  try {
    datos = await api(`/api/equipos/${encodeURIComponent(equipo.id)}/parcheo`);
  } catch (error) {
    caja.innerHTML = `<h3>Parcheo aprobado</h3><p class="nota">${esc(error.message)}</p>`;
    return;
  }
  if ($("#parcheo-equipo") !== caja) return; // se abrió otro equipo mientras tanto
  const propuesta = datos.propuesta;
  const admin = puede("admin");
  const activo = datos.planes.some((p) => ["aprobado", "entregado"].includes(p.estado));
  const acciones = propuesta.acciones || [];
  const manuales = propuesta.manuales || [];
  let cuerpo;
  if (propuesta.motivo) {
    cuerpo = `<p class="nota">${esc(propuesta.motivo)}</p>`;
  } else if (!acciones.length) {
    cuerpo = '<p class="nota">No hay nada que el agente pueda aplicar solo en este equipo.</p>';
  } else {
    cuerpo = `
      <ul class="parcheo-lista">${acciones.map((a) => filaAccionParcheo(a, admin && !activo)).join("")}</ul>
      ${admin && !activo ? `${bloqueClave(datos)}
        <form id="firmar-plan" class="parcheo-firmar">
          <button type="submit" disabled>Firmar y enviar plan</button>
          <span class="nota" id="parcheo-aviso">Marca las acciones que apruebas. El agente las aplica en su próxima consulta (cada 15 minutos), verifica cada una y revierte si algo falla. Nunca reinicia el equipo.</span>
        </form>` : ""}
      ${activo ? '<p class="nota">Hay un plan en curso: el siguiente se aprueba cuando el equipo envíe su resultado o si cancelas el actual.</p>' : ""}`;
  }
  caja.innerHTML = `
    <h3>Parcheo aprobado</h3>
    <p class="nota">Lo aplica el agente del equipo solo si se instaló con el parcheo habilitado y tu clave de aprobación. Cada acción sale del catálogo cerrado del agente.</p>
    ${cuerpo}
    ${manuales.length ? `<details class="parcheo-manuales"><summary>${esc(manuales.length)} acciones que quedan para una persona</summary>
      <ul>${manuales.map((m) => `<li>${pildoraPrioridad(m.prioridad)} <strong>${esc(m.titulo)}</strong> <span class="nota">${esc(m.motivo)}</span></li>`).join("")}</ul></details>` : ""}
    <h3 style="margin-top:16px">Planes</h3>
    ${bloqueHistorial(datos.planes)}`;
  conectarParcheo(equipo, datos);
}

function conectarParcheo(equipo, datos) {
  const caja = $("#parcheo-equipo");
  const formulario = $("#firmar-plan");
  const aviso = (texto, error = false) => {
    const nodo = $("#parcheo-aviso");
    if (nodo) { nodo.textContent = texto; nodo.classList.toggle("clave-error", error); }
  };
  const casillas = () => [...caja.querySelectorAll(".parcheo-casilla")];
  const actualizar = () => {
    if (!formulario) return;
    formulario.querySelector("button").disabled = !clavePanel || !casillas().some((c) => c.checked);
  };
  casillas().forEach((c) => c.addEventListener("change", actualizar));
  actualizar();

  const archivo = $("#archivo-clave");
  if (archivo) {
    archivo.addEventListener("change", async () => {
      try {
        await cargarClavePanel(archivo.files[0]);
        pintarParcheo(equipo);
      } catch (error) {
        aviso(error.message, true);
      }
    });
  }
  const crear = $("#crear-clave");
  if (crear) {
    crear.addEventListener("click", async () => {
      if (!(await ed25519Disponible())) {
        aviso("Este navegador no firma con Ed25519. Usa una versión reciente de Chrome, Edge, Firefox o Safari.", true);
        return;
      }
      const ok = await confirmar(
        "Crear clave de aprobación",
        "Se descarga un archivo con tu clave privada. Guárdalo fuera de este equipo: sin él no podrás aprobar parches, y quien lo tenga sí. La clave pública queda registrada en el radar y hay que ponerla al instalar el agente en cada equipo.",
        "Crear y descargar");
      if (!ok) return;
      try {
        await crearClavePanel(SESION ? SESION.nombre : "Aprobador");
        pintarParcheo(equipo);
      } catch (error) {
        aviso(error.message, true);
      }
    });
  }
  const olvidar = $("#olvidar-clave");
  if (olvidar) olvidar.addEventListener("click", () => { clavePanel = null; pintarParcheo(equipo); });

  caja.querySelectorAll("[data-cancelar]").forEach((boton) => {
    boton.addEventListener("click", async () => {
      const ok = await confirmar("Cancelar plan",
        "El radar deja de entregar este plan. Si el equipo ya lo descargó, puede estar aplicándolo: su resultado llegará igual.",
        "Cancelar plan");
      if (!ok) return;
      try {
        await api(`/api/parcheo/${encodeURIComponent(boton.dataset.cancelar)}/cancelar`, { method: "POST" });
        pintarParcheo(equipo);
      } catch (error) {
        boton.insertAdjacentHTML("afterend", ` <span class="clave-error">${esc(error.message)}</span>`);
      }
    });
  });

  if (!formulario) return;
  formulario.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const elegidas = casillas().filter((c) => c.checked).map((c) => c.value);
    const titulos = datos.propuesta.acciones.filter((a) => elegidas.includes(a.id)).map((a) => `• ${a.titulo}`);
    const ok = await confirmar(
      `Aprobar ${elegidas.length} ${elegidas.length === 1 ? "acción" : "acciones"} en ${equipo.nombre}`,
      `${titulos.join("\n")}\n\nEl plan vence en 72 horas. Se firma con tu clave ${clavePanel.huella}.`,
      "Firmar y enviar");
    if (!ok) return;
    const boton = formulario.querySelector("button");
    boton.disabled = true;
    try {
      const { plan } = await api(`/api/equipos/${encodeURIComponent(equipo.id)}/parcheo/borrador`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ acciones: elegidas }),
      });
      // Antes de firmar se comprueba que el plan diga lo que se aprobó.
      const leido = JSON.parse(plan);
      const ids = leido.acciones.map((a) => a.id).sort();
      if (leido.equipo_id !== equipo.id || JSON.stringify(ids) !== JSON.stringify([...elegidas].sort())) {
        throw new Error("El plan que armó el servidor no coincide con lo que marcaste. No se firmó.");
      }
      const firma = await crypto.subtle.sign({ name: "Ed25519" }, clavePanel.privada, new TextEncoder().encode(plan));
      await api(`/api/equipos/${encodeURIComponent(equipo.id)}/parcheo`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan, firma: aBase64(firma) }),
      });
      pintarParcheo(equipo);
    } catch (error) {
      boton.disabled = false;
      aviso(error.message, true);
    }
  });
}

window.pintarParcheo = pintarParcheo;
