// Panel de administración: sesión, navegación por secciones, alta de equipos con token,
// tokens de inscripción y usuarios. Usa api(), esc(), $ y puede() de panel.js.
"use strict";

const VISTAS = {
  resumen: "Resumen", hallazgos: "Hallazgos", equipos: "Equipos", inventario: "Cargar inventario",
  umbrales: "Umbrales", actividad: "Actividad del agente", usuarios: "Usuarios",
  configuracion: "Configuración",
};
const ROLES = { lector: "Lector", analista: "Analista", admin: "Administrador" };

// ---- confirmación dentro de la página ---------------------------------------

function confirmar(titulo, texto, accion) {
  const dialogo = $("#confirmar");
  $("#t-confirmar").textContent = titulo;
  $("#confirmar-texto").textContent = texto;
  $("#confirmar-si").textContent = accion;
  return new Promise((resolver) => {
    const cerrar = (valor) => {
      dialogo.close();
      $("#confirmar-si").onclick = null;
      $("#confirmar-no").onclick = null;
      resolver(valor);
    };
    $("#confirmar-si").onclick = () => cerrar(true);
    $("#confirmar-no").onclick = () => cerrar(false);
    dialogo.oncancel = () => resolver(false);
    dialogo.showModal();
    $("#confirmar-no").focus();
  });
}

document.querySelectorAll("dialog [data-cerrar]").forEach((boton) =>
  boton.addEventListener("click", () => boton.closest("dialog").close()));

async function copiar(texto, boton) {
  try {
    await navigator.clipboard.writeText(texto);
    const antes = boton.textContent;
    boton.textContent = "Copiado";
    setTimeout(() => { boton.textContent = antes; }, 1600);
  } catch {
    boton.textContent = "Selecciónalo y copia";
  }
}

// ---- navegación --------------------------------------------------------------

function vistaPermitida(nombre) {
  const enlace = document.querySelector(`.nav a[data-vista="${nombre}"]`);
  if (!enlace || enlace.hidden) return false;
  return true;
}

let primeraVista = true;

function mostrarVista() {
  // Entre secciones, una transición corta del contenido (la barra lateral queda quieta).
  // Sin soporte del navegador o con movimiento reducido, cambia de golpe.
  const suave = !primeraVista && document.startViewTransition
    && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  primeraVista = false;
  if (suave) document.startViewTransition(cambiarVista); else cambiarVista();
}

function cambiarVista() {
  let nombre = location.hash.replace("#", "") || "resumen";
  if (!VISTAS[nombre] || !vistaPermitida(nombre)) nombre = "resumen";
  document.querySelectorAll(".vista").forEach((v) => { v.hidden = v.dataset.vista !== nombre; });
  document.querySelectorAll(".nav a").forEach((a) => {
    const activa = a.dataset.vista === nombre;
    a.classList.toggle("activa", activa);
    if (activa) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  $("#titulo-vista").textContent = VISTAS[nombre];
  document.title = `${VISTAS[nombre]} · Lighthouse`;
  document.body.classList.remove("menu-abierto");
  $("#menu-movil").setAttribute("aria-expanded", "false");
  if (nombre === "usuarios") cargarUsuarios();
  if (nombre === "configuracion") { cargarAjustes(); cargarNtfy(); }
  if (nombre === "equipos" && puede("admin")) cargarTokens();
}

window.addEventListener("hashchange", mostrarVista);
$("#menu-movil").addEventListener("click", () => {
  const abierto = document.body.classList.toggle("menu-abierto");
  $("#menu-movil").setAttribute("aria-expanded", String(abierto));
});

function aplicarRol() {
  document.querySelectorAll("[data-rol]").forEach((el) => { el.hidden = !puede(el.dataset.rol); });
  $("#cuenta-nombre").textContent = SESION.nombre;
  $("#cuenta-rol").textContent = ROLES[SESION.rol] || SESION.rol;
  $("#cuenta").title = `Usuario: ${SESION.usuario}`;
}

// ---- sesión ------------------------------------------------------------------

$("#salir").addEventListener("click", async () => {
  await fetch("/api/sesion", { method: "DELETE", credentials: "same-origin" }).catch(() => {});
  location.replace("/entrar/");
});

$("#abrir-clave").addEventListener("click", () => {
  $("#form-clave").reset();
  $("#clave-resultado").textContent = "";
  $("#dialogo-clave").showModal();
});

$("#form-clave").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const salida = $("#clave-resultado");
  try {
    await api("/api/sesion/clave", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actual: f.elements.actual.value, nueva: f.elements.nueva.value }),
    });
    salida.className = "resultado ok";
    salida.textContent = "Contraseña cambiada. Entra otra vez con la nueva.";
    setTimeout(() => location.replace("/entrar/"), 1400);
  } catch (error) {
    salida.className = "resultado error";
    salida.textContent = error.message;
  }
});

// ---- agregar equipo ------------------------------------------------------------

const asistente = {
  sistema: "windows",
  token: null,
  equiposAntes: new Set(),
  espera: null,
};

function irAPaso(n) {
  document.querySelectorAll("#asistente .paso").forEach((p) => { p.hidden = p.dataset.paso !== String(n); });
  document.querySelectorAll("#pasos li").forEach((li) => {
    const paso = Number(li.dataset.paso);
    li.classList.toggle("hecho", paso < n);
    li.classList.toggle("actual", paso === n);
  });
  if (n === 3) pintarInstalacion();
  if (n === 4) esperarEquipo(); else detenerEspera();
}

// El zip que se descarga ya trae la URL del radar y el token (configuracion.txt): en Windows
// basta con doble clic en INSTALAR.cmd, y en Linux con una orden sin parámetros.
function comandoInstalacion() {
  if (asistente.sistema === "windows") return "Doble clic en INSTALAR.cmd";
  return "sudo sh agente_local/instalacion/instalar.sh";
}

// Parcheo aprobado (docs/plan-parcheo.md): con la casilla marcada, el zip lleva la clave
// pública del aprobador y el comando rápido la pasa por RADAR_CLAVE_APROBACION.
let claveParcheo = null; // { huella, publica } de la clave vigente más reciente

async function cargarClaveParcheo() {
  claveParcheo = null;
  try {
    const { claves } = await api("/api/parcheo/claves");
    const vigentes = (claves || []).filter((c) => !c.revocada);
    claveParcheo = vigentes.length ? vigentes[vigentes.length - 1] : null;
  } catch { claveParcheo = null; }
  $("#opcion-parcheo").hidden = !claveParcheo;
  if (claveParcheo) $("#clave-parcheo").textContent = claveParcheo.huella;
}

function parcheoMarcado() {
  return Boolean(claveParcheo && $("#permitir-parcheo").checked);
}

// Una sola orden con el zip genérico de este mismo radar: no lleva token (el equipo se
// activa con el código que muestra el instalador).
function comandoRapido() {
  const origen = location.origin;
  const clave = parcheoMarcado() ? `RADAR_CLAVE_APROBACION=${claveParcheo.publica} ` : "";
  return `curl -fsSL ${origen}/descargas/radar-agente-linux.zip -o /tmp/ra.zip && ` +
    `unzip -oq /tmp/ra.zip -d /tmp/radar-agente && ` +
    `sudo ${clave}sh /tmp/radar-agente/agente_local/instalacion/instalar.sh ${origen}`;
}

function pintarInstalacion() {
  const win = asistente.sistema === "windows";
  const descarga = $("#descarga");
  descarga.removeAttribute("href");
  descarga.textContent = win ? "Descargar para Windows (.zip)" : "Descargar para Linux (.zip)";
  $("#descarga-nota").textContent = win
    ? "Ya trae la dirección del radar y el token. Si al equipo le falta Python, el instalador lo instala."
    : "Ya trae la dirección del radar y el token. Necesita python3 y systemd.";
  $("#comando-donde").textContent = win
    ? "Descomprímelo en el equipo y:"
    : "En una terminal, dentro de la carpeta descomprimida:";
  $("#comando").textContent = comandoInstalacion();
  $("#copiar-comando").hidden = win;
  $("#via-rapida").hidden = win;
  $("#comando-rapido").textContent = comandoRapido();
  cargarClaveParcheo().then(() => { $("#comando-rapido").textContent = comandoRapido(); });
}

$("#permitir-parcheo").addEventListener("change", () => {
  $("#comando-rapido").textContent = comandoRapido();
});
$("#copiar-rapido").addEventListener("click", (e) => copiar(comandoRapido(), e.target));

// La descarga va por POST: el token no queda en la URL ni en registros de acceso.
$("#descarga").addEventListener("click", async (e) => {
  e.preventDefault();
  const boton = e.currentTarget;
  try {
    const r = await fetch("/api/agente-instalador", {
      method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sistema: asistente.sistema,
        token: asistente.token,
        ...(parcheoMarcado() ? { clave_aprobacion: claveParcheo.huella } : {}),
      }),
    });
    if (!r.ok) throw new Error(`Error ${r.status}`);
    const enlace = document.createElement("a");
    enlace.href = URL.createObjectURL(await r.blob());
    enlace.download = `radar-agente-${asistente.sistema}.zip`;
    document.body.appendChild(enlace);
    enlace.click();
    enlace.remove();
    setTimeout(() => URL.revokeObjectURL(enlace.href), 10000);
  } catch (error) {
    $("#descarga-nota").textContent = `No se pudo descargar: ${error.message}`;
  }
  boton.blur();
});

async function abrirAsistente() {
  asistente.token = null;
  $("#form-token").reset();
  $("#token-error").textContent = "";
  try {
    const datos = await api("/api/equipos");
    asistente.equiposAntes = new Set((datos.equipos || []).map((e) => e.id));
  } catch { asistente.equiposAntes = new Set(); }
  irAPaso(1);
  $("#asistente").showModal();
}

$("#agregar-equipo").addEventListener("click", abrirAsistente);
$("#asistente").addEventListener("close", detenerEspera);
$("#asistente").addEventListener("change", (e) => {
  if (e.target.name === "sistema") asistente.sistema = e.target.value;
});
$("#asistente").addEventListener("click", (e) => {
  const boton = e.target.closest("[data-ir]");
  if (!boton) return;
  const destino = Number(boton.dataset.ir);
  // Sin token no se puede pasar a instalar: hay que crearlo primero.
  if (destino >= 3 && !asistente.token) { irAPaso(2); return; }
  irAPaso(destino);
});

$("#form-token").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const boton = document.querySelector('button[form="form-token"]');
  boton.disabled = true;
  try {
    const r = await api("/api/tokens", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        horas: Number(f.elements.horas.value),
        usos_max: Number(f.elements.usos_max.value),
        etiqueta: f.elements.etiqueta.value.trim() || null,
        sistema: asistente.sistema,
      }),
    });
    asistente.token = r.token;
    irAPaso(3);
    cargarTokens();
  } catch (error) {
    $("#token-error").className = "resultado error";
    $("#token-error").textContent = error.message;
  } finally {
    boton.disabled = false;
  }
});

$("#copiar-comando").addEventListener("click", (e) => copiar(comandoInstalacion(), e.target));

function detenerEspera() {
  clearInterval(asistente.espera);
  asistente.espera = null;
}

function esperarEquipo() {
  detenerEspera();
  const caja = $("#espera");
  caja.innerHTML = `<div class="espera-radar" aria-hidden="true"><span></span></div>
    <p>Esperando que el equipo se inscriba.</p>
    <p class="nota">Aparece aquí en cuanto el instalador canjea el token. Puedes cerrar esta ventana: el equipo saldrá igual en la lista.</p>`;
  const revisar = async () => {
    try {
      const datos = await api("/api/equipos");
      const nuevos = (datos.equipos || []).filter((eq) => !asistente.equiposAntes.has(eq.id));
      if (!nuevos.length) return;
      detenerEspera();
      caja.innerHTML = `<div class="espera-ok" aria-hidden="true"></div>
        <p>${nuevos.map((eq) => `<strong class="mono">${esc(eq.nombre)}</strong>`).join(", ")} ${nuevos.length > 1 ? "se inscribieron" : "se inscribió"}.</p>
        <p class="nota">${nuevos[0].ultimo_reporte ? "Ya envió su primer reporte." : "Su primer reporte llega en unos minutos."}
          ${nuevos.some((eq) => eq.pendiente) ? "Queda por activar: escribe en su ficha el código que mostró el instalador." : ""}</p>
        <button type="button" class="boton-texto" id="ver-nuevo">${nuevos.some((eq) => eq.pendiente) ? "Activar con el código" : "Ver el equipo"}</button>`;
      $("#ver-nuevo").addEventListener("click", () => {
        $("#asistente").close();
        location.hash = "#equipos";
        abrirEquipo(nuevos[0].id);
      });
      refrescarAuxiliares();
      cargarTokens();
    } catch { /* se reintenta */ }
  };
  revisar();
  asistente.espera = setInterval(revisar, 4000);
}

// ---- tokens de inscripción -------------------------------------------------------

const ESTADO_TOKEN = {
  vigente: ["p-ok", "Vigente"], agotado: ["", "Agotado"], vencido: ["", "Vencido"], revocado: ["p-caida", "Revocado"],
};

async function cargarTokens() {
  if (!puede("admin")) return;
  const caja = $("#tokens");
  try {
    const d = await api("/api/tokens");
    const filas = d.tokens.map((t) => {
      const [clase, texto] = ESTADO_TOKEN[t.estado] || ["", t.estado];
      return `<tr>
        <td>${t.etiqueta ? esc(t.etiqueta) : '<span class="sin-dato">sin etiqueta</span>'}
          <div class="nota">creado por ${esc(t.creado_por)}, ${esc(fmtHora(t.creado))}</div></td>
        <td>${esc(t.sistema === "windows" ? "Windows" : t.sistema === "linux" ? "Linux" : "Cualquiera")}</td>
        <td class="mono">rdr_…${esc(t.pista)}</td>
        <td class="num">${esc(t.usos)} de ${esc(t.usos_max)}</td>
        <td class="mono">${esc(fmtHora(t.vence))}</td>
        <td><span class="pildora ${clase}"><span class="punto"></span>${esc(texto)}</span></td>
        <td>${t.estado === "vigente" ? `<button type="button" class="boton-texto texto-peligro" data-revocar-token="${esc(t.id)}">Revocar</button>` : ""}</td>
      </tr>`;
    }).join("");
    const organizacion = d.token_organizacion
      ? '<p class="nota">Además está activo el token de la organización (variable AGENTE_TOKEN_INSCRIPCION del servidor), que no vence.</p>'
      : "";
    caja.innerHTML = filas
      ? `<div class="tabla-envoltura"><table class="tabla tabla-tokens"><thead><tr>
          <th>Etiqueta</th><th>Sistema</th><th>Token</th><th class="num">Usos</th><th>Vence</th><th>Estado</th><th></th>
        </tr></thead><tbody>${filas}</tbody></table></div>${organizacion}`
      : `<p class="vacio">Todavía no hay tokens. Se crean al agregar un equipo.</p>${organizacion}`;
  } catch (error) {
    caja.innerHTML = `<p class="vacio">${esc(error.message)}</p>`;
  }
}

$("#tokens").addEventListener("click", async (e) => {
  const boton = e.target.closest("[data-revocar-token]");
  if (!boton) return;
  const ok = await confirmar("Revocar token",
    "Ningún equipo nuevo podrá inscribirse con este token. Los equipos ya inscritos siguen funcionando.",
    "Revocar token");
  if (!ok) return;
  boton.disabled = true;
  try {
    await api(`/api/tokens/${encodeURIComponent(boton.dataset.revocarToken)}`, { method: "DELETE" });
  } finally {
    cargarTokens();
  }
});

// ---- usuarios -------------------------------------------------------------------

async function cargarUsuarios() {
  if (!puede("admin")) return;
  const caja = $("#usuarios");
  try {
    const d = await api("/api/usuarios");
    caja.innerHTML = `<div class="tabla-envoltura"><table class="tabla tabla-usuarios"><thead><tr>
        <th>Usuario</th><th>Nombre</th><th>Rol</th><th>Estado</th><th>Último ingreso</th><th></th>
      </tr></thead><tbody>${d.usuarios.map((u) => {
        const yo = u.id === SESION.id;
        const opciones = Object.entries(ROLES).map(([v, t]) =>
          `<option value="${v}"${v === u.rol ? " selected" : ""}>${t}</option>`).join("");
        return `<tr data-usuario="${esc(u.id)}">
          <td class="mono">${esc(u.usuario)}${yo ? ' <span class="pildora">tú</span>' : ""}</td>
          <td>${esc(u.nombre)}</td>
          <td><select data-campo="rol" aria-label="Rol de ${esc(u.usuario)}">${opciones}</select></td>
          <td><span class="pildora ${u.activo ? "p-ok" : ""}"><span class="punto"></span>${u.activo ? "Activo" : "Desactivado"}</span></td>
          <td class="mono">${esc(u.ultimo_ingreso ? fmtHora(u.ultimo_ingreso) : "nunca")}</td>
          <td class="acciones-fila">
            <button type="button" class="boton-texto" data-accion="clave">Nueva contraseña</button>
            <button type="button" class="boton-texto${u.activo ? " texto-peligro" : ""}" data-accion="activo" data-valor="${u.activo ? "0" : "1"}">${u.activo ? "Desactivar" : "Activar"}</button>
          </td>
        </tr>`;
      }).join("")}</tbody></table></div><div class="resultado" id="usuarios-resultado" aria-live="polite"></div>`;
  } catch (error) {
    caja.innerHTML = `<p class="vacio">${esc(error.message)}</p>`;
  }
}

async function cambiarUsuario(id, cambio) {
  const salida = $("#usuarios-resultado");
  try {
    await api(`/api/usuarios/${encodeURIComponent(id)}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cambio),
    });
    await cargarUsuarios();
    return true;
  } catch (error) {
    await cargarUsuarios();
    const nueva = $("#usuarios-resultado");
    (nueva || salida).className = "resultado error";
    (nueva || salida).textContent = error.message;
    return false;
  }
}

$("#usuarios").addEventListener("change", (e) => {
  const select = e.target.closest("select[data-campo='rol']");
  if (!select) return;
  cambiarUsuario(select.closest("tr").dataset.usuario, { rol: select.value });
});

$("#usuarios").addEventListener("click", async (e) => {
  const boton = e.target.closest("[data-accion]");
  if (!boton) return;
  const fila = boton.closest("tr");
  const id = fila.dataset.usuario;
  if (boton.dataset.accion === "activo") {
    const activar = boton.dataset.valor === "1";
    if (!activar) {
      const ok = await confirmar("Desactivar usuario",
        "No podrá entrar y sus sesiones abiertas se cierran. Se puede volver a activar.", "Desactivar");
      if (!ok) return;
    }
    cambiarUsuario(id, { activo: activar });
    return;
  }
  // Nueva contraseña: formulario en la misma fila, sin prompt().
  if (fila.nextElementSibling && fila.nextElementSibling.classList.contains("fila-clave")) {
    fila.nextElementSibling.remove();
    return;
  }
  fila.insertAdjacentHTML("afterend", `<tr class="fila-clave"><td colspan="6">
    <form class="formulario-fila">
      <label>Contraseña nueva para ${esc(fila.querySelector("td").textContent.replace(" tú", ""))}
        <input name="clave" type="password" minlength="10" required autocomplete="new-password"></label>
      <button type="submit">Guardar contraseña</button>
      <span class="nota">Sus sesiones abiertas se cierran.</span>
    </form></td></tr>`);
  const form = fila.nextElementSibling.querySelector("form");
  form.elements.clave.focus();
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (await cambiarUsuario(id, { clave: form.elements.clave.value })) {
      $("#usuarios-resultado").className = "resultado ok";
      $("#usuarios-resultado").textContent = "Contraseña cambiada.";
    }
  });
});

$("#nuevo-usuario").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const salida = $("#nuevo-usuario-resultado");
  try {
    const r = await api("/api/usuarios", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usuario: f.elements.usuario.value.trim(), nombre: f.elements.nombre.value.trim(),
        rol: f.elements.rol.value, clave: f.elements.clave.value,
      }),
    });
    f.reset();
    salida.className = "resultado ok";
    salida.textContent = `Usuario ${r.usuario.usuario} creado. Pásale la contraseña inicial por un canal aparte.`;
    cargarUsuarios();
  } catch (error) {
    salida.className = "resultado error";
    salida.textContent = error.message;
  }
});

// ---- configuración: modelo de Claude ------------------------------------------

const USOS_MODELO = {
  analista: ["Analista", "Redacta los análisis y comunicados de cada producto."],
  desempate: ["Desempate del normalizador", "Elige entre CPE empatados (solo con RADAR_DESEMPATE_MODELO=1)."],
  asistente: ["Asistente", "Responde las preguntas de la caja del panel y de Mi equipo. Por defecto, Sonnet 5.5."],
};

function origenModelo(u) {
  if (u.origen === "consola") return `Consola${u.por ? `, ${esc(u.por)}` : ""}${u.cambiado ? `, ${esc(fmtHora(u.cambiado))}` : ""}`;
  if (u.origen === "variable") return `Variable <span class="mono">${esc(u.variable)}</span>`;
  return "Por defecto";
}

async function cargarAjustes() {
  if (!puede("admin")) return;
  const caja = $("#ajustes-modelo");
  try {
    const d = await api("/api/ajustes");
    caja.innerHTML = `<div class="tabla-envoltura"><table class="tabla"><thead><tr>
        <th>Uso</th><th>Modelo</th><th>De dónde sale</th>
      </tr></thead><tbody>${Object.entries(USOS_MODELO).map(([uso, [titulo, detalle]]) => {
        const u = d.usos[uso];
        const entorno = d.modelos.find((m) => m.id === u.del_entorno)?.nombre || u.del_entorno;
        const opciones = [`<option value=""${u.origen !== "consola" ? " selected" : ""}>Usar el del entorno (${esc(entorno)})</option>`]
          .concat(d.modelos.map((m) =>
            `<option value="${esc(m.id)}"${u.origen === "consola" && m.id === u.modelo ? " selected" : ""}>${esc(m.nombre)}</option>`))
          .join("");
        return `<tr>
          <td><strong>${esc(titulo)}</strong><br><span class="nota">${esc(detalle)}</span></td>
          <td><select data-uso="${esc(uso)}" aria-label="Modelo para ${esc(titulo)}">${opciones}</select>
            <div class="mono nota">${esc(u.modelo)}</div></td>
          <td>${origenModelo(u)}</td>
        </tr>`;
      }).join("")}</tbody></table></div><div class="resultado" id="ajustes-resultado" aria-live="polite"></div>`;
  } catch (error) {
    caja.innerHTML = `<p class="vacio">${esc(error.message)}</p>`;
  }
}

$("#ajustes-modelo").addEventListener("change", async (e) => {
  const select = e.target.closest("select[data-uso]");
  if (!select) return;
  select.disabled = true;
  try {
    await api(`/api/ajustes/modelo/${encodeURIComponent(select.dataset.uso)}`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ modelo: select.value || null }),
    });
    await cargarAjustes();
    $("#ajustes-resultado").className = "resultado ok";
    $("#ajustes-resultado").textContent = "Modelo guardado.";
  } catch (error) {
    await cargarAjustes();
    $("#ajustes-resultado").className = "resultado error";
    $("#ajustes-resultado").textContent = error.message;
  }
});

// ---- avisos por ntfy (radar/avisos/ntfy.py) -------------------------------------

function pintarNtfy(d) {
  const caja = $("#ajustes-ntfy");
  $("#probar-ntfy").disabled = !d.configurado;
  if (!d.configurado) {
    caja.innerHTML = `<p class="vacio">${d.topico_definido
      ? "<span class=\"mono\">NTFY_TOPICO</span> no es válido (1 a 64 caracteres: letras, números, _ o -)."
      : "Sin configurar: falta <span class=\"mono\">NTFY_TOPICO</span> en el entorno."}</p>`;
    return;
  }
  caja.innerHTML = `<dl class="ntfy-datos">
      <dt>Tópico</dt><dd class="mono">${esc(d.servidor)}/${esc(d.topico)}</dd>
      <dt>Token</dt><dd>${d.con_token ? "Sí" : "No (tópico abierto)"}</dd>
      <dt>Enlace al panel</dt><dd>${d.enlace_panel ? "Sí" : "No (falta <span class=\"mono\">RADAR_URL_PUBLICA</span>)"}</dd>
    </dl>`;
}

async function cargarNtfy() {
  if (!puede("admin")) return;
  try {
    pintarNtfy(await api("/api/ajustes/ntfy"));
  } catch (error) {
    $("#ajustes-ntfy").innerHTML = `<p class="vacio">${esc(error.message)}</p>`;
  }
}

$("#probar-ntfy").addEventListener("click", async () => {
  const boton = $("#probar-ntfy");
  const salida = $("#ntfy-resultado");
  boton.disabled = true;
  salida.className = "resultado";
  salida.textContent = "Enviando…";
  try {
    const d = await api("/api/ajustes/ntfy/prueba", { method: "POST" });
    salida.className = "resultado ok";
    salida.textContent = `Notificación enviada a ${d.topico}. Revisa la app de ntfy.`;
  } catch (error) {
    salida.className = "resultado error";
    salida.textContent = error.message;
  } finally {
    // Pausa corta: el servidor rechaza pruebas seguidas.
    setTimeout(() => { boton.disabled = false; }, 10000);
  }
});

// ---- arranque ------------------------------------------------------------------

(async function arrancar() {
  try {
    const r = await fetch("/api/sesion", { credentials: "same-origin" });
    const d = await r.json();
    if (!d.usuario) { irAlLogin(); return; }
    SESION = d.usuario;
  } catch {
    $("#estado").innerHTML = '<span class="pildora p-caida"><span class="punto"></span>API sin respuesta</span>';
    document.body.classList.remove("cargando-sesion");
    return;
  }
  aplicarRol();
  mostrarVista();
  document.body.classList.remove("cargando-sesion");
  iniciarCiclo();
  if (window.iniciarAsistente) window.iniciarAsistente(SESION);
})();
