// Movimiento de la landing. Una sola idea: el barrido del radar. Cada pieza muestra lo que
// dice su texto ocurriendo (el inventario se lee, el ataque no pasa, el equipo se inscribe).
//
// Falla abierto: el HTML ya trae el estado final. Este script agrega la clase `motion` al
// <html>, que es lo único que esconde cosas (veredictos, tachados, el equipo en el panel).
// Con movimiento reducido, sin GSAP o si una pieza falla, se quita `motion` y todo queda
// visible y quieto.
"use strict";

(function () {
  const raiz = document.documentElement;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const gsap = window.gsap;
  if (!gsap) return;
  if (window.SplitText) gsap.registerPlugin(window.SplitText);
  if (window.ScrambleTextPlugin) gsap.registerPlugin(window.ScrambleTextPlugin);

  raiz.classList.add("motion");
  const piezas = [titular, radar, banco, terminal, tachados];
  for (const pieza of piezas) {
    try { pieza(); } catch (error) {
      raiz.classList.remove("motion");
      console.warn("landing: una pieza falló y la página queda quieta", error);
    }
  }

  // Ejecuta `alEntrar` la primera vez que el elemento entra en pantalla.
  function alVerse(el, alEntrar, umbral = 0.35) {
    const io = new IntersectionObserver((entradas) => {
      if (entradas.some((e) => e.isIntersecting)) { io.disconnect(); alEntrar(); }
    }, { threshold: umbral });
    io.observe(el);
  }

  // ---- titular: entra una vez, línea por línea ----------------------------------
  function titular() {
    const h1 = document.querySelector(".hero h1");
    if (!h1 || !window.SplitText) return;
    // autoSplit espera a las fuentes y vuelve a partir si cambia el ancho.
    window.SplitText.create(h1, {
      type: "lines", mask: "lines", linesClass: "linea-titulo", autoSplit: true,
      onSplit: (self) => gsap.from(self.lines, { yPercent: 105, duration: 0.9, ease: "expo.out", stagger: 0.09 }),
    });
    gsap.from([".hero-bajada", ".hero-acciones"], { y: 14, opacity: 0, duration: 0.7, delay: 0.35, stagger: 0.1, ease: "power2.out", clearProps: "transform,opacity" });
  }

  // ---- radar del hero ----------------------------------------------------------
  // El barrido gira detrás de la tabla. Cada fila tiene un punto; se mide su ángulo
  // respecto del centro del radar y, cuando el barrido lo cruza, la fila se "lee".
  // Una vuelta por ciclo: un poco antes de la primera fila, todo vuelve a estar sin leer.
  function radar() {
    const figura = document.querySelector(".escaner");
    const disco = figura && figura.querySelector(".radar");
    if (!disco) return;
    const barrido = document.getElementById("radar-barrido");
    const estado = document.getElementById("escaner-estado");
    const filas = [...figura.querySelectorAll(".fila[data-veredicto]")];
    const inyeccion = figura.querySelector(".inyeccion");
    const original = inyeccion ? inyeccion.textContent : "";
    let angulos = filas.map(() => 0);

    function medir() {
      const r = disco.getBoundingClientRect();
      const cx = r.left + r.width / 2;
      const cy = r.top + r.height / 2;
      angulos = filas.map((f) => {
        const b = f.querySelector(".blip").getBoundingClientRect();
        const dx = b.left + b.width / 2 - cx;
        const dy = b.top + b.height / 2 - cy;
        return (Math.atan2(dx, -dy) * 180 / Math.PI + 360) % 360; // horario desde arriba
      });
    }
    medir();
    new ResizeObserver(medir).observe(figura);
    document.fonts.ready.then(medir);

    const leidas = new Set();
    function reiniciar() {
      leidas.clear();
      filas.forEach((f) => f.classList.remove("leida"));
      if (inyeccion) { gsap.killTweensOf(inyeccion); inyeccion.textContent = original; }
      estado.textContent = "cruzando";
      estado.classList.remove("listo");
    }

    function leer(fila, i) {
      leidas.add(i);
      fila.classList.add("leida", "destello");
      setTimeout(() => fila.classList.remove("destello"), 900);
      const blip = fila.querySelector(".blip");
      blip.classList.remove("ping");
      void blip.offsetWidth;
      blip.classList.add("ping");
      if (fila.dataset.veredicto === "limpio" && inyeccion && gsap.plugins.scrambleText) {
        gsap.to(inyeccion, { duration: 1.1, scrambleText: { text: "[texto no confiable, sin efecto]", chars: "░▒▓", speed: 0.5 } });
      }
      if (leidas.size === filas.length) {
        estado.textContent = "cruzado";
        estado.classList.add("listo");
      }
    }

    // ¿El barrido pasó por `x` al ir de `desde` a `hasta` (con vuelta por 360)?
    const cruza = (desde, hasta, x) => (hasta >= desde ? x > desde && x <= hasta : x > desde || x <= hasta);

    reiniciar();
    const primero = Math.min(...angulos);
    const giro = { a: (primero - 50 + 360) % 360 };
    let previo = giro.a;
    const tween = gsap.to(giro, {
      a: giro.a + 360, duration: 9, ease: "none", repeat: -1,
      onUpdate() {
        const a = giro.a % 360;
        barrido.style.transform = `rotate(${a}deg)`;
        const corte = (Math.min(...angulos) - 70 + 360) % 360;
        if (leidas.size && cruza(previo, a, corte)) reiniciar();
        filas.forEach((f, i) => { if (!leidas.has(i) && cruza(previo, a, angulos[i])) leer(f, i); });
        previo = a;
      },
    });
    // Fuera de pantalla no gasta fotogramas.
    new IntersectionObserver(([e]) => (e.isIntersecting ? tween.play() : tween.pause())).observe(figura);
  }

  // ---- banco de defensa ----------------------------------------------------------
  // El mismo ataque con y sin encierro. La primera vez que se ve corre solo: sin defensa
  // (el modelo obedece y marca todo mitigado) y después con defensa (no cambia nada).
  function banco() {
    const caja = document.getElementById("banco");
    if (!caja) return;
    const botones = [...caja.querySelectorAll(".banco-control button")];
    let tocado = false;
    let espera = null;

    function mostrar(modo) {
      caja.dataset.modo = modo;
      botones.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.modo === modo)));
      const pasos = caja.querySelectorAll(
        `.banco-traza li[data-en="${modo}"], .banco-hallazgos li, .banco-pie[data-en="${modo}"]`);
      pasos.forEach((el, k) => {
        el.classList.remove("entra");
        el.style.animationDelay = `${k * 0.38}s`;
        void el.offsetWidth;
        el.classList.add("entra");
      });
    }

    botones.forEach((b) => b.addEventListener("click", () => {
      tocado = true;
      clearTimeout(espera);
      mostrar(b.dataset.modo);
    }));
    alVerse(caja, () => {
      if (tocado) return;
      mostrar("sin");
      espera = setTimeout(() => { if (!tocado) mostrar("con"); }, 4600);
    });
  }

  // ---- terminal del agente local -------------------------------------------------
  // Escribe la instalación y, al terminar, el equipo aparece en el panel por aprobar y
  // después aprobado.
  function terminal() {
    const pre = document.querySelector(".terminal pre");
    const codigo = pre && pre.querySelector("code");
    const panel = document.querySelector(".terminal-panel");
    const pildora = document.getElementById("estado-equipo");
    if (!codigo || !panel) return;
    const lineas = codigo.innerHTML.split("\n");
    const final = pildora.textContent;
    pre.style.minHeight = `${pre.offsetHeight}px`;
    codigo.innerHTML = "";
    panel.classList.add("oculto");
    pildora.textContent = "Por aprobar";
    pildora.classList.add("pendiente");

    const espera = (ms) => new Promise((r) => setTimeout(r, ms));
    const cursor = document.createElement("span");
    cursor.className = "cursor-term";

    alVerse(pre, async () => {
      codigo.append(cursor);
      for (const [n, linea] of lineas.entries()) {
        if (n) codigo.insertBefore(document.createTextNode("\n"), cursor);
        if (linea.includes("t-ok")) {
          await espera(320);
          cursor.insertAdjacentHTML("beforebegin", linea);
          continue;
        }
        const prompt = linea.match(/^<span class="t-prompt">\$<\/span>/);
        if (prompt) cursor.insertAdjacentHTML("beforebegin", prompt[0]);
        const plano = document.createElement("span");
        plano.innerHTML = prompt ? linea.slice(prompt[0].length) : linea;
        const texto = plano.textContent;
        const nodo = document.createTextNode("");
        codigo.insertBefore(nodo, cursor);
        for (const c of texto) { nodo.data += c; await espera(c === " " ? 18 : 26); }
        await espera(260);
      }
      await espera(300);
      panel.classList.remove("oculto");
      await espera(1400);
      pildora.classList.remove("pendiente");
      pildora.textContent = final;
    }, 0.5);
  }

  // ---- tachado de lo que el radar no hace ------------------------------------------
  function tachados() {
    const lista = document.querySelector(".reglas-lista");
    if (!lista) return;
    const marcas = [...lista.querySelectorAll(".tachable")];
    alVerse(lista, () => marcas.forEach((m, i) => setTimeout(() => m.classList.add("visto"), 250 + i * 220)), 0.25);
  }
})();
