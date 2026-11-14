// Barrido del hero: una línea recorre el inventario y cada fila recibe su veredicto al pasar.
// Es el único movimiento automático de la página. Con movimiento reducido se ve el estado final.
"use strict";

(function () {
  const tabla = document.getElementById("escaner");
  if (!tabla) return;
  const barrido = tabla.querySelector(".escaner-barrido");
  const filas = [...tabla.querySelectorAll(".fila[data-veredicto]")];
  const estado = document.getElementById("escaner-estado");
  const reducido = window.matchMedia("(prefers-reduced-motion: reduce)");

  function final() {
    filas.forEach((f) => f.classList.add("leida"));
    estado.textContent = "cruzado";
    estado.classList.add("listo");
  }

  if (reducido.matches) { final(); return; }

  const POR_FILA = 1100;
  const PAUSA = 4200;

  function ciclo() {
    filas.forEach((f) => f.classList.remove("leida"));
    estado.textContent = "cruzando";
    estado.classList.remove("listo");
    barrido.style.transition = "none";
    barrido.style.opacity = "1";
    barrido.style.transform = "translateY(-70px)";
    void barrido.offsetHeight;

    filas.forEach((fila, i) => {
      setTimeout(() => {
        barrido.style.transition = `transform ${POR_FILA}ms linear`;
        barrido.style.transform = `translateY(${fila.offsetTop + fila.offsetHeight - 60}px)`;
        setTimeout(() => fila.classList.add("leida"), POR_FILA * 0.85);
      }, i * POR_FILA);
    });

    const fin = filas.length * POR_FILA;
    setTimeout(() => {
      barrido.style.transition = "opacity 500ms";
      barrido.style.opacity = "0";
      estado.textContent = "cruzado";
      estado.classList.add("listo");
    }, fin);
    setTimeout(ciclo, fin + PAUSA);
  }

  // Arranca cuando el hero está a la vista, para que no se pierda el primer barrido.
  setTimeout(ciclo, 500);
  reducido.addEventListener("change", (e) => { if (e.matches) final(); });
})();
