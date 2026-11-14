// Tema claro u oscuro para la landing y el panel. Se carga en <head> sin defer para fijar
// data-tema antes del primer pintado (sin destello). Sin elección guardada sigue al sistema;
// con el botón, la elección queda en este navegador. Sin JS la página queda en oscuro.
(function () {
  const CLAVE = "radar-tema";
  const raiz = document.documentElement;
  const sistema = window.matchMedia("(prefers-color-scheme: light)");

  function guardado() {
    try {
      const valor = localStorage.getItem(CLAVE);
      return valor === "claro" || valor === "oscuro" ? valor : null;
    } catch {
      return null;
    }
  }

  function aplicar(tema) {
    raiz.dataset.tema = tema;
    document.querySelectorAll("[data-tema-boton]").forEach((boton) => {
      const siguiente = tema === "claro" ? "oscuro" : "claro";
      boton.setAttribute("aria-label", `Cambiar a modo ${siguiente}`);
      boton.title = `Modo ${siguiente}`;
    });
    window.dispatchEvent(new CustomEvent("tema", { detail: tema }));
  }

  aplicar(guardado() || (sistema.matches ? "claro" : "oscuro"));

  sistema.addEventListener("change", (e) => {
    if (!guardado()) aplicar(e.matches ? "claro" : "oscuro");
  });

  document.addEventListener("click", (e) => {
    if (!e.target.closest("[data-tema-boton]")) return;
    const tema = raiz.dataset.tema === "claro" ? "oscuro" : "claro";
    try { localStorage.setItem(CLAVE, tema); } catch { /* sin almacenamiento: dura la visita */ }
    aplicar(tema);
  });

  // Los botones existen recién cuando termina de leerse el HTML.
  document.addEventListener("DOMContentLoaded", () => aplicar(raiz.dataset.tema));
})();
