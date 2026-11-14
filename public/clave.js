// Botón para mostrar u ocultar lo escrito en los campos de contraseña. Se aplica solo a
// todo input[type=password] de la página, también a los que se agregan después (por
// ejemplo la fila de "nueva contraseña" que arma admin.js). Al enviar o limpiar el
// formulario el campo vuelve a ocultarse, así el navegador lo guarda como contraseña.
(function () {
  const OJO = '<svg class="icono-ver" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  const OJO_TACHADO = '<svg class="icono-ocultar" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.9 5.2A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-2.6 3.5M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7c1.9 0 3.6-.6 5-1.5M9.9 9.9a3 3 0 0 0 4.2 4.2M3 3l18 18"/></svg>';

  function fijar(boton, campo, visible) {
    campo.type = visible ? "text" : "password";
    boton.setAttribute("aria-pressed", String(visible));
    boton.setAttribute("aria-label", visible ? "Ocultar contraseña" : "Mostrar contraseña");
    boton.title = visible ? "Ocultar contraseña" : "Mostrar contraseña";
  }

  function preparar(campo) {
    if (campo.dataset.claveLista) return;
    campo.dataset.claveLista = "1";
    const envoltura = document.createElement("span");
    envoltura.className = "clave-campo";
    campo.replaceWith(envoltura);
    envoltura.append(campo);
    const boton = document.createElement("button");
    boton.type = "button";
    boton.className = "clave-ver";
    boton.setAttribute("aria-controls", campo.id || "");
    if (!campo.id) boton.removeAttribute("aria-controls");
    boton.innerHTML = OJO + OJO_TACHADO;
    envoltura.append(boton);
    fijar(boton, campo, false);

    boton.addEventListener("click", () => {
      fijar(boton, campo, campo.type === "password");
      campo.focus();
    });
    const form = campo.form;
    if (form) {
      // Captura: se oculta antes de que el manejador del formulario lea o limpie el campo.
      form.addEventListener("submit", () => fijar(boton, campo, false), true);
      form.addEventListener("reset", () => fijar(boton, campo, false));
    }
  }

  function recorrer(raiz) {
    if (raiz.matches && raiz.matches('input[type="password"]')) preparar(raiz);
    if (raiz.querySelectorAll) raiz.querySelectorAll('input[type="password"]').forEach(preparar);
  }

  document.addEventListener("DOMContentLoaded", () => {
    recorrer(document);
    new MutationObserver((cambios) => {
      cambios.forEach((c) => c.addedNodes.forEach(recorrer));
    }).observe(document.body, { childList: true, subtree: true });
  });
})();
