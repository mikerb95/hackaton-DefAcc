// Usuario robot del asistente: entra al panel, pregunta, ve la tarjeta, aprueba o descarta.
// Modelo simulado (radar/asistente/motor.py, modelo_simulado): no gasta IA.
import { test, expect } from "@playwright/test";

const CLAVE = "clave-de-prueba-e2e";

async function entrar(page, usuario) {
  const r = await page.request.post("/api/sesion", { data: { usuario, clave: CLAVE } });
  expect(r.ok()).toBeTruthy();
  await page.goto("/panel/#resumen");
  await expect(page.locator("#asistente-saludo")).toContainText("Hola");
}

async function estados(page) {
  const d = await (await page.request.get("/api/hallazgos")).json();
  return d.hallazgos.map((h) => h.estado);
}

test("pregunta y ve los pasos y la respuesta", async ({ page }) => {
  await entrar(page, "ana");
  await expect(page.locator("#asistente-saludo")).toHaveText("Hola, Ana.");
  await expect(page.locator(".asis-atajo").first()).toBeVisible();
  await page.fill("#asistente-pregunta", "¿Cómo estamos hoy?");
  await page.press("#asistente-pregunta", "Enter");
  await expect(page.locator(".asis-pasos li")).toContainText("Revisando el resumen del radar");
  await expect(page.locator(".asis-respuesta")).toContainText("Respuesta simulada");
  await expect(page.locator(".asis-respuesta a")).toHaveAttribute("href", "/panel/#resumen");
  await expect(page.locator("#asistente-ia")).toHaveClass(/is-chat/);
  await page.screenshot({ path: "capturas/1-respuesta.png", fullPage: false });
});

test("propone un cambio, se aprueba y queda en la base", async ({ page }) => {
  await entrar(page, "ana");
  const antes = (await estados(page)).filter((e) => e === "en_curso").length;
  await page.fill("#asistente-pregunta", "marca el primero en curso");
  await page.press("#asistente-pregunta", "Enter");
  const tarjeta = page.locator(".asis-tarjeta");
  await expect(tarjeta).toBeVisible();
  await expect(tarjeta.locator("del")).toHaveText("Nuevo");
  await expect(tarjeta.locator("ins")).toHaveText("En curso");
  // Antes de aprobar no cambió nada.
  expect((await estados(page)).filter((e) => e === "en_curso").length).toBe(antes);
  await page.screenshot({ path: "capturas/2-tarjeta.png" });
  await tarjeta.getByRole("button", { name: "Aprobar y guardar" }).click();
  await expect(tarjeta.locator(".asis-sello")).toContainText("Aprobado por Ana");
  await expect(page.locator(".asis-respuesta").last()).toContainText("Listo");
  expect((await estados(page)).filter((e) => e === "en_curso").length).toBe(antes + 1);
  await page.screenshot({ path: "capturas/3-aprobada.png" });
});

test("descartar no cambia la base", async ({ page }) => {
  await entrar(page, "ana");
  const antes = await estados(page);
  await page.fill("#asistente-pregunta", "marca el primero en curso");
  await page.press("#asistente-pregunta", "Enter");
  const tarjeta = page.locator(".asis-tarjeta");
  await tarjeta.getByRole("button", { name: "Descartar" }).click();
  await expect(tarjeta.locator(".asis-sello")).toHaveText("Descartado");
  await expect(page.locator(".asis-respuesta").last()).toContainText("no cambio nada");
  expect(await estados(page)).toEqual(antes);
});

test("el lector pide un cambio y no aparece tarjeta", async ({ page }) => {
  await entrar(page, "luis");
  await page.fill("#asistente-pregunta", "marca el primero en curso");
  await page.press("#asistente-pregunta", "Enter");
  await expect(page.locator(".asis-respuesta")).toContainText("solo puedes consultar");
  await expect(page.locator(".asis-tarjeta")).toHaveCount(0);
});

test("recientes y retomar con ?c=", async ({ page }) => {
  await entrar(page, "ana");
  await page.fill("#asistente-pregunta", "Pregunta para retomar");
  await page.press("#asistente-pregunta", "Enter");
  await expect(page.locator(".asis-respuesta")).toContainText("Respuesta simulada");
  const id = new URL(page.url()).searchParams.get("c");
  expect(id).toBeTruthy();
  await expect(page.locator(".asis-reciente-pregunta").first()).toHaveText("Pregunta para retomar");
  await page.goto(`/panel/?c=${id}#resumen`);
  await expect(page.locator(".asis-pregunta")).toHaveText("Pregunta para retomar");
  await expect(page.locator(".asis-respuesta")).toContainText("Respuesta simulada");
});

test("el buscador sin IA encuentra productos", async ({ page }) => {
  await entrar(page, "ana");
  await page.fill("#asistente-pregunta", "winrar");
  const busqueda = page.locator("#asistente-busqueda");
  await expect(busqueda).toBeVisible();
  await expect(busqueda).toContainText("Producto");
  await page.screenshot({ path: "capturas/4-buscador.png" });
});

test("el admin ve los topes y la auditoría", async ({ page }) => {
  await entrar(page, "jefa");
  await page.goto("/panel/#configuracion");
  const topes = page.locator("#asistente-topes");
  await expect(topes.locator("input[name=dia]")).toHaveValue("3");
  await expect(topes).toContainText("Propuestas decididas");
  await expect(topes).toContainText("proponer_estado_hallazgo: aprobada");
  await page.screenshot({ path: "capturas/5-topes.png", fullPage: true });
});
