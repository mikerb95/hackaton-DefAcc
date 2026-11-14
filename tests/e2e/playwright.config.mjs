// Playwright del asistente: levanta la API con una base sqlite de pruebas y el modelo
// SIMULADO (RADAR_ASISTENTE_FALSO=1). No gasta IA y nunca toca Turso. Solo desarrollo.
import { defineConfig } from "@playwright/test";

const PUERTO = 8765;
const BASE = "/tmp/radar-e2e.db";

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.mjs/,
  workers: 1,
  timeout: 30_000,
  use: { baseURL: `http://127.0.0.1:${PUERTO}`, screenshot: "only-on-failure" },
  webServer: {
    command:
      `cd ../.. && env -u TURSO_DATABASE_URL -u TURSO_AUTH_TOKEN -u VERCEL ` +
      `RADAR_SQLITE=${BASE} RADAR_DATOS=base RADAR_ASISTENTE_FALSO=1 CLAVE_ACCESO=clave-e2e ` +
      `TURSO_DATABASE_URL= .venv/bin/python tests/e2e/sembrar.py && ` +
      `env -u VERCEL RADAR_SQLITE=${BASE} RADAR_DATOS=base RADAR_ASISTENTE_FALSO=1 CLAVE_ACCESO=clave-e2e ` +
      `TURSO_DATABASE_URL= .venv/bin/uvicorn app:app --port ${PUERTO}`,
    url: `http://127.0.0.1:${PUERTO}/api/sesion`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
