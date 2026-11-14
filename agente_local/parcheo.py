"""Ejecución de planes de parcheo en el equipo (docs/plan-parcheo.md). Solo librería estándar.

Promesa: el agente nunca deja el equipo peor de lo que estaba y nunca miente en el resultado.

- Solo pide planes si el parcheo se habilitó al instalar, con la clave pública del aprobador
  fijada en este equipo (`parcheo.json`). El servidor no puede cambiarla.
- Un plan se ejecuta solo si: la firma Ed25519 es de una clave fijada, es para este equipo y
  esta plataforma, está vigente, no se ejecutó antes y cada acción es del catálogo cerrado.
  Si algo falla, se rechaza el plan entero sin tocar nada.
- Cada acción: medir, prechequear, respaldar, aplicar, medir de nuevo y verificar. Si la
  verificación falla, revertir y volver a medir. El estado final es lo medido.
- Todo queda en un diario con `fsync` por línea. Si el proceso muere a mitad, la próxima
  corrida mide el estado real y reporta la acción como `interrumpido`, sin reintentarla.
- Nunca reinicia el equipo.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from agente_local import VERSION, ed25519
from agente_local import plan_parcheo as catalogo

ARCHIVO_CONFIG = "parcheo.json"
CARPETA = "parcheo"
CANDADO = "candado"
HORAS_CANDADO = 8  # un candado más viejo es de un proceso que murió
MAX_EJECUTADOS = 500
LARGO_SALIDA = 4000

# Estados finales de una acción (los mismos que valida el servidor).
APLICADO = "aplicado"
YA_AL_DIA = "ya_al_dia"
REVERTIDO = "revertido"
SIN_CAMBIOS = "sin_cambios"
OMITIDO = "omitido"
FALLIDO = "fallido_sin_revertir"
INTERRUMPIDO = "interrumpido"
RECHAZADO = "rechazado"


class Rechazo(ValueError):
    """El plan no se ejecuta. El mensaje va al resultado."""


def ahora_texto() -> str:
    return catalogo.fecha(datetime.now(UTC))


# ---------------------------------------------------------------------------
# Configuración local
# ---------------------------------------------------------------------------


class Config:
    """`parcheo.json` en la carpeta protegida del agente (solo SYSTEM o root)."""

    def __init__(self, carpeta: Path):
        self.carpeta = carpeta
        self.ruta = carpeta / ARCHIVO_CONFIG
        try:
            self.datos: dict[str, Any] = json.loads(self.ruta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.datos = {}

    @property
    def habilitado(self) -> bool:
        return bool(self.datos.get("habilitado")) and bool(self.claves)

    @property
    def claves(self) -> list[bytes]:
        claves = []
        for texto in self.datos.get("claves") or []:
            try:
                clave = base64.b64decode(texto, validate=True)
            except (binascii.Error, ValueError, TypeError):
                continue
            if len(clave) == ed25519.LARGO_CLAVE:
                claves.append(clave)
        return claves

    def ejecutado(self, plan_id: str) -> bool:
        return plan_id in (self.datos.get("ejecutados") or [])

    def registrar_ejecutado(self, plan_id: str) -> None:
        lista = [p for p in self.datos.get("ejecutados") or [] if p != plan_id]
        self.datos["ejecutados"] = (lista + [plan_id])[-MAX_EJECUTADOS:]
        self.guardar()

    def habilitar(self, claves_b64: list[str]) -> list[str]:
        """Fija las claves del aprobador. Devuelve sus huellas. Lanza ValueError si alguna
        no es una clave Ed25519 en base64."""
        huellas = []
        for texto in claves_b64:
            try:
                clave = base64.b64decode(texto.strip(), validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError("La clave de aprobación no es base64 válido.") from error
            if len(clave) != ed25519.LARGO_CLAVE:
                raise ValueError("La clave de aprobación debe medir 32 bytes.")
            huellas.append(ed25519.huella(clave))
        self.datos["habilitado"] = True
        self.datos["claves"] = [t.strip() for t in claves_b64]
        self.guardar()
        return huellas

    def deshabilitar(self) -> None:
        self.datos["habilitado"] = False
        self.guardar()

    def guardar(self) -> None:
        from agente_local.envio import proteger

        self.carpeta.mkdir(parents=True, exist_ok=True)
        temporal = self.ruta.with_suffix(".tmp")
        temporal.write_text(json.dumps(self.datos, indent=2), encoding="utf-8")
        os.replace(temporal, self.ruta)
        proteger(self.ruta)


# ---------------------------------------------------------------------------
# Verificación del plan
# ---------------------------------------------------------------------------


def verificar_plan(
    entrega: dict[str, Any],
    config: Config,
    equipo_id: str,
    plataforma: str | None,
    ahora: datetime | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Devuelve (plan, bytes canónicos) o lanza `Rechazo`. No toca nada del equipo."""
    ahora = ahora or datetime.now(UTC)
    texto = entrega.get("plan")
    firma_b64 = entrega.get("firma")
    if not isinstance(texto, str) or not isinstance(firma_b64, str):
        raise Rechazo("entrega sin plan o sin firma")
    try:
        bytes_plan = texto.encode("ascii")
        firma = base64.b64decode(firma_b64, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise Rechazo("plan o firma mal codificados") from error
    # La firma se comprueba contra las claves fijadas en este equipo, nunca contra la que
    # venga en la entrega.
    if not any(ed25519.verificar(clave, bytes_plan, firma) for clave in config.claves):
        raise Rechazo("la firma no es de ninguna clave de aprobación fijada en este equipo")
    try:
        plan = json.loads(texto)
        catalogo.validar_plan(plan)
    except (ValueError, catalogo.PlanInvalido) as error:
        raise Rechazo(f"plan fuera del catálogo: {error}") from error
    if catalogo.canonico(plan) != bytes_plan:
        raise Rechazo("el plan no está en forma canónica")
    if plan["equipo_id"] != equipo_id:
        raise Rechazo("el plan es para otro equipo")
    if plan["plataforma"] != plataforma:
        raise Rechazo(f"el plan es para {plan['plataforma']} y este equipo es {plataforma}")
    margen = timedelta(minutes=catalogo.MARGEN_RELOJ_MINUTOS)
    if catalogo.leer_fecha(plan["emitido"]) > ahora + margen:
        raise Rechazo("el plan está fechado en el futuro (reloj del equipo o del servidor)")
    if catalogo.leer_fecha(plan["vence"]) < ahora - margen:
        raise Rechazo("el plan venció")
    if config.ejecutado(plan["plan_id"]):
        raise Rechazo("ese plan ya se ejecutó en este equipo")
    return plan, bytes_plan


# ---------------------------------------------------------------------------
# Correr programas
# ---------------------------------------------------------------------------


class Corredor:
    """Corre programas sin shell y anota cada paso para la evidencia del reporte."""

    def __init__(self) -> None:
        self.pasos: list[dict[str, Any]] = []

    def correr(
        self,
        orden: list[str],
        tiempo: int = 600,
        entorno: dict[str, str] | None = None,
        anotar: bool = True,
    ) -> dict[str, Any]:
        inicio = time.monotonic()
        codigo: int | None
        try:
            r = subprocess.run(
                orden,
                capture_output=True,
                timeout=tiempo,
                check=False,
                stdin=subprocess.DEVNULL,
                env={**os.environ, **entorno} if entorno else None,
            )
            codigo = r.returncode
            salida = _decodificar(r.stdout + b"\n" + r.stderr).strip()
        except subprocess.TimeoutExpired as error:
            codigo = None
            salida = f"[sin terminar tras {tiempo} s] " + _decodificar(error.stdout or b"")
        except OSError as error:
            codigo = None
            salida = f"[no se pudo ejecutar] {error}"
        paso = {
            "orden": [str(p)[:200] for p in orden[:30]],
            "codigo": codigo,
            "salida": salida[-LARGO_SALIDA:],
            "duracion": round(time.monotonic() - inicio, 2),
        }
        if anotar:
            self.pasos.append(paso)
        return paso


def _decodificar(datos: bytes) -> str:
    for codificacion in ("utf-8", "cp1252"):
        try:
            return datos.decode(codificacion)
        except UnicodeDecodeError:
            continue
    return datos.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# Ejecutores
# ---------------------------------------------------------------------------


@dataclass
class Previo:
    """Lo que dice el prechequeo. `final`: la acción termina ahí (ya al día u omitida)."""

    final: str | None = None
    motivo: str = ""
    datos: dict[str, Any] = field(default_factory=dict)


@dataclass
class Respaldo:
    reversible: bool
    motivo: str = ""
    datos: dict[str, Any] = field(default_factory=dict)


@dataclass
class Verificacion:
    ok: bool
    motivo: str = ""
    reinicio: bool = False
    cumple_minimo: bool | None = None


class Ejecutor(Protocol):
    """Lo que implementa cada ejecutor del catálogo (parcheo_windows, parcheo_linux)."""

    def medir(self, accion: dict[str, Any]) -> dict[str, Any]: ...

    def prechequear(self, accion: dict[str, Any], antes: dict[str, Any]) -> Previo: ...

    def respaldar(
        self, accion: dict[str, Any], antes: dict[str, Any], previo: Previo
    ) -> Respaldo: ...

    def aplicar(self, accion: dict[str, Any], previo: Previo) -> dict[str, Any]: ...

    def verificar(
        self,
        accion: dict[str, Any],
        antes: dict[str, Any],
        despues: dict[str, Any],
        aplicado: dict[str, Any],
    ) -> Verificacion: ...

    def revertir(
        self, accion: dict[str, Any], antes: dict[str, Any], respaldo: Respaldo
    ) -> None: ...

    def igual(self, accion: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> bool: ...


# ---------------------------------------------------------------------------
# Diario
# ---------------------------------------------------------------------------


class Diario:
    """Una línea JSON por evento, con fsync: lo que sobrevive a un corte de luz."""

    def __init__(self, carpeta: Path, plan_id: str):
        carpeta.mkdir(parents=True, exist_ok=True)
        self.ruta = carpeta / f"{plan_id}.jsonl"

    def escribir(self, evento: str, **datos: Any) -> None:
        linea = json.dumps(
            {"evento": evento, "momento": ahora_texto(), **datos}, ensure_ascii=False
        )
        with open(self.ruta, "a", encoding="utf-8") as archivo:
            archivo.write(linea + "\n")
            archivo.flush()
            os.fsync(archivo.fileno())

    def leer(self) -> list[dict[str, Any]]:
        eventos = []
        try:
            lineas = self.ruta.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for linea in lineas:
            try:
                eventos.append(json.loads(linea))
            except ValueError:
                continue  # la última línea puede quedar cortada por un corte de luz
        return eventos


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------


def _limpio(valor: Any) -> dict[str, Any]:
    """Estado medido como mapa plano de textos cortos (lo que acepta el servidor)."""
    if not isinstance(valor, dict):
        return {}
    return {str(k)[:40]: (None if v is None else str(v)[:160]) for k, v in list(valor.items())[:20]}


def _accion_resultado(
    accion: dict[str, Any],
    estado: str,
    motivo: str,
    antes: dict[str, Any],
    despues: dict[str, Any],
    inicio: str,
    pasos: list[dict[str, Any]],
    reversible: bool | None = None,
    reinicio: bool = False,
    cumple_minimo: bool | None = None,
) -> dict[str, Any]:
    return {
        "id": accion["id"],
        "estado": estado,
        "motivo": motivo[:500],
        "antes": _limpio(antes),
        "despues": _limpio(despues),
        "reversible": reversible,
        "reinicio_pendiente": reinicio,
        "cumple_minimo": cumple_minimo,
        "inicio": inicio,
        "fin": ahora_texto(),
        "pasos": pasos[-25:],
    }


def _medir(ejecutor: Ejecutor, accion: dict[str, Any]) -> dict[str, Any]:
    try:
        return ejecutor.medir(accion) or {}
    except Exception as error:  # noqa: BLE001 - medir nunca debe tumbar el plan
        return {"error_medicion": str(error)[:150]}


def ejecutar_accion(
    accion: dict[str, Any], ejecutor: Ejecutor, corredor: Corredor
) -> dict[str, Any]:
    """Una acción de punta a punta. Nunca lanza: todo termina en un estado medido."""
    corredor.pasos = []
    inicio = ahora_texto()
    antes = _medir(ejecutor, accion)
    if "error_medicion" in antes:
        return _accion_resultado(
            accion,
            OMITIDO,
            f"no se pudo medir el estado previo: {antes['error_medicion']}",
            antes,
            {},
            inicio,
            corredor.pasos,
        )
    try:
        previo = ejecutor.prechequear(accion, antes)
    except Exception as error:  # noqa: BLE001
        return _accion_resultado(
            accion, OMITIDO, f"el prechequeo falló: {error}", antes, {}, inicio, corredor.pasos
        )
    if previo.final:
        return _accion_resultado(
            accion, previo.final, previo.motivo, antes, antes, inicio, corredor.pasos
        )
    try:
        respaldo = ejecutor.respaldar(accion, antes, previo)
    except Exception as error:  # noqa: BLE001
        return _accion_resultado(
            accion,
            OMITIDO,
            f"no se pudo preparar la reversión: {error}",
            antes,
            {},
            inicio,
            corredor.pasos,
        )

    aplicado: dict[str, Any] = {}
    error_aplicar = ""
    try:
        aplicado = ejecutor.aplicar(accion, previo) or {}
    except Exception as error:  # noqa: BLE001
        error_aplicar = f"la aplicación falló: {error}"
    despues = _medir(ejecutor, accion)

    if not error_aplicar and "error_medicion" not in despues:
        try:
            verificacion = ejecutor.verificar(accion, antes, despues, aplicado)
        except Exception as error:  # noqa: BLE001
            verificacion = Verificacion(False, f"la verificación falló: {error}")
        if verificacion.ok:
            return _accion_resultado(
                accion,
                APLICADO,
                verificacion.motivo,
                antes,
                despues,
                inicio,
                corredor.pasos,
                respaldo.reversible,
                verificacion.reinicio,
                verificacion.cumple_minimo,
            )
        motivo = verificacion.motivo or "la verificación no confirmó el cambio"
    else:
        motivo = error_aplicar or f"no se pudo medir después: {despues.get('error_medicion')}"

    # Falló. Si el equipo quedó como estaba, no hay nada que revertir.
    if "error_medicion" not in despues and ejecutor.igual(accion, antes, despues):
        return _accion_resultado(
            accion,
            SIN_CAMBIOS,
            motivo,
            antes,
            despues,
            inicio,
            corredor.pasos,
            respaldo.reversible,
        )
    if not respaldo.reversible:
        return _accion_resultado(
            accion,
            FALLIDO,
            f"{motivo}. No reversible: {respaldo.motivo}",
            antes,
            despues,
            inicio,
            corredor.pasos,
            False,
        )
    try:
        ejecutor.revertir(accion, antes, respaldo)
    except Exception as error:  # noqa: BLE001
        motivo += f". La reversión falló: {error}"
    revertido = _medir(ejecutor, accion)
    if "error_medicion" not in revertido and ejecutor.igual(accion, antes, revertido):
        return _accion_resultado(
            accion, REVERTIDO, motivo, antes, revertido, inicio, corredor.pasos, True
        )
    return _accion_resultado(
        accion,
        FALLIDO,
        f"{motivo}. Tras revertir, el estado no coincide con el previo",
        antes,
        revertido,
        inicio,
        corredor.pasos,
        True,
    )


@dataclass
class Contexto:
    """Lo que el plan necesita del equipo. En pruebas todo se reemplaza por dobles."""

    ejecutores: dict[str, Ejecutor]
    corredor: Corredor
    punto_restauracion: Callable[[str], dict[str, Any]] | None = None
    reinicio_pendiente: Callable[[], bool] | None = None


# Ejecutores que exigen un punto de restauración del sistema antes de correr (Windows).
EXIGEN_PUNTO = frozenset({"windows_update"})
PIDEN_PUNTO = frozenset({"windows_update", "postura_windows", "winget"})


def ejecutar_plan(
    plan: dict[str, Any], bytes_plan: bytes, contexto: Contexto, diario: Diario
) -> dict[str, Any]:
    """Ejecuta el plan ya verificado. Devuelve el resultado para el servidor."""
    acciones = catalogo.en_orden(plan["acciones"])
    resultado: dict[str, Any] = {
        "plan_id": plan["plan_id"],
        "equipo_id": plan["equipo_id"],
        "agente_version": VERSION,
        "estado": "ejecutado",
        "motivo": "",
        "huella_plan": catalogo.huella_plan(bytes_plan),
        "inicio": ahora_texto(),
        "fin": None,
        "punto_restauracion": None,
        "reinicio_pendiente": False,
        "acciones": [],
    }
    diario.escribir("inicio_plan", huella=resultado["huella_plan"], inicio=resultado["inicio"])

    punto: dict[str, Any] | None = None
    if contexto.punto_restauracion and any(a["ejecutor"] in PIDEN_PUNTO for a in acciones):
        try:
            punto = contexto.punto_restauracion(f"Radar plan {plan['plan_id'][:8]}")
        except Exception as error:  # noqa: BLE001
            punto = {"creado": False, "detalle": f"falló: {error}"[:300]}
        resultado["punto_restauracion"] = punto
        diario.escribir("punto_restauracion", **punto)

    for accion in acciones:
        diario.escribir("inicio_accion", id=accion["id"])
        ejecutor = contexto.ejecutores.get(accion["ejecutor"])
        if ejecutor is None:
            fila = _accion_resultado(
                accion, OMITIDO, "este agente no tiene ese ejecutor", {}, {}, ahora_texto(), []
            )
        elif (
            accion["ejecutor"] in EXIGEN_PUNTO
            and contexto.punto_restauracion
            and not (punto and punto.get("creado"))
        ):
            fila = _accion_resultado(
                accion,
                OMITIDO,
                "no hay punto de restauración del sistema y esta acción no se puede revertir "
                "(activar Protección del sistema en la unidad C:)",
                {},
                {},
                ahora_texto(),
                [],
            )
        else:
            fila = ejecutar_accion(accion, ejecutor, contexto.corredor)
        resultado["acciones"].append(fila)
        diario.escribir("fin_accion", resultado=fila)

    if contexto.reinicio_pendiente:
        try:
            resultado["reinicio_pendiente"] = bool(contexto.reinicio_pendiente())
        except Exception:  # noqa: BLE001
            resultado["reinicio_pendiente"] = False
    resultado["reinicio_pendiente"] = resultado["reinicio_pendiente"] or any(
        a["reinicio_pendiente"] for a in resultado["acciones"]
    )
    resultado["fin"] = ahora_texto()
    diario.escribir("fin_plan", resultado=resultado)
    return resultado


def resultado_rechazo(
    plan_id: str | None, equipo_id: str, bytes_plan: bytes | None, motivo: str
) -> dict[str, Any] | None:
    """Resultado de un plan rechazado, si se puede atribuir a un plan (para el servidor)."""
    if not plan_id or not bytes_plan or not catalogo.UUID.match(plan_id):
        return None
    momento = ahora_texto()
    return {
        "plan_id": plan_id,
        "equipo_id": equipo_id,
        "agente_version": VERSION,
        "estado": "rechazado",
        "motivo": motivo[:500],
        "huella_plan": catalogo.huella_plan(bytes_plan),
        "inicio": momento,
        "fin": momento,
        "punto_restauracion": None,
        "reinicio_pendiente": False,
        "acciones": [],
    }


def recuperar_interrumpido(
    diario: Diario, plan: dict[str, Any] | None, contexto: Contexto | None
) -> dict[str, Any] | None:
    """Arma el resultado de un plan que quedó a medias (el proceso murió).

    Las acciones terminadas quedan como estaban. La que estaba en curso se mide de nuevo y
    queda `interrumpido`. Las que no empezaron no van: el informe las muestra sin resultado.
    """
    eventos = diario.leer()
    if not eventos or any(e["evento"] == "fin_plan" for e in eventos):
        return None
    inicio = next((e for e in eventos if e["evento"] == "inicio_plan"), None)
    if inicio is None or plan is None:
        return None
    terminadas = [e["resultado"] for e in eventos if e["evento"] == "fin_accion"]
    hechas = {t["id"] for t in terminadas}
    en_curso = [
        e["id"] for e in eventos if e["evento"] == "inicio_accion" and e["id"] not in hechas
    ]
    por_id = {a["id"]: a for a in plan["acciones"]}
    acciones = list(terminadas)
    for id_accion in en_curso:
        accion = por_id.get(id_accion)
        if accion is None:
            continue
        ejecutor = contexto.ejecutores.get(accion["ejecutor"]) if contexto else None
        despues = _medir(ejecutor, accion) if ejecutor else {}
        acciones.append(
            _accion_resultado(
                accion,
                INTERRUMPIDO,
                "el agente se detuvo durante esta acción; el estado medido después es el que "
                "se muestra. Revisar el equipo",
                {},
                despues,
                inicio["momento"],
                [],
            )
        )
    punto = next((e for e in eventos if e["evento"] == "punto_restauracion"), None)
    return {
        "plan_id": plan["plan_id"],
        "equipo_id": plan["equipo_id"],
        "agente_version": VERSION,
        "estado": "interrumpido",
        "motivo": "el agente se detuvo antes de terminar el plan",
        "huella_plan": inicio["huella"],
        "inicio": inicio["inicio"],
        "fin": ahora_texto(),
        "punto_restauracion": {k: punto[k] for k in ("creado", "detalle") if k in punto}
        if punto
        else None,
        "reinicio_pendiente": any(a.get("reinicio_pendiente") for a in acciones),
        "acciones": acciones,
    }


# ---------------------------------------------------------------------------
# Candado
# ---------------------------------------------------------------------------


class Ocupado(RuntimeError):
    """Otro proceso del agente está parcheando."""


class Candado:
    def __init__(self, carpeta: Path):
        carpeta.mkdir(parents=True, exist_ok=True)
        self.ruta = carpeta / CANDADO

    def __enter__(self) -> Candado:  # noqa: PYI034 - Self exige Python 3.11
        for _ in range(2):
            try:
                descriptor = os.open(self.ruta, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    edad = time.time() - self.ruta.stat().st_mtime
                except OSError:
                    continue
                if edad > HORAS_CANDADO * 3600:
                    self.ruta.unlink(missing_ok=True)
                    continue
                raise Ocupado("Otro proceso del agente está parcheando.") from None
            with os.fdopen(descriptor, "w") as archivo:
                archivo.write(f"{os.getpid()} {ahora_texto()}")
            return self
        raise Ocupado("No se pudo tomar el candado del parcheo.")

    def __exit__(self, *_: object) -> None:
        self.ruta.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Resultados pendientes de enviar
# ---------------------------------------------------------------------------


def guardar_pendiente(carpeta: Path, resultado: dict[str, Any]) -> Path:
    carpeta.mkdir(parents=True, exist_ok=True)
    ruta = carpeta / f"resultado-{resultado['plan_id']}.json"
    temporal = ruta.with_suffix(".tmp")
    temporal.write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporal, ruta)
    return ruta


def pendientes(carpeta: Path) -> list[Path]:
    return sorted(carpeta.glob("resultado-*.json")) if carpeta.is_dir() else []


def diarios_abiertos(carpeta: Path) -> list[Path]:
    """Diarios sin `fin_plan` (planes interrumpidos)."""
    abiertos = []
    for ruta in sorted(carpeta.glob("*.jsonl")) if carpeta.is_dir() else []:
        diario = Diario(carpeta, ruta.stem)
        eventos = diario.leer()
        if eventos and not any(e["evento"] == "fin_plan" for e in eventos):
            abiertos.append(ruta)
    return abiertos


def resumen_texto(resultado: dict[str, Any]) -> str:
    """Una línea por acción, para la consola y el registro local."""
    lineas = [f"Plan {resultado['plan_id']}: {resultado['estado']}"]
    if resultado.get("motivo"):
        lineas.append(f"  motivo: {resultado['motivo']}")
    for accion in resultado["acciones"]:
        lineas.append(
            f"  {accion['id']}: {accion['estado']}"
            + (f" ({accion['motivo']})" if accion["motivo"] else "")
        )
    if resultado.get("reinicio_pendiente"):
        lineas.append(
            "  REINICIO PENDIENTE: el agente no reinicia; hágalo en una ventana acordada."
        )
    return "\n".join(lineas)
