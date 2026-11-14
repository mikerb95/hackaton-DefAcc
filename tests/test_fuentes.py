"""Cliente de NVD, EPSS y descarga en línea, con transporte simulado (sin red)."""

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from radar import bd
from radar.fuentes import epss as fuente_epss
from radar.fuentes.nvd import ClienteNvd, ErrorNvd, ventanas


def item(cve_id, criterio="cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*", hasta="7.13"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-11-01T00:00:00.000",
            "lastModified": "2026-11-13T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "x"}],
            "metrics": {},
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": criterio,
                                    "vulnerable": True,
                                    "versionEndExcluding": hasta,
                                },
                                {
                                    "criteria": "cpe:2.3:a:otro:prod:*:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                },
                            ]
                        }
                    ]
                }
            ],
        }
    }


def cliente_con(respuestas, clave=""):
    """ClienteNvd cuyo transporte devuelve `respuestas` en orden y anota cada petición.

    `clave=""` explícita: así nunca toma la NVD_API_KEY real del .env.
    """
    pedidas, esperas = [], []
    cola = list(respuestas)

    def manejar(peticion):
        pedidas.append(peticion)
        r = cola.pop(0)
        return r if isinstance(r, httpx.Response) else httpx.Response(200, json=r)

    http = httpx.Client(transport=httpx.MockTransport(manejar))
    return ClienteNvd(clave=clave, cliente=http, dormir=esperas.append), pedidas, esperas


def test_paginacion_y_parametros():
    pagina1 = {
        "totalResults": 3,
        "resultsPerPage": 2,
        "vulnerabilities": [item("CVE-2026-0001"), item("CVE-2026-0002")],
    }
    pagina2 = {"totalResults": 3, "resultsPerPage": 1, "vulnerabilities": [item("CVE-2026-0003")]}
    nvd, pedidas, esperas = cliente_con([pagina1, pagina2])
    cves = nvd.por_par("rarlab:winrar")
    assert sorted(cves) == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    q = parse_qs(urlparse(str(pedidas[1].url)).query, keep_blank_values=True)
    assert q["virtualMatchString"] == ["cpe:2.3:a:rarlab:winrar"]
    assert q["startIndex"] == ["2"]
    assert "noRejected" in q and q["noRejected"] == [""]
    assert str(pedidas[0].url).endswith("&noRejected")
    assert esperas == [6.0]  # pausa sin clave entre las dos peticiones
    assert "apiKey" not in pedidas[0].headers


def test_clave_en_cabecera_y_pausa_corta():
    nvd, pedidas, _esperas = cliente_con(
        [{"totalResults": 1, "resultsPerPage": 1, "vulnerabilities": [item("CVE-2026-0001")]}],
        clave="clave-de-prueba",
    )
    nvd.por_par("rarlab:winrar")
    assert pedidas[0].headers["apiKey"] == "clave-de-prueba"
    assert nvd.pausa == 0.7


def test_429_espera_retry_after_y_5xx_reintenta():
    ok = {"totalResults": 1, "resultsPerPage": 1, "vulnerabilities": [item("CVE-2026-0001")]}
    nvd, pedidas, esperas = cliente_con(
        [httpx.Response(429, headers={"Retry-After": "12"}), httpx.Response(503), ok]
    )
    assert list(nvd.por_par("rarlab:winrar")) == ["CVE-2026-0001"]
    assert len(pedidas) == 3
    assert 12.0 in esperas and 20.0 in esperas  # Retry-After y espera creciente del 5xx


def test_403_no_reintenta():
    nvd, pedidas, _ = cliente_con([httpx.Response(403)])
    with pytest.raises(ErrorNvd, match="403"):
        nvd.por_par("rarlab:winrar")
    assert len(pedidas) == 1


def test_se_rinde_tras_los_intentos():
    nvd, _pedidas, _ = cliente_con([httpx.Response(500)] * 6)
    with pytest.raises(ErrorNvd, match="6 intentos"):
        nvd.por_par("rarlab:winrar")


def test_incremental_parte_en_ventanas_de_120_dias():
    hasta = datetime(2026, 11, 14, tzinfo=UTC)
    desde = hasta - timedelta(days=200)
    assert len(ventanas(desde, hasta)) == 2
    vacio = {"totalResults": 0, "resultsPerPage": 0, "vulnerabilities": []}
    nvd, pedidas, _ = cliente_con([vacio, vacio])
    nvd.por_par("rarlab:winrar", desde=desde, hasta=hasta)
    q = parse_qs(urlparse(str(pedidas[0].url)).query)
    assert q["lastModStartDate"] == ["2026-04-28T00:00:00.000"]
    assert q["lastModEndDate"] == ["2026-08-26T00:00:00.000"]


def test_leer_csv_epss():
    texto = (
        "#model_version:v2026.06.15,score_date:2026-11-14T12:00:22Z\n"
        "cve,epss,percentile\nCVE-2018-20250,0.96004,0.99877\nCVE-1999-0001,0.04,0.9\n"
    )
    senales = fuente_epss.leer_csv(texto, solo={"CVE-2018-20250", "CVE-2099-0001"})
    assert list(senales) == ["CVE-2018-20250"]  # CVE-2099-0001 no aparece: no se inventa
    assert senales["CVE-2018-20250"].fecha.isoformat() == "2026-11-14"


def test_descarga_en_linea_con_par_caido(tmp_path, monkeypatch):
    from worker import descargar

    kev = {
        "catalogVersion": "prueba",
        "vulnerabilities": [{"cveID": "CVE-2026-0001", "knownRansomwareCampaignUse": "Known"}],
    }
    monkeypatch.setattr(
        descargar.httpx,
        "get",
        lambda *a, **k: httpx.Response(200, json=kev, request=httpx.Request("GET", "https://kev")),
    )
    ok = {"totalResults": 1, "resultsPerPage": 1, "vulnerabilities": [item("CVE-2026-0001")]}
    nvd, _, _ = cliente_con([ok, httpx.Response(403)])

    c = bd.conectar(ruta_sqlite=tmp_path / "radar.db")
    e = descargar.descargar_en_linea(
        c, ["rarlab:winrar", "google:chrome"], con_epss=False, cliente=nvd
    )
    assert e.fuentes == {"kev": True, "nvd": False, "epss": False}  # un par caído no es cero
    assert "google:chrome" in e.error
    [cve] = bd.leer_cves(c)
    assert [r.par for r in cve.rangos] == ["rarlab:winrar"]  # rangos ajenos fuera
    assert bd.leer_senales(c).kev["CVE-2026-0001"].ransomware
    c.close()


def test_osv_respuesta_incompleta_es_fuente_caida():
    """Menos resultados que consultas: error (fuente caída), nunca "sin avisos"."""
    from radar.fuentes import osv

    def manejar(peticion):
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "UBUNTU-1"}]}]})

    http = httpx.Client(transport=httpx.MockTransport(manejar))
    consultas = [
        osv.Consulta("openssl", "3.0.2-0ubuntu1.15", "Ubuntu:22.04:LTS"),
        osv.Consulta("curl", "7.81.0-1ubuntu1.16", "Ubuntu:22.04:LTS"),
    ]
    with pytest.raises(osv.RespuestaIncompleta, match="1 resultados para 2 consultas"):
        osv.consultar_lote(consultas, http)
    assert issubclass(osv.RespuestaIncompleta, ValueError)  # el worker la registra osv: False


def test_fin_de_soporte_eol_true_es_vencido_sin_fecha():
    from datetime import date

    from radar.equipos.contratos import SistemaReportado
    from radar.equipos.so import soporte
    from radar.fuentes import finsoporte

    ciclos = finsoporte.reducir(
        [
            {"cycle": "18.04", "eol": True},
            {"cycle": "24.04", "eol": False},
            {"cycle": "20.04", "eol": "2025-05-31"},
        ]
    )
    assert ciclos[0]["vencido_sin_fecha"] and ciclos[0]["fin"] is None
    assert not ciclos[1]["vencido_sin_fecha"] and ciclos[1]["fin"] is None
    catalogo = {"productos": {"ubuntu": ciclos}}
    hoy = date(2026, 11, 14)

    def de(version):
        so = SistemaReportado(familia="linux", nombre="Ubuntu", version=version, distro="ubuntu")
        return soporte(so, catalogo)

    assert de("18.04").vencido(hoy)  # eol: true -> vencido aunque no haya fecha
    assert not de("24.04").vencido(hoy)  # eol: false -> con soporte
    assert de("20.04").vencido(hoy) and de("20.04").fin == date(2025, 5, 31)
