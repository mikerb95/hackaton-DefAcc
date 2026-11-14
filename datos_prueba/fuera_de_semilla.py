"""Conjunto de exactitud no ajustada para el normalizador.

Nombres sucios de productos reales que NO están en la semilla ni en la tabla de alias, tal
como los reportaría un RMM. Lo esperado se escribió antes de correr el normalizador, a
partir del nombre con que NVD publica las CVE de cada producto; solo se comprobó que los
pares existen en el diccionario. Si el normalizador falla aquí, se reporta: no se ajusta
la tabla de alias a este conjunto (dejaría de medir generalización).

Cada caso: (programa, versión, proveedor, pares aceptables). Un conjunto vacío significa
que el producto no está en NVD y lo correcto es "sin CPE".
"""

from __future__ import annotations

CASOS: list[tuple[str, str, str | None, frozenset[str]]] = [
    # Navegadores y correo
    ("Microsoft Edge", "131.0.2903.70", "Microsoft Corporation",
     frozenset({"microsoft:edge_chromium"})),
    ("Mozilla Thunderbird (x64 es-ES)", "128.4.2", "Mozilla", frozenset({"mozilla:thunderbird"})),
    ("Opera Stable 114.0.5282.102", "114.0.5282.102", "Opera Software",
     frozenset({"opera:opera_browser"})),
    ("Brave", "131.1.73.89", "Brave Software Inc", frozenset({"brave:brave"})),
    # Utilidades
    ("Wireshark 4.2.5 64-bit", "4.2.5", "The Wireshark developer community",
     frozenset({"wireshark:wireshark"})),
    ("FileZilla Client 3.67.0", "3.67.0", "Tim Kosse",
     frozenset({"filezilla-project:filezilla_client"})),
    ("KeePass Password Safe 2.57", "2.57", "Dominik Reichl",
     frozenset({"keepass:keepass", "keepass:password_safe"})),
    ("WinSCP 6.3.5", "6.3.5", "Martin Prikryl", frozenset({"winscp:winscp"})),
    ("Greenshot 1.2.10.6", "1.2.10.6", "Greenshot", frozenset({"getgreenshot:greenshot"})),
    ("Audacity 3.6.4", "3.6.4", "Audacity Team", frozenset({"audacityteam:audacity"})),
    ("GIMP 2.10.38", "2.10.38", "The GIMP Team", frozenset({"gimp:gimp"})),
    # HeidiSQL no tiene CPE en NVD (verificado en el diccionario): lo correcto es sin CPE.
    ("HeidiSQL 12.8.0.6908", "12.8.0.6908", "Ansgar Becker", frozenset()),
    ("Foxit PDF Reader", "2024.3.0.26795", "Foxit Software Inc.",
     frozenset({"foxit:pdf_reader"})),
    # Ofimática y desarrollo
    ("LibreOffice 24.8.3.2", "24.8.3.2", "The Document Foundation",
     frozenset({"libreoffice:libreoffice"})),
    ("Microsoft Visual Studio Code (User)", "1.95.3", "Microsoft Corporation",
     frozenset({"microsoft:visual_studio_code"})),
    ("Postman x64 11.2.0", "11.2.0", "Postman", frozenset({"postman:postman"})),
    ("Oracle VM VirtualBox 7.0.18", "7.0.18", "Oracle Corporation",
     frozenset({"oracle:vm_virtualbox"})),
    # Servidores y bases de datos
    ("Apache Tomcat 9.0 Tomcat9 (remove only)", "9.0.93", "The Apache Software Foundation",
     frozenset({"apache:tomcat"})),
    ("PostgreSQL 16", "16.4", "PostgreSQL Global Development Group",
     frozenset({"postgresql:postgresql"})),
    ("Microsoft SQL Server 2019 (64-bit)", "15.0.2000.5", "Microsoft Corporation",
     frozenset({"microsoft:sql_server"})),
    # Acceso remoto y VPN
    ("AnyDesk", "8.0.14", "AnyDesk Software GmbH", frozenset({"anydesk:anydesk"})),
    ("OpenVPN 2.6.10-I001 amd64", "2.6.10", "OpenVPN, Inc.", frozenset({"openvpn:openvpn"})),
    ("FortiClient VPN", "7.2.4.0972", "Fortinet Technologies Inc",
     frozenset({"fortinet:forticlient"})),
    ("Cisco Secure Client - AnyConnect VPN", "5.1.4.74", "Cisco Systems, Inc.",
     frozenset({"cisco:secure_client", "cisco:anyconnect_secure_mobility_client"})),
    ("Citrix Workspace 2402", "24.2.0.187", "Citrix Systems, Inc.",
     frozenset({"citrix:workspace"})),
    # Nube y mensajería
    ("Microsoft OneDrive", "24.201.1006.0005", "Microsoft Corporation",
     frozenset({"microsoft:onedrive"})),
    ("Dropbox", "212.4.5767", "Dropbox, Inc.", frozenset({"dropbox:dropbox"})),
    # Sin CPE: internos o genéricos que no están en NVD
    ("Intranet Corporativa Kiosko", "3.1.0", "Área de Sistemas", frozenset()),
    ("Controlador Táctil Genérico HID", "10.0.19041.1", "Fabricante del Equipo", frozenset()),
    ("Slack", "4.41.97", "Slack Technologies Inc.", frozenset()),
]


def medir(dic=None) -> dict:
    """Exactitud del normalizador sobre este conjunto (sin modelo)."""
    from radar.ingesta import normalizador as nz

    dic = dic or nz.diccionario_por_defecto()
    resultados = []
    for programa, version, proveedor, aceptables in CASOS:
        limpio = nz.limpiar_nombre(programa)
        d = nz.decidir(limpio, dic, proveedor, usar_modelo=False)
        obtenidos = frozenset(d.pares)
        ok = (not aceptables and not obtenidos) or (
            bool(obtenidos) and obtenidos <= aceptables
        )
        resultados.append({
            "programa": programa, "esperado": sorted(aceptables), "obtenido": sorted(obtenidos),
            "metodo": d.metodo, "empate": d.empate, "correcto": ok,
            "por_alias": d.metodo == "exacto",
        })
    correctos = sum(r["correcto"] for r in resultados)
    con_cpe = [r for r in resultados if r["esperado"]]
    return {
        "casos": len(resultados),
        "correctos": correctos,
        "exactitud_pct": round(100 * correctos / len(resultados), 1),
        "casos_con_cpe": len(con_cpe),
        "cpe_equivocado": sum(1 for r in con_cpe if r["obtenido"] and not r["correcto"]),
        "sin_cpe_indebido": sum(1 for r in con_cpe if not r["obtenido"]),
        "cpe_inventado": sum(1 for r in resultados if not r["esperado"] and r["obtenido"]),
        "resueltos_por_alias": sum(r["por_alias"] for r in resultados),
        "errores": [r for r in resultados if not r["correcto"]],
    }
