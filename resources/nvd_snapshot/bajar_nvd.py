import json, sys, time, urllib.parse, urllib.request, pathlib
out = pathlib.Path(sys.argv[1])
pares = sys.argv[2:]
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
import os
CLAVE = next((l.split("=",1)[1].strip() for l in open(os.environ["ENV_FILE"]) if l.startswith("NVD_API_KEY=")), "")
PAUSA = 0.8 if CLAVE else 6.5
def get(url):
    for i in range(6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "radar-prueba/0.1", **({"apiKey": CLAVE} if CLAVE else {})})
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 403: raise SystemExit("403: clave rechazada")
            espera = int(e.headers.get("Retry-After", 30)) if e.code == 429 else 10 * (i + 1)
            print("  HTTP", e.code, "espero", espera, flush=True); time.sleep(espera)
        except Exception as e:
            print("  error", e, flush=True); time.sleep(10 * (i + 1))
    raise SystemExit("fallo " + url)
for par in pares:
    destino = out / (par.replace(":", "__").replace("\\", "") + ".json")
    if destino.exists(): print("ya", par); continue
    vendor, prod = par.split(":", 1)
    vms = f"cpe:2.3:a:{vendor}:{prod}"
    vulns, start = [], 0
    while True:
        q = urllib.parse.urlencode({"virtualMatchString": vms, "startIndex": start, "resultsPerPage": 2000}) + "&noRejected"
        d = get(BASE + "?" + q); time.sleep(PAUSA)
        vulns += d.get("vulnerabilities", [])
        total = d.get("totalResults", 0)
        start += d.get("resultsPerPage", 0)
        print(par, len(vulns), "/", total, flush=True)
        if start >= total or not d.get("resultsPerPage"): break
    destino.write_text(json.dumps({"par": par, "total": total, "vulnerabilities": vulns}))
