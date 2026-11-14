"""Auxiliar de planeacion (no es codigo del proyecto). Resume rangos por par y KEV."""
import json, re, sys, pathlib
raw = pathlib.Path(sys.argv[1]); kev = {v["cveID"]: v for v in json.load(open(sys.argv[2]))["vulnerabilities"]}
def ver(s):
    if s is None: return None
    m = re.fullmatch(r"(\d+(?:\.\d+){0,3})", s.strip())
    if not m: return None
    t = [int(x) for x in m.group(1).split(".")]; return tuple(t + [0] * (4 - len(t)))
def rangos(v, vendor, prod):
    out = []
    for conf in v["cve"].get("configurations", []):
        for n in conf.get("nodes", []):
            for m in n.get("cpeMatch", []):
                if not m.get("vulnerable"): continue
                p = m["criteria"].split(":")
                if p[3] != vendor or p[4].replace("\\", "") != prod.replace("\\", ""): continue
                out.append({"version": p[5], "desde": m.get("versionStartIncluding") or m.get("versionStartExcluding"),
                            "desde_incluye": "versionStartIncluding" in m,
                            "hasta": m.get("versionEndIncluding") or m.get("versionEndExcluding"),
                            "hasta_incluye": "versionEndIncluding" in m})
    return out
def afecta(r, x):
    X = ver(x)
    if X is None: return None
    if r["version"] not in ("*", "-") :
        return ver(r["version"]) == X if ver(r["version"]) else None
    if r["desde"] is None and r["hasta"] is None: return "todas"
    if r["desde"]:
        D = ver(r["desde"]);
        if D is None: return None
        if X < D or (X == D and not r["desde_incluye"]): return False
    if r["hasta"]:
        H = ver(r["hasta"]);
        if H is None: return None
        if X > H or (X == H and not r["hasta_incluye"]): return False
    return True
def metric(v):
    m = v["cve"].get("metrics", {})
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            d = m[k][0]["cvssData"]; return d.get("baseScore")
    return None
def cargar(par):
    f = raw / (par.replace(":", "__").replace("\\", "") + ".json")
    return json.load(open(f))["vulnerabilities"]
if __name__ == "__main__":
    modo = sys.argv[3]
    if modo == "resumen":
        for f in sorted(raw.glob("*.json")):
            d = json.load(open(f)); vendor, prod = d["par"].split(":", 1)
            con = [v for v in d["vulnerabilities"] if rangos(v, vendor, prod)]
            k = [v for v in con if v["cve"]["id"] in kev]
            print(f"\n## {d['par']}  total={d['total']} con_rango_propio={len(con)} kev={len(k)}")
            for v in sorted(k, key=lambda v: v["cve"]["id"])[-6:]:
                rs = rangos(v, vendor, prod)
                print("  KEV", v["cve"]["id"], metric(v), "ransomware" if kev[v["cve"]["id"]]["knownRansomwareCampaignUse"]=="Known" else "", [ (r["version"], r["desde"], r["desde_incluye"], r["hasta"], r["hasta_incluye"]) for r in rs][:3])
            ult = sorted(con, key=lambda v: v["cve"]["published"])[-3:]
            for v in ult:
                rs = rangos(v, vendor, prod)
                print("  rec", v["cve"]["id"], v["cve"]["published"][:10], metric(v), [ (r["version"], r["desde"], r["hasta"], r["hasta_incluye"]) for r in rs][:2])
    elif modo == "versiones":
        # argv: par version1 version2 ...
        par = sys.argv[4]; vendor, prod = par.split(":", 1)
        vs = cargar(par)
        for x in sys.argv[5:]:
            hits, imprec = [], 0
            for v in vs:
                res = [afecta(r, x) for r in rangos(v, vendor, prod)]
                if True in res: hits.append(v)
                elif "todas" in res: imprec += 1
            k = [v["cve"]["id"] for v in hits if v["cve"]["id"] in kev]
            mx = max([metric(v) or 0 for v in hits], default=0)
            print(f"{par} {x}: afectan={len(hits)} kev={k} peor_cvss={mx} sin_version={imprec}")
