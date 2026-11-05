"""Cruzamento de pacotes com vulnerabilidades.

Fontes suportadas:
  * OSV.dev (online, gratuito, sem chave) - consulta por purl ou nome+ecossistema+versão
  * Relatórios de scanners importados (Trivy JSON, Grype JSON, CycloneDX com 'vulnerabilities'/VEX)
"""
import json
import urllib.request

OSV_API = "https://api.osv.dev/v1"
SEV_MAP = {"critical": "critica", "high": "alta", "medium": "media", "moderate": "media",
           "low": "baixa", "negligible": "baixa", "info": "baixa", "none": "baixa"}
SEV_ORDER = ["critica", "alta", "media", "baixa", "desconhecida"]


def norm_sev(s):
    return SEV_MAP.get(str(s or "").lower(), "desconhecida")


def _post(url, payload, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _get(url, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _osv_query(pkg):
    purl = pkg.get("purl")
    if purl:
        if "@" not in purl and pkg.get("version"):
            return {"package": {"purl": purl}, "version": pkg["version"]}
        return {"package": {"purl": purl.split("?")[0].split("#")[0]}}
    if pkg.get("ecosystem") and pkg.get("version"):
        return {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}, "version": pkg["version"]}
    return None


def osv_lookup(items, fetch=_post, get=_get):
    """items: lista de dicts com name/version/purl/ecosystem/key.
    Retorna (lista de (key, vuln_id)), dict vuln_id -> detalhes normalizados."""
    queries, keys = [], []
    for it in items:
        q = _osv_query(it)
        if q:
            queries.append(q)
            keys.append(it["key"])
    matches = []
    for i in range(0, len(queries), 1000):  # limite do querybatch
        res = fetch(f"{OSV_API}/querybatch", {"queries": queries[i:i + 1000]})
        for key, r in zip(keys[i:i + 1000], res.get("results", [])):
            for v in r.get("vulns") or []:
                matches.append((key, v["id"]))
    details = {}
    for vid in {m[1] for m in matches}:
        try:
            details[vid] = osv_normalize(get(f"{OSV_API}/vulns/{vid}"))
        except Exception:
            details[vid] = {"id": vid, "aliases": [], "severity": "desconhecida", "source": "osv"}
    return matches, details


def osv_normalize(v):
    sev = (v.get("database_specific") or {}).get("severity")
    for a in v.get("affected") or []:
        sev = sev or (a.get("ecosystem_specific") or {}).get("severity") or (a.get("database_specific") or {}).get("severity")
    fixed = {}
    for a in v.get("affected") or []:
        name = (a.get("package") or {}).get("name")
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                if "fixed" in e and name:
                    fixed.setdefault(name, e["fixed"])
    aliases = v.get("aliases") or []
    cve = next((a for a in [v["id"]] + aliases if a.startswith("CVE-")), None)
    return {
        "id": v["id"], "aliases": aliases,
        "summary": v.get("summary") or (v.get("details") or "")[:300],
        "severity": norm_sev(sev), "cvss": None,
        "published": v.get("published"),
        "url": f"https://osv.dev/vulnerability/{v['id']}" if not cve else f"https://nvd.nist.gov/vuln/detail/{cve}",
        "source": "osv", "fixed": fixed,
    }


def parse_scanner_report(doc):
    """Trivy JSON ou Grype JSON -> lista de achados {name, version, purl, vuln{...}, fixed}"""
    out = []
    if "Results" in doc:  # Trivy
        for res in doc.get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                score = None
                for c in (v.get("CVSS") or {}).values():
                    score = max(score or 0, c.get("V3Score") or c.get("V2Score") or 0) or None
                out.append({
                    "name": v.get("PkgName"), "version": v.get("InstalledVersion"),
                    "purl": (v.get("PkgIdentifier") or {}).get("PURL"),
                    "fixed": v.get("FixedVersion"),
                    "vuln": {"id": v.get("VulnerabilityID"), "aliases": [], "summary": v.get("Title") or v.get("Description"),
                             "severity": norm_sev(v.get("Severity")), "cvss": score,
                             "published": v.get("PublishedDate"), "url": v.get("PrimaryURL"), "source": "trivy"},
                })
    elif "matches" in doc:  # Grype
        for m in doc.get("matches") or []:
            v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
            score = max([c.get("metrics", {}).get("baseScore", 0) for c in v.get("cvss") or []] or [0]) or None
            aliases = [r.get("id") for r in m.get("relatedVulnerabilities") or [] if r.get("id") != v.get("id")]
            out.append({
                "name": a.get("name"), "version": a.get("version"), "purl": a.get("purl"),
                "fixed": ", ".join((v.get("fix") or {}).get("versions") or []) or None,
                "vuln": {"id": v.get("id"), "aliases": aliases, "summary": v.get("description"),
                         "severity": norm_sev(v.get("severity")), "cvss": score,
                         "published": None, "url": v.get("dataSource"), "source": "grype"},
            })
    else:
        raise ValueError("Relatório não reconhecido (esperado Trivy JSON ou Grype JSON)")
    return out


# ---------------------------------------------------------------- "essa CVE nos afeta?"
VULN_ID_PREFIXES = ("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-", "MAL-", "DSA-", "USN-")


def looks_like_vuln_id(q):
    return q.upper().startswith(VULN_ID_PREFIXES)


def _vparts(v):
    """'2.14.1' -> (2, 14, 1); comparação simples, suficiente para triagem inicial."""
    import re
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:6])


def version_status(version, affected):
    """Classifica a versão de um pacote do inventário frente a um bloco 'affected' do OSV.
    Retorna 'afetada', 'nao_afetada' ou 'verificar' (sem dados suficientes)."""
    if not version:
        return "verificar"
    versions = affected.get("versions") or []
    if version in versions:
        return "afetada"
    ranges = [r for r in affected.get("ranges") or [] if r.get("type") in ("SEMVER", "ECOSYSTEM")]
    if not ranges:
        return "nao_afetada" if versions else "verificar"
    v = _vparts(version)
    if not v:
        return "verificar"
    for r in ranges:
        intro, fixed, last = None, None, None
        for e in r.get("events") or []:
            if "introduced" in e:
                intro = _vparts(e["introduced"]) if e["introduced"] != "0" else ()
            if "fixed" in e:
                fixed = _vparts(e["fixed"])
            if "last_affected" in e:
                last = _vparts(e["last_affected"])
            if intro is not None and (fixed is not None or last is not None):
                if intro <= v and ((fixed is not None and v < fixed) or (last is not None and v <= last)):
                    return "afetada"
                intro, fixed, last = None, None, None
        if intro is not None and intro <= v:  # introduzida e nunca corrigida
            return "afetada"
    return "nao_afetada"


def osv_vuln(vuln_id, get=_get):
    """Busca a vulnerabilidade no OSV (aceita CVE, GHSA etc.). Retorna (normalizada, affected[])."""
    from urllib.error import HTTPError
    try:
        raw = get(f"{OSV_API}/vulns/{vuln_id}")
    except HTTPError as e:
        if e.code == 404:
            return None, []
        raise
    affected = [a for a in raw.get("affected") or [] if a.get("package")]
    if affected:
        return osv_normalize(raw), affected
    # Registros CVE no OSV muitas vezes só têm faixas de commits (git); os pacotes afetados
    # ficam nos aliases (ex.: CVE-2021-44228 -> GHSA-jfh8-c2jp-5v3q). Usa o primeiro alias útil.
    best = None
    for alias in (raw.get("aliases") or [])[:5]:
        try:
            other = get(f"{OSV_API}/vulns/{alias}")
        except Exception:
            continue
        pk = [a for a in other.get("affected") or [] if a.get("package")]
        if pk:
            if best is None:
                best = other
            affected.extend(pk)
    if best is None:
        return osv_normalize(raw), []
    norm = osv_normalize(best)
    norm["aliases"] = sorted(set(norm["aliases"]) | {raw["id"]} | set(raw.get("aliases") or []) - {norm["id"]})
    return norm, affected


def package_matches(pkg, affected):
    """pkg: linha de packages (name, purl, ecosystem). affected: bloco do OSV."""
    ap = affected.get("package") or {}
    a_name, a_eco = (ap.get("name") or "").lower(), (ap.get("ecosystem") or "").lower()
    if ap.get("purl") and pkg.get("purl") and pkg["purl"].split("@")[0].lower() == ap["purl"].split("@")[0].lower():
        return True
    if not a_name:
        return False
    eco = (pkg.get("ecosystem") or "").lower()
    if eco and a_eco and eco != a_eco.split(":")[0]:
        return False
    name = (pkg.get("name") or "").lower()
    # Maven no OSV usa "grupo:artefato"; no inventário guardamos só o artefato (vindo do purl)
    return name == a_name or a_name.endswith(":" + name) or a_name.endswith("/" + name)
