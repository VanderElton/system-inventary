"""Leitura de SBOMs CycloneDX (JSON) e SPDX (JSON)."""
from urllib.parse import unquote

# purl type -> ecossistema OSV
PURL_ECOSYSTEM = {
    "npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
    "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex",
    "pub": "Pub", "deb": "Debian", "apk": "Alpine", "rpm": "Red Hat", "swift": "SwiftURL",
    "cocoapods": "CocoaPods", "conan": "ConanCenter", "github": "GitHub Actions",
}


def purl_type(purl):
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0].lower()


def purl_name_version(purl):
    """pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?x=y -> (log4j-core, 2.14.1)"""
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    path, _, version = body.partition("@")
    name = unquote(path.rsplit("/", 1)[-1])
    return name, unquote(version) or None


def _licenses_cdx(comp):
    out = []
    for l in comp.get("licenses") or []:
        if "license" in l:
            out.append(l["license"].get("id") or l["license"].get("name") or "")
        elif "expression" in l:
            out.append(l["expression"])
    return " OR ".join(x for x in out if x) or None


def _walk_cdx(components):
    for c in components or []:
        yield c
        yield from _walk_cdx(c.get("components"))


def parse(doc):
    """Retorna dict: format, spec_version, packages[], vulnerabilities[]"""
    if doc.get("bomFormat") == "CycloneDX":
        return parse_cyclonedx(doc)
    if "spdxVersion" in doc:
        return parse_spdx(doc)
    raise ValueError("Formato de SBOM não reconhecido (esperado CycloneDX JSON ou SPDX JSON)")


def parse_cyclonedx(doc):
    pkgs = []
    for c in _walk_cdx(doc.get("components")):
        if c.get("type") in ("file",):
            continue
        purl = c.get("purl")
        name = c.get("name")
        if c.get("group") and not purl:
            name = f'{c["group"]}:{name}'
        pkgs.append({
            "ref": c.get("bom-ref"),
            "name": name,
            "version": c.get("version"),
            "purl": purl,
            "ecosystem": PURL_ECOSYSTEM.get(purl_type(purl), purl_type(purl)),
            "license": _licenses_cdx(c),
        })
    vulns = []
    for v in doc.get("vulnerabilities") or []:
        sev, score = None, None
        for r in v.get("ratings") or []:
            if r.get("score") and (score is None or r["score"] > score):
                score = r["score"]
            sev = sev or r.get("severity")
        aliases = [v.get("id")] + [r.get("id") for r in v.get("references") or [] if r.get("id")]
        vulns.append({
            "id": v.get("id"),
            "aliases": [a for a in aliases if a and a != v.get("id")],
            "summary": v.get("description") or v.get("detail"),
            "severity": sev, "cvss": score,
            "published": v.get("published"),
            "url": (v.get("source") or {}).get("url"),
            "affects": [a.get("ref") for a in v.get("affects") or []],
            "analysis": (v.get("analysis") or {}).get("state"),
        })
    return {"format": "CycloneDX", "spec_version": doc.get("specVersion"),
            "packages": pkgs, "vulnerabilities": vulns}


def parse_spdx(doc):
    pkgs = []
    for p in doc.get("packages") or []:
        purl = None
        for ref in p.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
        lic = p.get("licenseConcluded") or p.get("licenseDeclared")
        if lic in ("NOASSERTION", "NONE"):
            lic = None
        pkgs.append({
            "ref": p.get("SPDXID"),
            "name": p.get("name"),
            "version": p.get("versionInfo"),
            "purl": purl,
            "ecosystem": PURL_ECOSYSTEM.get(purl_type(purl), purl_type(purl)),
            "license": lic,
        })
    # o pacote "raiz" descrito pelo documento costuma ser o próprio componente
    described = set(doc.get("documentDescribes") or [])
    for rel in doc.get("relationships") or []:
        if rel.get("relationshipType") == "DESCRIBES":
            described.add(rel.get("relatedSpdxElement"))
    pkgs = [p for p in pkgs if p["ref"] not in described] or pkgs
    return {"format": "SPDX", "spec_version": doc.get("spdxVersion"),
            "packages": pkgs, "vulnerabilities": []}
