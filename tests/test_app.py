import io
import json
from pathlib import Path

from app import sbom, vulns

EX = Path(__file__).parent.parent / "exemplos"

LOG4SHELL_GHSA = {
    "id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Log4Shell",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"},
                                                              {"introduced": "2.4"}, {"fixed": "2.12.2"},
                                                              {"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}]}],
}
LOG4SHELL_CVE = {"id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"],
                 "affected": [{"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}]}


def fake_get(url, timeout=30):
    vid = url.rsplit("/", 1)[-1]
    return {"CVE-2021-44228": LOG4SHELL_CVE, "GHSA-jfh8-c2jp-5v3q": LOG4SHELL_GHSA}[vid]


# ------------------------------------------------------------------ parsers
def test_parse_cyclonedx():
    p = sbom.parse(json.loads((EX / "sboms/api-pagamentos.cdx.json").read_text()))
    assert p["format"] == "CycloneDX"
    log4j = next(x for x in p["packages"] if x["name"] == "log4j-core")
    assert log4j["version"] == "2.14.1" and log4j["ecosystem"] == "Maven"


def test_parse_spdx_skips_described_root():
    p = sbom.parse(json.loads((EX / "sboms/telemetria-ingest.spdx.json").read_text()))
    names = {x["name"] for x in p["packages"]}
    assert p["format"] == "SPDX" and "telemetria-ingest" not in names and "PyYAML" in names


def test_parse_rejects_unknown():
    import pytest
    with pytest.raises(ValueError):
        sbom.parse({"foo": 1})


def test_version_status():
    a = LOG4SHELL_GHSA["affected"][0]
    assert vulns.version_status("2.14.1", a) == "afetada"
    assert vulns.version_status("2.17.1", a) == "nao_afetada"
    assert vulns.version_status("2.12.2", a) == "nao_afetada"
    assert vulns.version_status(None, a) == "verificar"
    assert vulns.version_status("1.0.0", {"versions": ["1.0.0"]}) == "afetada"


# ------------------------------------------------------------------ API
def test_crud_and_links(client):
    t = client.post("/api/e/teams", json={"name": "Squad X", "email": "x@ex.com"}).json()["id"]
    p = client.post("/api/e/products", json={"name": "Produto A", "owner_team_id": t}).json()["id"]
    c = client.post("/api/e/components", json={"name": "svc-a", "owner_team_id": t}).json()["id"]
    s = client.post("/api/e/systems", json={"name": "Jenkins", "category": "ci_cd"}).json()["id"]
    assert client.post(f"/api/e/products/{p}/links/components", json={"id": c}).status_code == 200
    assert client.post(f"/api/e/components/{c}/links/systems", json={"id": s, "role": "build"}).status_code == 200
    eco = client.get(f"/api/ecosystem/product/{p}").json()
    assert eco["components"][0]["name"] == "svc-a"
    assert eco["components"][0]["systems"][0]["role"] == "build"
    assert [x["name"] for x in eco["teams"]] == ["Squad X"]
    assert client.post("/api/e/teams", json={"name": ""}).status_code == 400
    assert client.get("/api/e/hackers").status_code == 404


def test_seed_and_package_impact(seeded):
    r = seeded.get("/api/impact", params={"q": "log4j-core@2.14.1"}).json()
    assert len(r["packages"]) == 1
    hit = r["packages"][0]
    assert hit["component"] == "api-pagamentos" and "Portal do Cliente" in hit["products"]
    assert hit["team"] == "Squad Pagamentos"
    r = seeded.get("/api/impact", params={"q": "jenkins"}).json()
    assert r["systems"][0]["system"] == "Jenkins"


def test_cve_lookup_via_osv_and_register(seeded, monkeypatch):
    monkeypatch.setattr(vulns, "_get", fake_get)
    monkeypatch.setattr(vulns.osv_vuln, "__defaults__", (fake_get,))
    r = seeded.get("/api/impact", params={"q": "CVE-2021-44228"}).json()
    assert r["osv"]["vuln"]["id"] == "GHSA-jfh8-c2jp-5v3q"
    assert [(m["name"], m["version_status"]) for m in r["osv"]["matches"]] == [("log4j-core", "afetada")]
    assert seeded.post("/api/vulns/CVE-2021-44228/register").json()["registered"] == 1
    # agora o achado é local e encontrado também pelo alias CVE
    r = seeded.get("/api/impact", params={"q": "CVE-2021-44228"}).json()
    assert r["osv"] is None and r["vulns"][0]["component"] == "api-pagamentos"
    assert r["vulns"][0]["severity"] == "critica"


def test_triage_survives_sbom_reimport(seeded, monkeypatch):
    monkeypatch.setattr(vulns.osv_vuln, "__defaults__", (fake_get,))
    seeded.post("/api/vulns/CVE-2021-44228/register")
    f = seeded.get("/api/findings").json()[0]
    seeded.patch(f"/api/findings/{f['id']}", json={"status": "afetado", "notes": "JNDI exposto"})
    comp = f["component_id"]
    doc = (EX / "sboms/api-pagamentos.cdx.json").read_bytes()
    assert seeded.post(f"/api/components/{comp}/sbom", files={"file": ("bom.json", io.BytesIO(doc))}).status_code == 200
    f2 = seeded.get("/api/findings").json()
    assert len(f2) == 1 and f2[0]["status"] == "afetado" and f2[0]["notes"] == "JNDI exposto"


def test_ci_upload_creates_component(client):
    doc = (EX / "sboms/portal-web.cdx.json").read_bytes()
    r = client.post("/api/sbom", params={"component": "novo-svc", "product": "Produto Novo", "team": "Squad Y"},
                    files={"file": ("bom.json", io.BytesIO(doc))})
    assert r.status_code == 200 and r.json()["packages"] == 4
    comps = client.get("/api/e/components").json()
    assert comps[0]["name"] == "novo-svc" and comps[0]["products"] == "Produto Novo" and comps[0]["team"] == "Squad Y"


def test_scan_with_mocked_osv(seeded, monkeypatch):
    def fake_post(url, payload, timeout=60):
        return {"results": [{"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]} if "log4j-core" in json.dumps(q) else {}
                            for q in payload["queries"]]}
    monkeypatch.setattr(vulns.osv_lookup, "__defaults__", (fake_post, fake_get))
    r = seeded.post("/api/scan").json()
    assert r["findings"] == 1
    stats = seeded.get("/api/stats").json()
    assert stats["open_by_severity"] == {"critica": 1}


def test_invalid_upload(seeded):
    r = seeded.post("/api/components/1/sbom", files={"file": ("x.json", io.BytesIO(b"not json"))})
    assert r.status_code == 400


def test_maven_group_must_match():
    a = {"package": {"ecosystem": "Maven", "name": "org.example:widget"}}
    same = {"name": "widget", "ecosystem": "Maven", "purl": "pkg:maven/org.example/widget@1.0"}
    other = {"name": "widget", "ecosystem": "Maven", "purl": "pkg:maven/com.other/widget@1.0"}
    assert vulns.package_matches(same, a)
    assert not vulns.package_matches(other, a)
    scoped = {"name": "core", "ecosystem": "npm", "purl": "pkg:npm/%40babel/core@7.0.0"}
    assert vulns.package_matches(scoped, {"package": {"ecosystem": "npm", "name": "@babel/core"}})
    assert not vulns.package_matches(scoped, {"package": {"ecosystem": "npm", "name": "core"}})


def test_triage_not_copied_to_homonymous_package(client):
    c = client.post("/api/e/components", json={"name": "svc"}).json()["id"]
    bom = lambda group: {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"bom-ref": "w", "name": "widget", "version": "1.0", "purl": f"pkg:maven/{group}/widget@1.0"}]}
    up = lambda d: client.post(f"/api/components/{c}/sbom", files={"file": ("b.json", io.BytesIO(json.dumps(d).encode()))})
    up(bom("org.example"))
    from app import db as dbm
    with dbm.tx() as cx:
        cx.execute("INSERT INTO vulns (id, severity) VALUES ('GHSA-x', 'alta')")
        cx.execute("INSERT INTO findings (vuln_id, package_id, status) SELECT 'GHSA-x', id, 'nao_afetado' FROM packages")
    up(bom("com.other"))
    assert client.get("/api/findings").json() == []


def test_system_findings_reach_products(client, monkeypatch):
    p = client.post("/api/e/products", json={"name": "Prod"}).json()["id"]
    c = client.post("/api/e/components", json={"name": "svc"}).json()["id"]
    s = client.post("/api/e/systems", json={"name": "Jenkins", "version": "2.440",
                                            "identifier": "pkg:maven/org.jenkins-ci.main/jenkins-core@2.440"}).json()["id"]
    client.post(f"/api/e/products/{p}/links/components", json={"id": c})
    client.post(f"/api/e/components/{c}/links/systems", json={"id": s, "role": "build"})  # só via componente

    def fake_post(url, payload, timeout=60):
        return {"results": [{"vulns": [{"id": "GHSA-jenkins"}]} for _ in payload["queries"]]}
    get = lambda url, timeout=30: {"id": "GHSA-jenkins", "aliases": ["CVE-2024-23897"], "database_specific": {"severity": "CRITICAL"}}
    monkeypatch.setattr(vulns.osv_lookup, "__defaults__", (fake_post, get))
    assert client.post("/api/scan").json()["findings"] == 1
    assert [f["system"] for f in client.get("/api/findings", params={"product_id": p}).json()] == ["Jenkins"]
    assert client.get("/api/e/products").json()[0]["open_vulns"] == 1
    hit = client.get("/api/impact", params={"q": "CVE-2024-23897"}).json()["vulns"][0]
    assert hit["products"] == "Prod"


def test_platforms_seed_detail_and_impact(seeded):
    plats = {f["name"]: f for f in seeded.get("/api/e/platforms").json()}
    assert plats["Spring Boot"]["products"] == "Portal do Cliente 2026.10"
    d = seeded.get(f"/api/platform-detail/{plats['Spring Boot']['id']}").json()
    assert d["products"][0]["via"] == "api-pagamentos" and not d["products"][0]["direct"]
    assert d["components"][0]["update_mechanism"] == "imagem_container"
    java = seeded.get(f"/api/platform-detail/{plats['Java (OpenJDK/Temurin)']['id']}").json()
    assert [s["name"] for s in java["systems"]] == ["Jenkins"]
    eco = seeded.get("/api/ecosystem/product/1").json()
    assert {f["name"] for c in eco["components"] for f in c["platforms"]} >= {"Spring Boot", "Node.js"}
    r = seeded.get("/api/impact", params={"q": "spring boot@2.7"}).json()
    assert r["platforms"][0]["products"] == "Portal do Cliente 2026.10"
    st = seeded.get("/api/stats").json()
    assert st["platforms"] == 7 and st["platforms_eol"] >= 3
    assert {"Spring Boot", "Node.js", "FreeRTOS"} <= {f["name"] for f in st["platforms_attention"]}


def test_platform_crud_and_links(client):
    f = client.post("/api/e/platforms", json={"name": "Android SDK", "version": "34", "kind": "mobile",
                                              "eol_date": "2020-01-01", "update_strategy": "targetSdk anual"}).json()["id"]
    p = client.post("/api/e/products", json={"name": "App", "update_mechanism": "loja_apps"}).json()["id"]
    assert client.post(f"/api/e/products/{p}/links/platforms", json={"id": f, "role": "SDK"}).status_code == 200
    eco = client.get(f"/api/ecosystem/product/{p}").json()
    assert eco["platforms"][0]["role"] == "SDK" and eco["product"]["update_mechanism"] == "loja_apps"
    assert client.delete(f"/api/e/products/{p}/links/platforms/{f}").json()["ok"]
    assert client.get(f"/api/ecosystem/product/{p}").json()["platforms"] == []


def test_migration_adds_columns(tmp_path, monkeypatch):
    import sqlite3
    from app import db
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT);"
                      "CREATE TABLE components (id INTEGER PRIMARY KEY, name TEXT);"
                      "CREATE TABLE systems (id INTEGER PRIMARY KEY, name TEXT);")
    con.close()
    monkeypatch.setattr(db, "DB_PATH", str(path))
    db.init()
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(products)")}
    assert "update_mechanism" in cols
