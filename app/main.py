"""Inventário de Ecossistema de Produtos - API + UI (PSIRT)."""
import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Body
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import db, sbom as sbomlib, vulns as vulnlib

@asynccontextmanager
async def _lifespan(_app):
    db.init()
    yield


app = FastAPI(title="Inventário de Ecossistema (PSIRT)", version="0.1.0", lifespan=_lifespan)
STATIC = os.path.join(os.path.dirname(__file__), "static")

ENTITIES = {
    "teams": ["name", "email", "chat", "manager", "notes"],
    "products": ["name", "version", "description", "owner_team_id", "criticality", "lifecycle"],
    "components": ["name", "version", "type", "language", "repo_url", "owner_team_id", "notes"],
    "systems": ["name", "category", "vendor", "version", "identifier", "url", "owner_team_id", "notes"],
}
OPEN = "('em_analise','afetado')"
# Sistemas de um produto: vínculo direto ou via seus componentes
PRODUCT_SYSTEM_IDS = """SELECT system_id FROM product_systems WHERE product_id={p}
    UNION SELECT cs.system_id FROM component_systems cs JOIN product_components pc ON pc.component_id=cs.component_id
          WHERE pc.product_id={p}"""



@app.exception_handler(ValueError)
def _value_error(_, exc):
    return JSONResponse({"detail": str(exc)}, status_code=400)


def _entity(name):
    if name not in ENTITIES:
        raise HTTPException(404, "Entidade desconhecida")
    return ENTITIES[name]


def _clean(fields, data):
    out = {k: (data.get(k) if data.get(k) != "" else None) for k in fields if k in data}
    if "name" in fields and not (out.get("name") or "").strip() and "name" in data:
        raise ValueError("Nome é obrigatório")
    return out


# ---------------------------------------------------------------- listagens
LIST_SQL = {
    "teams": """
        SELECT t.*,
          (SELECT COUNT(*) FROM products WHERE owner_team_id=t.id) AS products,
          (SELECT COUNT(*) FROM components WHERE owner_team_id=t.id) AS components,
          (SELECT COUNT(*) FROM systems WHERE owner_team_id=t.id) AS systems
        FROM teams t ORDER BY t.name""",
    "products": f"""
        SELECT p.*, t.name AS team,
          (SELECT COUNT(*) FROM product_components WHERE product_id=p.id) AS components,
          (SELECT COUNT(*) FROM product_systems WHERE product_id=p.id) AS systems,
          (SELECT COUNT(DISTINCT f.vuln_id) FROM findings f WHERE f.status IN {OPEN} AND (
             f.package_id IN (SELECT k.id FROM packages k JOIN product_components pc ON pc.component_id=k.component_id
                              WHERE pc.product_id=p.id)
             OR f.system_id IN ({PRODUCT_SYSTEM_IDS.format(p="p.id")}))) AS open_vulns
        FROM products p LEFT JOIN teams t ON t.id=p.owner_team_id ORDER BY p.name, p.version""",
    "components": f"""
        SELECT c.*, t.name AS team,
          (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM product_components pc
             JOIN products p ON p.id=pc.product_id WHERE pc.component_id=c.id) AS products,
          (SELECT COUNT(*) FROM packages WHERE component_id=c.id) AS packages,
          (SELECT MAX(imported_at) FROM sboms WHERE component_id=c.id) AS sbom_at,
          (SELECT COUNT(DISTINCT f.vuln_id) FROM findings f JOIN packages k ON k.id=f.package_id
             WHERE k.component_id=c.id AND f.status IN {OPEN}) AS open_vulns
        FROM components c LEFT JOIN teams t ON t.id=c.owner_team_id ORDER BY c.name""",
    "systems": f"""
        SELECT s.*, t.name AS team,
          (SELECT COUNT(*) FROM product_systems WHERE system_id=s.id) AS products,
          (SELECT COUNT(*) FROM component_systems WHERE system_id=s.id) AS components,
          (SELECT COUNT(*) FROM findings f WHERE f.system_id=s.id AND f.status IN {OPEN}) AS open_vulns
        FROM systems s LEFT JOIN teams t ON t.id=s.owner_team_id ORDER BY s.category, s.name""",
}


@app.get("/api/e/{entity}")
def list_entity(entity: str):
    _entity(entity)
    with db.tx() as c:
        return db.rows(c.execute(LIST_SQL[entity]))


@app.post("/api/e/{entity}", status_code=201)
def create_entity(entity: str, data: dict = Body(...)):
    vals = _clean(_entity(entity), data)
    if not vals.get("name"):
        raise ValueError("Nome é obrigatório")
    with db.tx() as c:
        cols = ", ".join(vals)
        cur = c.execute(f"INSERT INTO {entity} ({cols}) VALUES ({', '.join('?' * len(vals))})", list(vals.values()))
        return {"id": cur.lastrowid}


@app.get("/api/e/{entity}/{item_id}")
def get_entity(entity: str, item_id: int):
    _entity(entity)
    with db.tx() as c:
        r = c.execute(f"SELECT * FROM {entity} WHERE id=?", (item_id,)).fetchone()
        if not r:
            raise HTTPException(404, "Não encontrado")
        return dict(r)


@app.put("/api/e/{entity}/{item_id}")
def update_entity(entity: str, item_id: int, data: dict = Body(...)):
    vals = _clean(_entity(entity), data)
    if not vals:
        return {"ok": True}
    with db.tx() as c:
        c.execute(f"UPDATE {entity} SET {', '.join(k + '=?' for k in vals)} WHERE id=?", [*vals.values(), item_id])
    return {"ok": True}


@app.delete("/api/e/{entity}/{item_id}")
def delete_entity(entity: str, item_id: int):
    _entity(entity)
    with db.tx() as c:
        c.execute(f"DELETE FROM {entity} WHERE id=?", (item_id,))
    return {"ok": True}


# ---------------------------------------------------------------- relacionamentos
LINKS = {
    ("products", "components"): ("product_components", "product_id", "component_id", False),
    ("products", "systems"): ("product_systems", "product_id", "system_id", True),
    ("components", "systems"): ("component_systems", "component_id", "system_id", True),
}


@app.post("/api/e/{entity}/{item_id}/links/{target}")
def add_link(entity: str, item_id: int, target: str, data: dict = Body(...)):
    if (entity, target) not in LINKS:
        raise HTTPException(404, "Relacionamento inválido")
    table, a, b, has_role = LINKS[(entity, target)]
    with db.tx() as c:
        if has_role:
            c.execute(f"INSERT OR REPLACE INTO {table} ({a},{b},role) VALUES (?,?,?)",
                      (item_id, data["id"], data.get("role") or None))
        else:
            c.execute(f"INSERT OR IGNORE INTO {table} ({a},{b}) VALUES (?,?)", (item_id, data["id"]))
    return {"ok": True}


@app.delete("/api/e/{entity}/{item_id}/links/{target}/{target_id}")
def del_link(entity: str, item_id: int, target: str, target_id: int):
    if (entity, target) not in LINKS:
        raise HTTPException(404, "Relacionamento inválido")
    table, a, b, _ = LINKS[(entity, target)]
    with db.tx() as c:
        c.execute(f"DELETE FROM {table} WHERE {a}=? AND {b}=?", (item_id, target_id))
    return {"ok": True}


# ---------------------------------------------------------------- visões
def _sev_counts(c, where, args):
    r = c.execute(f"""SELECT v.severity, COUNT(DISTINCT v.id) n FROM findings f JOIN vulns v ON v.id=f.vuln_id
        LEFT JOIN packages k ON k.id=f.package_id WHERE f.status IN {OPEN} AND {where} GROUP BY v.severity""", args)
    return {x["severity"]: x["n"] for x in r}


@app.get("/api/ecosystem/product/{pid}")
def product_ecosystem(pid: int):
    with db.tx() as c:
        p = c.execute("SELECT p.*, t.name team FROM products p LEFT JOIN teams t ON t.id=p.owner_team_id WHERE p.id=?", (pid,)).fetchone()
        if not p:
            raise HTTPException(404, "Produto não encontrado")
        comps = db.rows(c.execute("""SELECT c.*, t.name team, t.email team_email,
              (SELECT COUNT(*) FROM packages WHERE component_id=c.id) packages,
              (SELECT MAX(imported_at) FROM sboms WHERE component_id=c.id) sbom_at
            FROM product_components pc JOIN components c ON c.id=pc.component_id
            LEFT JOIN teams t ON t.id=c.owner_team_id WHERE pc.product_id=? ORDER BY c.name""", (pid,)))
        for comp in comps:
            comp["vulns"] = _sev_counts(c, "k.component_id=?", (comp["id"],))
            comp["systems"] = db.rows(c.execute("""SELECT s.id, s.name, s.category, cs.role FROM component_systems cs
                JOIN systems s ON s.id=cs.system_id WHERE cs.component_id=? ORDER BY s.name""", (comp["id"],)))
        systems = db.rows(c.execute("""SELECT s.*, ps.role, t.name team FROM product_systems ps JOIN systems s ON s.id=ps.system_id
            LEFT JOIN teams t ON t.id=s.owner_team_id WHERE ps.product_id=? ORDER BY s.category, s.name""", (pid,)))
        teams = db.rows(c.execute("""SELECT DISTINCT t.* FROM teams t WHERE t.id IN (
              SELECT owner_team_id FROM products WHERE id=:p
              UNION SELECT c.owner_team_id FROM components c JOIN product_components pc ON pc.component_id=c.id WHERE pc.product_id=:p
              UNION SELECT s.owner_team_id FROM systems s JOIN product_systems ps ON ps.system_id=s.id WHERE ps.product_id=:p
              UNION SELECT s.owner_team_id FROM systems s JOIN component_systems cs ON cs.system_id=s.id
                    JOIN product_components pc ON pc.component_id=cs.component_id WHERE pc.product_id=:p) ORDER BY t.name""", {"p": pid}))
        return {"product": dict(p), "components": comps, "systems": systems, "teams": teams}


@app.get("/api/ecosystem/component/{cid}")
def component_detail(cid: int):
    with db.tx() as c:
        comp = c.execute("SELECT c.*, t.name team FROM components c LEFT JOIN teams t ON t.id=c.owner_team_id WHERE c.id=?", (cid,)).fetchone()
        if not comp:
            raise HTTPException(404, "Componente não encontrado")
        return {
            "component": dict(comp),
            "products": db.rows(c.execute("SELECT p.id, p.name, p.version FROM product_components pc JOIN products p ON p.id=pc.product_id WHERE pc.component_id=?", (cid,))),
            "systems": db.rows(c.execute("SELECT s.id, s.name, s.category, cs.role FROM component_systems cs JOIN systems s ON s.id=cs.system_id WHERE cs.component_id=?", (cid,))),
            "sboms": db.rows(c.execute("SELECT * FROM sboms WHERE component_id=? ORDER BY id DESC", (cid,))),
            "packages": db.rows(c.execute(f"""SELECT k.*,
                (SELECT COUNT(*) FROM findings f WHERE f.package_id=k.id AND f.status IN {OPEN}) open_vulns
                FROM packages k WHERE k.component_id=? ORDER BY open_vulns DESC, k.name""", (cid,))),
        }


@app.get("/api/system-detail/{sid}")
def system_detail(sid: int):
    with db.tx() as c:
        s = c.execute("SELECT s.*, t.name team FROM systems s LEFT JOIN teams t ON t.id=s.owner_team_id WHERE s.id=?", (sid,)).fetchone()
        if not s:
            raise HTTPException(404, "Sistema não encontrado")
        return {
            "system": dict(s),
            "products": db.rows(c.execute("SELECT p.id, p.name, p.version, ps.role FROM product_systems ps JOIN products p ON p.id=ps.product_id WHERE ps.system_id=?", (sid,))),
            "components": db.rows(c.execute("""SELECT c.id, c.name, c.version, cs.role,
                (SELECT GROUP_CONCAT(p.name, ', ') FROM product_components pc JOIN products p ON p.id=pc.product_id WHERE pc.component_id=c.id) products
                FROM component_systems cs JOIN components c ON c.id=cs.component_id WHERE cs.system_id=?""", (sid,))),
        }


@app.get("/api/stats")
def stats():
    with db.tx() as c:
        one = lambda q: c.execute(q).fetchone()[0]
        return {
            "products": one("SELECT COUNT(*) FROM products"),
            "components": one("SELECT COUNT(*) FROM components"),
            "systems": one("SELECT COUNT(*) FROM systems"),
            "teams": one("SELECT COUNT(*) FROM teams"),
            "packages": one("SELECT COUNT(*) FROM packages"),
            "components_without_sbom": one("SELECT COUNT(*) FROM components c WHERE NOT EXISTS (SELECT 1 FROM sboms s WHERE s.component_id=c.id)"),
            "without_owner": one("SELECT (SELECT COUNT(*) FROM products WHERE owner_team_id IS NULL)+(SELECT COUNT(*) FROM components WHERE owner_team_id IS NULL)"),
            "open_by_severity": _sev_counts(c, "1=1", ()),
            "top_vulns": db.rows(c.execute(f"""SELECT v.id, v.aliases, v.severity, v.summary,
                  COUNT(DISTINCT k.component_id) components,
                  COUNT(DISTINCT pc.product_id) products
                FROM findings f JOIN vulns v ON v.id=f.vuln_id
                LEFT JOIN packages k ON k.id=f.package_id
                LEFT JOIN product_components pc ON pc.component_id=k.component_id
                WHERE f.status IN {OPEN}
                GROUP BY v.id ORDER BY CASE v.severity WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 WHEN 'media' THEN 2 WHEN 'baixa' THEN 3 ELSE 4 END,
                  products DESC LIMIT 10""")),
        }


# ---------------------------------------------------------------- busca de impacto (PSIRT)
@app.get("/api/impact")
def impact(q: str):
    """'Onde somos afetados?' - busca por CVE/GHSA, pacote (nome/purl) ou ferramenta/sistema."""
    q = q.strip()
    if len(q) < 2:
        raise ValueError("Informe ao menos 2 caracteres")
    name, _, version = q.partition("@") if not q.startswith("pkg:") else (q, "", "")
    like = f"%{name}%"
    with db.tx() as c:
        by_vuln = db.rows(c.execute("""
            SELECT v.id vuln, v.aliases, v.severity, v.summary, f.id finding_id, f.status, f.fixed_version, f.notes,
                   COALESCE(k.name, s.name) package, COALESCE(k.version, s.version) version,
                   c.id component_id, c.name component, s.id system_id,
                   COALESCE(tc.name, ts.name) team, COALESCE(tc.email, ts.email) team_email,
                   COALESCE(
                     (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM product_components pc JOIN products p ON p.id=pc.product_id WHERE pc.component_id=c.id),
                     (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM products p WHERE p.id IN (SELECT product_id FROM product_systems WHERE system_id=s.id UNION SELECT pc.product_id FROM component_systems cs JOIN product_components pc ON pc.component_id=cs.component_id WHERE cs.system_id=s.id))) products
            FROM vulns v JOIN findings f ON f.vuln_id=v.id
            LEFT JOIN packages k ON k.id=f.package_id LEFT JOIN components c ON c.id=k.component_id
            LEFT JOIN teams tc ON tc.id=c.owner_team_id
            LEFT JOIN systems s ON s.id=f.system_id LEFT JOIN teams ts ON ts.id=s.owner_team_id
            WHERE v.id LIKE :q OR (' '||COALESCE(v.aliases,'')||' ') LIKE :q
            ORDER BY v.id, products""", {"q": f"%{q}%"}))
        by_package = db.rows(c.execute(f"""
            SELECT k.name package, k.version, k.purl, k.license, c.id component_id, c.name component,
                   t.name team, t.email team_email,
                   (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM product_components pc JOIN products p ON p.id=pc.product_id WHERE pc.component_id=c.id) products,
                   (SELECT GROUP_CONCAT(f.vuln_id, ' ') FROM findings f WHERE f.package_id=k.id AND f.status IN {OPEN}) open_vulns
            FROM packages k JOIN components c ON c.id=k.component_id LEFT JOIN teams t ON t.id=c.owner_team_id
            WHERE (k.name LIKE :n OR k.purl LIKE :n) AND (:v = '' OR k.version = :v)
            ORDER BY k.name, k.version, c.name LIMIT 500""", {"n": like, "v": version}))
        by_system = db.rows(c.execute("""
            SELECT s.id system_id, s.name system, s.version, s.category, t.name team, t.email team_email,
                   (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM products p WHERE p.id IN (SELECT product_id FROM product_systems WHERE system_id=s.id UNION SELECT pc.product_id FROM component_systems cs JOIN product_components pc ON pc.component_id=cs.component_id WHERE cs.system_id=s.id)) products,
                   (SELECT GROUP_CONCAT(c.name, ', ') FROM component_systems cs JOIN components c ON c.id=cs.component_id WHERE cs.system_id=s.id) components
            FROM systems s LEFT JOIN teams t ON t.id=s.owner_team_id
            WHERE s.name LIKE :n OR s.vendor LIKE :n OR s.identifier LIKE :n ORDER BY s.name""", {"n": like}))
    osv = None
    if vulnlib.looks_like_vuln_id(q) and not by_vuln:
        osv = osv_check(q)
    return {"query": q, "vulns": by_vuln, "packages": by_package, "systems": by_system, "osv": osv}


def osv_check(vuln_id):
    """Consulta a vulnerabilidade no OSV.dev e cruza os pacotes afetados com os SBOMs do inventário.
    Não grava nada: devolve candidatos para o PSIRT revisar (ver POST /api/vulns/{id}/register)."""
    try:
        vuln, affected = vulnlib.osv_vuln(vuln_id.strip().upper() if vuln_id.upper().startswith("CVE-") else vuln_id.strip())
    except Exception as e:
        return {"error": f"Falha ao consultar OSV.dev: {e}"}
    if not vuln:
        return {"error": "Identificador não encontrado no OSV.dev."}
    names = {((a.get("package") or {}).get("name") or "").split(":")[-1].split("/")[-1].lower() for a in affected}
    names.discard("")
    matches = []
    if names:
        with db.tx() as c:
            marks = ",".join("?" * len(names))
            pkgs = db.rows(c.execute(f"""
                SELECT k.id package_id, k.name, k.version, k.purl, k.ecosystem, c.id component_id, c.name component,
                       t.name team, t.email team_email,
                       (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM product_components pc
                          JOIN products p ON p.id=pc.product_id WHERE pc.component_id=c.id) products
                FROM packages k JOIN components c ON c.id=k.component_id LEFT JOIN teams t ON t.id=c.owner_team_id
                WHERE lower(k.name) IN ({marks})""", list(names)))
        for k in pkgs:
            states = [vulnlib.version_status(k["version"], a) for a in affected if vulnlib.package_matches(k, a)]
            if not states:
                continue
            k["version_status"] = "afetada" if "afetada" in states else "verificar" if "verificar" in states else "nao_afetada"
            matches.append(k)
    order = {"afetada": 0, "verificar": 1, "nao_afetada": 2}
    matches.sort(key=lambda m: (order[m["version_status"]], m["name"], m["component"]))
    vuln.pop("fixed", None)
    return {"vuln": vuln, "affected_packages": sorted(names), "matches": matches}


@app.post("/api/vulns/{vuln_id}/register")
def register_osv_matches(vuln_id: str):
    """Registra como achados ('em análise') os pacotes do inventário com versão afetada ou a verificar."""
    r = osv_check(vuln_id)
    if r.get("error"):
        raise HTTPException(502, r["error"])
    with db.tx() as c:
        v = dict(r["vuln"], source="osv")
        _upsert_vuln(c, v)
        n = 0
        for m in r["matches"]:
            if m["version_status"] != "nao_afetada":
                _add_finding(c, v["id"], package_id=m["package_id"], source="osv")
                n += 1
    return {"vuln": v["id"], "registered": n}


# ---------------------------------------------------------------- SBOM
def _upsert_vuln(c, v):
    c.execute("""INSERT INTO vulns (id, aliases, summary, severity, cvss, published, url, source)
        VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
        aliases=COALESCE(excluded.aliases, aliases), summary=COALESCE(excluded.summary, summary),
        severity=CASE WHEN excluded.severity='desconhecida' THEN severity ELSE excluded.severity END,
        cvss=COALESCE(excluded.cvss, cvss), url=COALESCE(excluded.url, url)""",
              (v["id"], " ".join(v.get("aliases") or []) or None, v.get("summary"), v.get("severity") or "desconhecida",
               v.get("cvss"), v.get("published"), v.get("url"), v.get("source")))


def _add_finding(c, vuln_id, package_id=None, system_id=None, fixed=None, source=None, status=None):
    col = "package_id" if package_id else "system_id"
    c.execute(f"""INSERT INTO findings (vuln_id, {col}, fixed_version, source, status) VALUES (?,?,?,?,COALESCE(?, 'em_analise'))
        ON CONFLICT DO UPDATE SET fixed_version=COALESCE(excluded.fixed_version, fixed_version)""",
              (vuln_id, package_id or system_id, fixed, source, status))


def import_sbom(component_id, doc, filename=None):
    parsed = sbomlib.parse(doc)
    with db.tx() as c:
        if not c.execute("SELECT 1 FROM components WHERE id=?", (component_id,)).fetchone():
            raise HTTPException(404, "Componente não encontrado")
        # preserva a triagem existente (status/notas) para o mesmo pacote (nome+versão+purl) e vuln
        # (achados vindos do OSV/scanner também são mantidos se o pacote+versão continuar no novo SBOM)
        keep = [dict(r) for r in c.execute(
            """SELECT f.vuln_id, k.name, k.version, k.purl, f.status, f.notes, f.fixed_version, f.source FROM findings f
               JOIN packages k ON k.id=f.package_id WHERE k.component_id=?""", (component_id,))]
        c.execute("DELETE FROM sboms WHERE component_id=?", (component_id,))
        sid = c.execute("INSERT INTO sboms (component_id, format, spec_version, filename, package_count) VALUES (?,?,?,?,?)",
                        (component_id, parsed["format"], parsed["spec_version"], filename, len(parsed["packages"]))).lastrowid
        refs, by_nv, n_pkgs = {}, {}, 0
        for p in parsed["packages"]:
            if not p.get("name"):
                continue
            pid = c.execute("INSERT INTO packages (sbom_id, component_id, name, version, purl, ecosystem, license) VALUES (?,?,?,?,?,?,?)",
                            (sid, component_id, p["name"], p.get("version"), p.get("purl"), p.get("ecosystem"), p.get("license"))).lastrowid
            if p.get("ref"):
                refs[p["ref"]] = pid
            by_nv.setdefault((p["name"], p.get("version"), p.get("purl")), pid)
            n_pkgs += 1
        n_vulns = 0
        for v in parsed["vulnerabilities"]:
            if not v.get("id"):
                continue
            v["severity"] = vulnlib.norm_sev(v.get("severity"))
            v["source"] = "sbom"
            _upsert_vuln(c, v)
            status = {"not_affected": "nao_afetado", "false_positive": "nao_afetado", "resolved": "corrigido",
                      "exploitable": "afetado"}.get(v.get("analysis"))
            for ref in v["affects"]:
                if ref in refs:
                    _add_finding(c, v["id"], package_id=refs[ref], source="sbom", status=status)
                    n_vulns += 1
        for k in keep:
            pid = by_nv.get((k["name"], k["version"], k["purl"]))
            if not pid:
                continue  # pacote saiu do SBOM (ex.: atualizado): o achado antigo deixa de valer
            c.execute("""INSERT INTO findings (vuln_id, package_id, fixed_version, status, notes, source)
                VALUES (?,?,?,?,?,?) ON CONFLICT(vuln_id, package_id) DO UPDATE SET
                status=excluded.status, notes=excluded.notes,
                fixed_version=COALESCE(fixed_version, excluded.fixed_version)""",
                      (k["vuln_id"], pid, k["fixed_version"], k["status"], k["notes"], k["source"]))
        return {"sbom_id": sid, "format": parsed["format"], "packages": n_pkgs, "findings_from_sbom": n_vulns}


def _load_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        raise ValueError("Arquivo não é um JSON válido (suportado: CycloneDX JSON, SPDX JSON)")


@app.post("/api/components/{cid}/sbom")
async def upload_sbom(cid: int, file: UploadFile = File(...)):
    return import_sbom(cid, _load_json(await file.read()), file.filename)


@app.post("/api/sbom")
async def upload_sbom_by_name(component: str, file: UploadFile = File(...), version: str = None,
                              product: str = None, product_version: str = None, team: str = None):
    """Para CI/CD: cria o componente (e vínculo com produto) se não existir e importa o SBOM.
    curl -F file=@bom.json 'http://host:8000/api/sbom?component=api-pagamentos&product=Portal'"""
    doc = _load_json(await file.read())
    with db.tx() as c:
        cid = _get_or_create(c, "components", component, version, {"owner_team_id": _team_id(c, team)})
        if product:
            pid = _get_or_create(c, "products", product, product_version, {"owner_team_id": _team_id(c, team)})
            c.execute("INSERT OR IGNORE INTO product_components VALUES (?,?)", (pid, cid))
    return {"component_id": cid, **import_sbom(cid, doc, file.filename)}


def _team_id(c, name):
    if not name:
        return None
    r = c.execute("SELECT id FROM teams WHERE name=?", (name,)).fetchone()
    return r["id"] if r else c.execute("INSERT INTO teams (name) VALUES (?)", (name,)).lastrowid


def _get_or_create(c, table, name, version=None, extra=None):
    r = c.execute(f"SELECT id FROM {table} WHERE name=? AND version IS ?", (name, version or None)).fetchone()
    if r:
        return r["id"]
    vals = {"name": name, "version": version or None, **{k: v for k, v in (extra or {}).items() if v is not None}}
    return c.execute(f"INSERT INTO {table} ({', '.join(vals)}) VALUES ({', '.join('?' * len(vals))})", list(vals.values())).lastrowid


# ---------------------------------------------------------------- vulnerabilidades
@app.post("/api/scan")
def scan(component_id: int = None):
    """Consulta o OSV.dev para todos os pacotes (ou de um componente) e sistemas com purl."""
    with db.tx() as c:
        where, args = ("WHERE component_id=?", (component_id,)) if component_id else ("", ())
        pkgs = [{"key": ("p", r["id"]), **dict(r)} for r in c.execute(f"SELECT id, name, version, purl, ecosystem FROM packages {where}", args)]
        if not component_id:
            for r in c.execute("SELECT id, name, version, identifier FROM systems WHERE identifier LIKE 'pkg:%'"):
                pkgs.append({"key": ("s", r["id"]), "name": r["name"], "version": r["version"], "purl": r["identifier"],
                             "ecosystem": sbomlib.PURL_ECOSYSTEM.get(sbomlib.purl_type(r["identifier"]))})
    try:
        matches, details = vulnlib.osv_lookup(pkgs)
    except Exception as e:
        raise HTTPException(502, f"Falha ao consultar OSV.dev ({e}). Verifique acesso à internet/proxy, ou importe um relatório Trivy/Grype.")
    names = {p["key"]: p["name"] for p in pkgs}
    with db.tx() as c:
        for d in details.values():
            _upsert_vuln(c, d)
        for key, vid in matches:
            kind, ident = key
            fixed = details[vid].get("fixed", {})
            fx = fixed.get(names[key]) or next((v for k, v in fixed.items() if k.endswith(names[key])), None)
            _add_finding(c, vid, package_id=ident if kind == "p" else None, system_id=ident if kind == "s" else None,
                         fixed=fx, source="osv")
    return {"checked": len(pkgs), "findings": len(matches), "vulns": len(details)}


@app.post("/api/components/{cid}/report")
async def upload_report(cid: int, file: UploadFile = File(...)):
    """Importa relatório de scanner (Trivy JSON / Grype JSON) e associa aos pacotes do componente."""
    items = vulnlib.parse_scanner_report(_load_json(await file.read()))
    matched, unmatched = 0, 0
    with db.tx() as c:
        for it in items:
            r = None
            if it.get("purl"):
                r = c.execute("SELECT id FROM packages WHERE component_id=? AND purl=?", (cid, it["purl"])).fetchone()
            if not r:
                r = c.execute("SELECT id FROM packages WHERE component_id=? AND name=? AND (version IS ? OR ? IS NULL)",
                              (cid, it["name"], it["version"], it["version"])).fetchone()
            if not r:  # pacote não está no SBOM: registra mesmo assim
                sid = c.execute("SELECT id FROM sboms WHERE component_id=? ORDER BY id DESC", (cid,)).fetchone()
                if not sid:
                    sid = {"id": c.execute("INSERT INTO sboms (component_id, format, filename) VALUES (?, 'scanner', ?)", (cid, file.filename)).lastrowid}
                r = {"id": c.execute("INSERT INTO packages (sbom_id, component_id, name, version, purl) VALUES (?,?,?,?,?)",
                                     (sid["id"], cid, it["name"], it["version"], it.get("purl"))).lastrowid}
                unmatched += 1
            else:
                matched += 1
            _upsert_vuln(c, it["vuln"])
            _add_finding(c, it["vuln"]["id"], package_id=r["id"], fixed=it.get("fixed"), source=it["vuln"]["source"])
    return {"findings": len(items), "matched_packages": matched, "new_packages": unmatched}


@app.get("/api/findings")
def findings(status: str = None, severity: str = None, product_id: int = None, component_id: int = None, system_id: int = None):
    sql = """SELECT f.*, v.severity, v.summary, v.aliases, v.url,
               k.name package, k.version, k.purl, c.id component_id, c.name component, s.name system,
               COALESCE(tc.name, ts.name) team,
               COALESCE(
                 (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM product_components pc JOIN products p ON p.id=pc.product_id WHERE pc.component_id=c.id),
                 (SELECT GROUP_CONCAT(p.name || COALESCE(' '||p.version,''), ', ') FROM products p WHERE p.id IN (SELECT product_id FROM product_systems WHERE system_id=s.id UNION SELECT pc.product_id FROM component_systems cs JOIN product_components pc ON pc.component_id=cs.component_id WHERE cs.system_id=s.id))) products
             FROM findings f JOIN vulns v ON v.id=f.vuln_id
             LEFT JOIN packages k ON k.id=f.package_id LEFT JOIN components c ON c.id=k.component_id
             LEFT JOIN teams tc ON tc.id=c.owner_team_id
             LEFT JOIN systems s ON s.id=f.system_id LEFT JOIN teams ts ON ts.id=s.owner_team_id WHERE 1=1"""
    args = []
    if status == "abertos":
        sql += f" AND f.status IN {OPEN}"
    elif status:
        sql += " AND f.status=?"; args.append(status)
    if severity:
        sql += " AND v.severity=?"; args.append(severity)
    if component_id:
        sql += " AND c.id=?"; args.append(component_id)
    if system_id:
        sql += " AND s.id=?"; args.append(system_id)
    if product_id:
        sql += f""" AND (c.id IN (SELECT component_id FROM product_components WHERE product_id=?)
                     OR s.id IN ({PRODUCT_SYSTEM_IDS.format(p='?')}))"""; args += [product_id] * 3
    sql += """ ORDER BY CASE v.severity WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 WHEN 'media' THEN 2 WHEN 'baixa' THEN 3 ELSE 4 END,
               f.vuln_id LIMIT 2000"""
    with db.tx() as c:
        return db.rows(c.execute(sql, args))


@app.patch("/api/findings/{fid}")
def triage(fid: int, data: dict = Body(...)):
    if data.get("status") not in (None, "em_analise", "afetado", "nao_afetado", "corrigido"):
        raise ValueError("Status inválido")
    with db.tx() as c:
        c.execute("UPDATE findings SET status=COALESCE(?, status), notes=COALESCE(?, notes) WHERE id=?",
                  (data.get("status"), data.get("notes"), fid))
    return {"ok": True}


# ---------------------------------------------------------------- import/export do inventário
@app.post("/api/import")
def import_inventory(data: dict = Body(...)):
    """Carga em massa por nomes (ver exemplos/inventario-exemplo.json)."""
    n = 0
    with db.tx() as c:
        for t in data.get("teams", []):
            c.execute("""INSERT INTO teams (name, email, chat, manager, notes) VALUES (:name, :email, :chat, :manager, :notes)
                ON CONFLICT(name) DO UPDATE SET email=excluded.email, chat=excluded.chat, manager=excluded.manager, notes=excluded.notes""",
                      {k: t.get(k) for k in ENTITIES["teams"]}); n += 1
        for s in data.get("systems", []):
            sid = _get_or_create(c, "systems", s["name"], s.get("version"))
            _set(c, "systems", sid, s); n += 1
        for comp in data.get("components", []):
            cid = _get_or_create(c, "components", comp["name"], comp.get("version"))
            _set(c, "components", cid, comp); n += 1
            for s in comp.get("systems", []):
                c.execute("INSERT OR REPLACE INTO component_systems VALUES (?,?,?)", (cid, _by_name(c, "systems", s), _role(s)))
        for p in data.get("products", []):
            pid = _get_or_create(c, "products", p["name"], p.get("version"))
            _set(c, "products", pid, p); n += 1
            for comp in p.get("components", []):
                c.execute("INSERT OR IGNORE INTO product_components VALUES (?,?)", (pid, _by_name(c, "components", comp)))
            for s in p.get("systems", []):
                c.execute("INSERT OR REPLACE INTO product_systems VALUES (?,?,?)", (pid, _by_name(c, "systems", s), _role(s)))
    return {"imported": n}


def _role(ref):
    return ref.get("role") if isinstance(ref, dict) else None


def _by_name(c, table, ref):
    name = ref["name"] if isinstance(ref, dict) else ref
    r = c.execute(f"SELECT id FROM {table} WHERE name=? ORDER BY id LIMIT 1", (name,)).fetchone()
    if not r:
        raise ValueError(f"{table}: '{name}' não encontrado (declare-o antes no arquivo)")
    return r["id"]


def _set(c, table, ident, data):
    vals = {k: data[k] for k in ENTITIES[table] if k in data and k not in ("name", "version")}
    if data.get("owner_team"):
        vals["owner_team_id"] = _team_id(c, data["owner_team"])
    if vals:
        c.execute(f"UPDATE {table} SET {', '.join(k + '=?' for k in vals)} WHERE id=?", [*vals.values(), ident])


@app.get("/api/export")
def export_inventory():
    with db.tx() as c:
        out = {}
        for t in ["teams", "products", "components", "systems", "product_components", "product_systems",
                  "component_systems", "sboms", "packages", "vulns", "findings"]:
            out[t] = db.rows(c.execute(f"SELECT * FROM {t}"))
        return JSONResponse(out, headers={"Content-Disposition": "attachment; filename=inventario-export.json"})


# ---------------------------------------------------------------- UI
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))
