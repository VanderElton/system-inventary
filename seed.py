"""Carrega o inventário de exemplo e os SBOMs de exemplo no banco.

Uso:  python seed.py            (usa INVENTARIO_DB ou data/inventario.db)
      python seed.py --scan     (também consulta o OSV.dev; requer internet)
"""
import json
import sys
from pathlib import Path

from app import db, main

BASE = Path(__file__).parent / "exemplos"
SBOMS = {
    "api-pagamentos": "api-pagamentos.cdx.json",
    "portal-web": "portal-web.cdx.json",
    "telemetria-ingest": "telemetria-ingest.spdx.json",
}


def run(scan=False):
    db.init()
    print(main.import_inventory(json.loads((BASE / "inventario-exemplo.json").read_text(encoding="utf-8"))))
    with db.tx() as c:
        ids = {r["name"]: r["id"] for r in c.execute("SELECT id, name FROM components")}
    for comp, fname in SBOMS.items():
        doc = json.loads((BASE / "sboms" / fname).read_text(encoding="utf-8"))
        print(comp, main.import_sbom(ids[comp], doc, fname))
    if scan:
        print("OSV:", main.scan())


if __name__ == "__main__":
    run(scan="--scan" in sys.argv)
