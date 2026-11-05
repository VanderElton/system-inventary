"""Banco SQLite e esquema do inventário."""
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get("INVENTARIO_DB", os.path.join(os.path.dirname(__file__), "..", "data", "inventario.db"))

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    email TEXT, chat TEXT, manager TEXT, notes TEXT
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT,
    description TEXT,
    owner_team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL,
    criticality TEXT DEFAULT 'media',
    lifecycle TEXT DEFAULT 'ativo',
    UNIQUE(name, version)
);

-- Componente: serviço, biblioteca, firmware, app, imagem de container...
-- Um componente pode ser compartilhado por vários produtos.
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT,
    type TEXT DEFAULT 'servico',
    language TEXT,
    repo_url TEXT,
    owner_team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL,
    notes TEXT,
    UNIQUE(name, version)
);

-- Ferramentas e sistemas do ecossistema (SCM, CI/CD, registries, cloud, ...)
CREATE TABLE IF NOT EXISTS systems (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT DEFAULT 'outro',
    vendor TEXT,
    version TEXT,
    identifier TEXT,          -- purl ou CPE, para cruzar com vulnerabilidades
    url TEXT,
    owner_team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL,
    notes TEXT,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS product_components (
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    PRIMARY KEY (product_id, component_id)
);

CREATE TABLE IF NOT EXISTS product_systems (
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    system_id INTEGER NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    role TEXT,
    PRIMARY KEY (product_id, system_id)
);

CREATE TABLE IF NOT EXISTS component_systems (
    component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    system_id INTEGER NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    role TEXT,
    PRIMARY KEY (component_id, system_id)
);

-- SBOM: sempre o mais recente por componente vale como "atual"
CREATE TABLE IF NOT EXISTS sboms (
    id INTEGER PRIMARY KEY,
    component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    format TEXT, spec_version TEXT, filename TEXT,
    imported_at TEXT DEFAULT (datetime('now')),
    package_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY,
    sbom_id INTEGER NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    ecosystem TEXT,
    license TEXT
);
CREATE INDEX IF NOT EXISTS ix_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS ix_packages_purl ON packages(purl);
CREATE INDEX IF NOT EXISTS ix_packages_component ON packages(component_id);

CREATE TABLE IF NOT EXISTS vulns (
    id TEXT PRIMARY KEY,      -- CVE-..., GHSA-..., OSV id
    aliases TEXT,             -- separados por espaço
    summary TEXT,
    severity TEXT,            -- critica/alta/media/baixa/desconhecida
    cvss REAL,
    published TEXT,
    url TEXT,
    source TEXT
);

-- Achado: vulnerabilidade x pacote (de um componente), com triagem PSIRT (estilo VEX)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    vuln_id TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
    package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE,
    system_id INTEGER REFERENCES systems(id) ON DELETE CASCADE,
    fixed_version TEXT,
    status TEXT DEFAULT 'em_analise',  -- em_analise/afetado/nao_afetado/corrigido
    notes TEXT,
    source TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(vuln_id, package_id),
    UNIQUE(vuln_id, system_id)
);
"""


def connect():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def tx():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init():
    with tx() as c:
        c.executescript(SCHEMA)


def rows(cur):
    return [dict(r) for r in cur.fetchall()]
