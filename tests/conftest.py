import pytest
from fastapi.testclient import TestClient

from app import db, main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init()
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def seeded(client):
    import seed
    seed.run(scan=False)
    return client
