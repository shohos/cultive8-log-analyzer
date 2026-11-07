import json
import time
import uuid

import pytest

from app import store
from app.ingest import ingest


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB", tmp_path / "test.sqlite3")
    monkeypatch.setattr(store, "DATA", tmp_path)
    store.initialize()
    return tmp_path


@pytest.fixture
def make_job(database):
    def make(records=None, text=None):
        job = uuid.uuid4().hex
        path = database / f"{job}.log"
        path.write_text(text if text is not None else "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        with store.connect() as db:
            db.execute("INSERT INTO jobs(id,name,status,created,updated) VALUES (?,?,?,?,?)", (job, path.name, "ready", time.time(), time.time()))
        ingest(job, path)
        return job
    return make
