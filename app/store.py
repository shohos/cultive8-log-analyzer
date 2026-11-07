import json
import os
from pathlib import Path
import sqlite3
import time

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("ANALYZER_DATA", ROOT / "data"))
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / "analyzer.sqlite3"


def connect():
    db = sqlite3.connect(DB, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize():
    with connect() as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
            created REAL NOT NULL, updated REAL NOT NULL, total_lines INTEGER DEFAULT 0,
            total_entries INTEGER DEFAULT 0, duplicates INTEGER DEFAULT 0,
            cursor INTEGER DEFAULT 1, char_offset INTEGER DEFAULT 0,
            calls INTEGER DEFAULT 0, phase TEXT DEFAULT 'chunks',
            error TEXT, model TEXT, sha256 TEXT, bytes INTEGER DEFAULT 0,
            peak_rss_mb REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS entries (
            job TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            line INTEGER NOT NULL, end_line INTEGER NOT NULL, raw TEXT NOT NULL,
            record TEXT NOT NULL, entity TEXT NOT NULL, digest TEXT NOT NULL,
            duplicate_of INTEGER, PRIMARY KEY(job,line)
        );
        CREATE INDEX IF NOT EXISTS entity_idx ON entries(job,entity);
        CREATE INDEX IF NOT EXISTS digest_idx ON entries(job,digest);
        CREATE TABLE IF NOT EXISTS calls (
            job TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL, phase TEXT NOT NULL, start_line INTEGER,
            end_line INTEGER, payload TEXT NOT NULL, reply TEXT NOT NULL,
            metrics TEXT NOT NULL, PRIMARY KEY(job,seq)
        );
        CREATE TABLE IF NOT EXISTS attempts (
            job TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            seq INTEGER, attempt INTEGER, ok INTEGER, seconds REAL,
            raw TEXT, error TEXT, created REAL
        );
        CREATE TABLE IF NOT EXISTS proposals (
            job TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            seq INTEGER, finding TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            job TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            key TEXT NOT NULL, finding TEXT NOT NULL, PRIMARY KEY(job,key)
        );
        CREATE TABLE IF NOT EXISTS reviews (
            job TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            key TEXT NOT NULL, PRIMARY KEY(job,key)
        );
        """)


def update(job, **values):
    values["updated"] = time.time()
    with connect() as db:
        db.execute("UPDATE jobs SET " + ",".join(f"{k}=?" for k in values) + " WHERE id=?", [*values.values(), job])


def job_row(job):
    with connect() as db:
        row = db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
    return dict(row) if row else None


def entries(job, start=1):
    with connect() as db:
        for row in db.execute("SELECT * FROM entries WHERE job=? AND line>=? ORDER BY line", (job, start)):
            yield dict(row)


def evidence(job, lines):
    result = []
    with connect() as db:
        for line in sorted(set(lines)):
            row = db.execute("SELECT line,end_line,raw,entity,duplicate_of FROM entries WHERE job=? AND line<=? AND end_line>=? ORDER BY line DESC LIMIT 1", (job, line, line)).fetchone()
            if row:
                result.append(dict(row))
    return result


def report(job):
    from .reporting import present
    result = job_row(job)
    if result is None:
        return None
    with connect() as db:
        result["findings"] = [present(json.loads(r[0])) for r in db.execute("SELECT finding FROM findings WHERE job=? ORDER BY key", (job,))]
        result["call_history"] = [{"seq": r["seq"], "phase": r["phase"], "start_line": r["start_line"], "end_line": r["end_line"], **json.loads(r["metrics"])} for r in db.execute("SELECT * FROM calls WHERE job=? ORDER BY seq", (job,))]
        result["retries"] = db.execute("SELECT COUNT(*) FROM attempts WHERE job=? AND ok=0", (job,)).fetchone()[0]
    result["coverage_percent"] = min(100, round((result["cursor"] - 1) / max(1, result["total_lines"]) * 100))
    result["complete"] = result["status"] == "completed"
    result["disclaimer"] = "Possible threats requiring investigation. Model judgments are not proof of compromise. Partial reports may omit events."
    return result
