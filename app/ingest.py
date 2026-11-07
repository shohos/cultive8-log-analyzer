import hashlib
import json
import re

from . import store

MAX_BYTES = 5 * 1024 * 1024
MAX_LINES = 25000
MAX_ENTRY = 1024 * 1024
START = re.compile(r"^(?:\s*\{|\d{4}-\d{2}-\d{2}|\[?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\w{3}\s+\d{1,2}\s+\d\d:)")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_record(raw):
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, RecursionError):
        return {}


def ingest(job, path):
    """Stream complete entries into SQLite; raw physical line numbers are retained."""
    count = total = duplicates = 0
    with store.connect() as db:
        def flush(start, end, raw):
            nonlocal count, duplicates
            if not raw.strip():
                return
            if len(raw.encode("utf-8")) > MAX_ENTRY:
                raise ValueError("A single entry exceeds the 1 MiB limit")
            record = parse_record(raw)
            entity = str(record.get("client_ip") or record.get("ip") or record.get("source_ip") or record.get("username") or record.get("user_id") or record.get("session_id") or "")[:100]
            if not entity:
                m = IP.search(raw)
                entity = m.group() if m else ""
            digest = hashlib.sha256(raw.strip().encode()).hexdigest()
            old = db.execute("SELECT line FROM entries WHERE job=? AND digest=? ORDER BY line LIMIT 1", (job, digest)).fetchone()
            duplicates += bool(old)
            db.execute("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?)", (job, start, end, raw, json.dumps(record), entity, digest, old[0] if old else None))
            count += 1

        pending, start, end = "", 1, 0
        with path.open(encoding="utf-8-sig", errors="strict") as f:
            for number, line in enumerate(f, 1):
                total = number
                if number > MAX_LINES:
                    raise ValueError("Upload exceeds 25,000 physical lines")
                if any(ord(c) < 32 and c not in "\n\r\t" for c in line):
                    raise ValueError("Upload contains binary/control characters")
                # Stack traces/indented continuations stay with their leading entry.
                continuation = bool(pending and not START.match(line) and (line[:1].isspace() or line.startswith(("Traceback", "Caused by:", "at "))))
                if pending and not continuation:
                    flush(start, end, pending)
                    pending = ""
                if not pending:
                    start = number
                pending += line
                end = number
                if len(pending) > MAX_ENTRY:
                    raise ValueError("A single entry exceeds the 1 MiB limit")
            if pending:
                flush(start, end, pending)
        if not count:
            raise ValueError("Upload is empty")
        db.execute("UPDATE jobs SET total_lines=?,total_entries=?,duplicates=? WHERE id=?", (total, count, duplicates, job))
