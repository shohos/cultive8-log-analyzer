from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import threading
import time
import uuid

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import engine, store
from .ingest import MAX_BYTES, ingest
from .model import LocalModel


@asynccontextmanager
async def lifespan(app):
    store.initialize()
    engine.STOP.clear()
    thread = threading.Thread(target=engine.worker, name="analysis-queue", daemon=True)
    thread.start()
    yield
    engine.STOP.set()
    engine.WAKE.set()


app = FastAPI(title="Cultive8 | Local security log analyzer", lifespan=lifespan, docs_url=None, redoc_url=None)
STATIC = Path(__file__).parent / "static"


class BodyLimitMiddleware:
    """Bound streamed/chunked multipart bodies before the form parser buffers them."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        size = 0
        async def limited_receive():
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > MAX_BYTES + 65536:
                    raise HTTPException(413, "Upload exceeds 5 MiB")
            return message
        await self.app(scope, limited_receive if scope["type"] == "http" else receive, send)


app.add_middleware(BodyLimitMiddleware)


@app.middleware("http")
async def local_only(request: Request, call_next):
    host = request.url.hostname
    if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
        return JSONResponse({"detail": "Local connections only"}, status_code=403)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "Cross-origin writes are disabled"}, status_code=403)
        try:
            length = int(request.headers.get("content-length", "0") or 0)
        except ValueError:
            return JSONResponse({"detail": "Invalid content length"}, status_code=400)
        if length > MAX_BYTES + 65536:
            return JSONResponse({"detail": "Upload exceeds 5 MiB"}, status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    model = None
    try:
        model = LocalModel()
        model.health()
        ready, error = True, None
    except Exception:
        ready, error = False, "Local model is unavailable. Start with python scripts/run.py."
    finally:
        if model:
            model.client.close()
    return {"model_ready": ready, "model": "Qwen2.5 1.5B · Q4_K_M", "context": 2048, "threads": 2, "rss_mb": engine.rss_mb(), "memory_includes_model": bool(__import__("os").environ.get("MODEL_PID")), "error": error}


@app.get("/api/jobs")
def jobs():
    with store.connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 50")]


def create_job(name, source):
    with store.connect() as db:
        if db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= 100:
            raise HTTPException(409, "Storage limit: delete old analyses before uploading")
    job = uuid.uuid4().hex
    path = store.DATA / f"{job}.upload"
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("wb") as output:
            while chunk := source.read(65536):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError("Upload exceeds 5 MiB")
                output.write(chunk)
                digest.update(chunk)
        with store.connect() as db:
            db.execute("INSERT INTO jobs(id,name,status,created,updated,sha256,bytes,model) VALUES (?,?,?,?,?,?,?,?)", (job, name, "ready", time.time(), time.time(), digest.hexdigest(), size, "Qwen2.5-1.5B-Instruct-Q4_K_M"))
        ingest(job, path)
    except Exception as exc:
        with store.connect() as db:
            db.execute("DELETE FROM jobs WHERE id=?", (job,))
        if isinstance(exc, (ValueError, UnicodeError)):
            raise HTTPException(400, str(exc)) from exc
        raise
    finally:
        path.unlink(missing_ok=True)
    return store.report(job)


@app.post("/api/jobs", status_code=201)
def upload(file: UploadFile = File(...)):
    name = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    if Path(name).suffix.lower() not in (".log", ".txt"):
        raise HTTPException(400, "Choose a UTF-8 .log or .txt file")
    with store.connect() as db:
        if db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= 100:
            raise HTTPException(409, "Storage limit: delete old analyses before uploading")
    return create_job(name[:160], file.file)


@app.post("/api/sample", status_code=201)
def sample():
    path = store.ROOT / "samples" / "Cultive8_Workspace_Agrigen_Server.log"
    with path.open("rb") as f:
        return create_job(path.name, f)


@app.get("/api/jobs/{job}")
def get_job(job: str):
    report = store.report(job)
    if report is None:
        raise HTTPException(404, "Analysis not found")
    return report


@app.post("/api/jobs/{job}/start")
def start(job: str):
    row = store.job_row(job)
    if row is None:
        raise HTTPException(404, "Analysis not found")
    if row["status"] in ("running", "queued", "completed"):
        return get_job(job)
    store.update(job, status="queued", error=None)
    engine.WAKE.set()
    return get_job(job)


@app.post("/api/jobs/{job}/pause")
def pause(job: str):
    row = store.job_row(job)
    if row is None:
        raise HTTPException(404, "Analysis not found")
    if row["status"] in ("queued", "running"):
        store.update(job, status="paused")
    return get_job(job)


@app.delete("/api/jobs/{job}")
def delete(job: str):
    row = store.job_row(job)
    if not row:
        raise HTTPException(404, "Analysis not found")
    # A paused in-flight call can still commit. Restrict deletion to settled jobs.
    if row["status"] not in ("ready", "completed", "failed"):
        raise HTTPException(409, "Only settled analyses can be deleted")
    with store.connect() as db:
        db.execute("DELETE FROM jobs WHERE id=?", (job,))
    return {"deleted": True}


@app.get("/api/jobs/{job}/report")
def export(job: str):
    result = get_job(job)
    return JSONResponse(result, headers={"Content-Disposition": f'attachment; filename="analysis-{job}.json"'})


@app.get("/api/jobs/{job}/calls")
def audit(job: str):
    get_job(job)
    with store.connect() as db:
        return [{**dict(r), "payload": json.loads(r["payload"]), "reply": json.loads(r["reply"]), "metrics": json.loads(r["metrics"])} for r in db.execute("SELECT * FROM calls WHERE job=? ORDER BY seq", (job,))]


app.mount("/static", StaticFiles(directory=STATIC), name="static")
