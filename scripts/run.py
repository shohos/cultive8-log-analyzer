"""Start exactly one CPU model process and one application worker. Ctrl+C stops both."""
import os
from pathlib import Path
import shutil
import signal
import secrets
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    python = ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    binary = next((ROOT / "runtime").rglob("llama-server.exe"), None) if sys.platform == "win32" else shutil.which("llama-server")
    model = ROOT / "models" / "qwen2.5-1.5b-instruct-q4_k_m.gguf"
    if not binary or not model.exists() or not python.exists():
        raise SystemExit("Run python scripts/setup.py first.")
    env = dict(os.environ, OMP_NUM_THREADS="2", MODEL_URL="http://127.0.0.1:8081", MODEL_API_KEY=secrets.token_urlsafe(32), LAUNCHER_PID=str(os.getpid()))
    env["LLAMA_API_KEY"] = env["MODEL_API_KEY"]
    processes = []
    (ROOT / "data").mkdir(exist_ok=True)
    with (ROOT / "data" / "model-server.log").open("a", encoding="utf-8") as log:
        try:
            # No context shift: token overflows must fail rather than silently lose evidence.
            model_process = subprocess.Popen([str(binary), "-m", str(model), "--host", "127.0.0.1", "--port", "8081", "-c", "2048", "-np", "1", "-t", "2", "-tb", "2", "-ngl", "0", "-b", "256", "-ub", "128", "--cache-ram", "0", "--ctx-checkpoints", "0", "--no-context-shift", "--no-webui"], cwd=ROOT, env=env, stdout=log, stderr=log)
            processes.append(model_process)
            for _ in range(90):
                if model_process.poll() is not None:
                    raise RuntimeError("Model server exited; inspect data/model-server.log")
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8081/health", timeout=1):
                        break
                except Exception:
                    time.sleep(1)
            else:
                raise RuntimeError("Model did not become ready within 90 seconds")
            env["MODEL_PID"] = str(model_process.pid)
            server = subprocess.Popen([str(python), "-m", "uvicorn", "app.main:app", "--host", os.environ.get("APP_HOST", "127.0.0.1"), "--port", "8000", "--workers", "1"], cwd=ROOT, env=env)
            processes.append(server)
            print("Cultive8 analyzer: http://127.0.0.1:8000 (offline, CPU only)", flush=True)
            while server.poll() is None and model_process.poll() is None:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()


if __name__ == "__main__":
    main()
