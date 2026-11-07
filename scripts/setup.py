"""One-time online setup. Runtime never downloads anything."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "b12183"
MODEL_REV = "91cad51170dc346986eccefdc2dd33a9da36ead9"
MODEL = "qwen2.5-1.5b-instruct-q4_k_m.gguf"


def download(url, path, expected=None):
    if path.exists() and (expected is None or sha256(path) == expected):
        return
    print(f"Downloading {path.name} ...", flush=True)
    partial = path.with_suffix(path.suffix + ".partial")
    urllib.request.urlretrieve(url, partial)
    if expected and sha256(partial) != expected:
        raise RuntimeError(f"Checksum mismatch: {path.name}")
    partial.replace(path)


def sha256(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def main():
    for name in ["models", "runtime", "data"]:
        (ROOT / name).mkdir(exist_ok=True)
    if not (ROOT / ".venv").exists():
        subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True)
    python = ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    subprocess.run([str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements.lock.txt")], check=True)
    if sys.platform == "win32":
        url = f"https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/{RELEASE}"
        release = json.load(urllib.request.urlopen(url))
        asset = next(a for a in release["assets"] if a["name"] == f"llama-{RELEASE}-bin-win-cpu-x64.zip")
        digest = (asset.get("digest") or "").removeprefix("sha256:") or None
        archive = ROOT / "runtime" / asset["name"]
        download(asset["browser_download_url"], archive, digest)
        with zipfile.ZipFile(archive) as z:
            z.extractall(ROOT / "runtime")
    else:
        print("Install/build llama-server from llama.cpp " + RELEASE + " and put it on PATH.")
    api = f"https://huggingface.co/api/models/Qwen/Qwen2.5-1.5B-Instruct-GGUF/revision/{MODEL_REV}?blobs=true"
    metadata = json.load(urllib.request.urlopen(api))
    file = next(x for x in metadata["siblings"] if x["rfilename"] == MODEL)
    expected = file["lfs"]["sha256"]
    download(f"https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/{MODEL_REV}/{MODEL}", ROOT / "models" / MODEL, expected)
    (ROOT / "models" / "manifest.json").write_text(json.dumps({"repository": metadata["id"], "revision": MODEL_REV, "file": MODEL, "sha256": expected, "llama_cpp": RELEASE}, indent=2))
    print("Setup complete. Run: python scripts/run.py", flush=True)


if __name__ == "__main__":
    main()
