"""Download only pinned public EMBER feature ZIPs and LightGBM text models."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "ember2024"
REVISION = "3d23efef7c0f0b702c5024400cfff4c3744a3832"
FILES = {
    "Win64_train.zip": (5853142901, "7b050100ce7bd87149bbfca442de3e02d4bf97d51251566caec2581eebe799fd"),
    "Win64_test.zip": (1176459716, "52a5a05c1bfa5bb021bb8b44c2e0afcf8983dfa1c6c0a9d76db393e5c682ce10"),
}
MODEL_REVISION = "e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2"
MODELS = {
    "EMBER2024_Win64.model": "8eddddc26eb346d74810a0dfcc672342eca5709ece4da259934d6d3c77ca971b",
    "EMBER2024_PE.model": "4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99",
}


def download_models():
    directory = ROOT / "models"
    directory.mkdir(exist_ok=True)
    for name, expected in MODELS.items():
        destination = directory / name
        if not destination.exists():
            url = f"https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/{MODEL_REVISION}/{name}"
            with urllib.request.urlopen(url, timeout=120) as response:
                destination.write_bytes(response.read())
        actual = hashlib.sha256(destination.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Model SHA256 mismatch: {name}")
        destination.with_suffix(".verified.json").write_text(json.dumps(
            {"name": name, "sha256": actual, "size": destination.stat().st_size,
             "revision": MODEL_REVISION}, indent=2))
        print(f"VERIFIED {name} sha256={actual}", flush=True)


def download(name, size, expected):
    destination = ROOT / "downloads" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    marker = destination.with_suffix(".verified.json")
    if marker.exists() and destination.stat().st_size == size:
        return
    url = f"https://huggingface.co/datasets/joyce8/EMBER2024/resolve/{REVISION}/{name}"
    chunk_size = 32 * 1024 * 1024
    started = time.monotonic()
    with destination.open("wb") as output:
        output.truncate(size)

    def chunk(start):
        end = min(start + chunk_size, size) - 1
        for attempt in range(4):
            try:
                request = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
                with urllib.request.urlopen(request, timeout=120) as response:
                    if response.status != 206:
                        raise ValueError("Server ignored range request")
                    content_range = response.headers["Content-Range"]
                    if content_range != f"bytes {start}-{end}/{size}":
                        raise ValueError(f"Wrong content range: {content_range}")
                    data = response.read()
                if len(data) != end - start + 1:
                    raise ValueError("Incomplete range")
                with destination.open("r+b") as output:
                    output.seek(start)
                    output.write(data)
                return len(data)
            except Exception as exc:
                print(f"Retry {name} offset={start} attempt={attempt + 1}: {type(exc).__name__}", flush=True)
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)

    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(chunk, start) for start in range(0, size, chunk_size)]
        for future in concurrent.futures.as_completed(futures):
            completed += future.result()
            elapsed = time.monotonic() - started
            print(f"{name}: {completed}/{size} bytes ({completed / size:.1%}), {completed / elapsed / 1e6:.2f} MB/s", flush=True)
    digest = hashlib.file_digest(destination.open("rb"), "sha256").hexdigest()
    if digest != expected:
        raise ValueError(f"SHA256 mismatch for {name}: {digest}")
    marker.write_text(json.dumps({"name": name, "size": size, "sha256": digest,
                                  "revision": REVISION, "elapsed_seconds": time.monotonic() - started}, indent=2))
    print(f"VERIFIED {name} sha256={digest}", flush=True)


if __name__ == "__main__":
    download_models()
    for filename, (length, sha) in FILES.items():
        download(filename, length, sha)
