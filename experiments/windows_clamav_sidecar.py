"""Optional, isolated Windows ClamAV 1.5.4 sidecar; never installs a service.

The pinned archive digest was verified against Cisco Talos' detached signature.
See docs/research/WINDOWS_CLAMAV_SIDECAR_20261022.md for provenance and commands.
"""
import argparse
import ctypes
import hashlib
import json
import socket
import subprocess
import time
import zipfile
from pathlib import Path


ARCHIVE_SHA256 = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395"
MIN_FREE_BYTES = 2 * 1024**3


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def free_memory():
    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
            (name, ctypes.c_ulonglong) for name in
            ("total", "available", "page_total", "page_available", "virtual_total",
             "virtual_available", "extended")
        ]
    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError()
    return status.available


def prepare(archive, root):
    if digest(archive) != ARCHIVE_SHA256:
        raise ValueError("Archive does not match the verified official 1.5.4 ZIP")
    runtime = root / "runtime"
    if runtime.exists():
        raise FileExistsError("Use a new sidecar directory; existing runtime is preserved")
    files = []
    with zipfile.ZipFile(archive) as source:
        for entry in source.infolist():
            relative = Path(entry.filename).relative_to("clamav-1.5.4.win.x64")
            if entry.is_dir():
                continue
            if not (relative.suffix.lower() in {".exe", ".dll", ".crt", ".sample"}
                    or relative.parts[0] == "COPYING"
                    or str(relative) in {"COPYING.txt", "README.md", "NEWS.md"}):
                continue
            destination = runtime / relative
            if not destination.resolve().is_relative_to(runtime.resolve()):
                raise ValueError("Archive member escapes runtime")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read(entry))
            files.append({"path": relative.as_posix(), "bytes": entry.file_size,
                          "sha256": digest(destination)})
    for name in ("database", "logs", "temp"):
        (root / name).mkdir(exist_ok=True)
    (root / "freshclam.conf").write_text(
        f"DatabaseDirectory {root / 'database'}\nDatabaseMirror database.clamav.net\n"
        f"CVDCertsDirectory {runtime / 'certs'}\n"
        f"UpdateLogFile {root / 'logs' / 'freshclam.log'}\nLogTime yes\n"
        "TestDatabases yes\n", encoding="utf-8")
    (root / "clamd.conf").write_text(
        f"DatabaseDirectory {root / 'database'}\nCVDCertsDirectory {runtime / 'certs'}\n"
        f"LogFile {root / 'logs' / 'clamd.log'}\nLogTime yes\n"
        f"TemporaryDirectory {root / 'temp'}\n"
        "TCPAddr 127.0.0.1\nTCPSocket 3310\nForeground yes\nMaxThreads 2\n"
        "MaxQueue 4\nConcurrentDatabaseReload no\nStreamMaxLength 64M\n"
        "MaxFileSize 64M\nMaxScanSize 128M\nMaxEmbeddedPE 64M\n"
        "PCREMaxFileSize 64M\nAlertExceedsMax yes\n", encoding="utf-8")
    manifest = {"version": "1.5.4", "archive_sha256": ARCHIVE_SHA256,
                "runtime_bytes": sum(item["bytes"] for item in files), "files": files}
    (root / "runtime-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"prepared": str(root), "runtime_bytes": manifest["runtime_bytes"],
                      "runtime_files": len(files)}), flush=True)


def version():
    try:
        with socket.create_connection(("127.0.0.1", 3310), timeout=.2) as connection:
            connection.sendall(b"zVERSION\0")
            return connection.recv(1024).decode("utf-8").rstrip("\0")
    except OSError:
        return None


def managed(root, updating, seconds):
    if not updating:
        # Refuse any existing listener, including one that does not speak clamd.
        with socket.socket() as reservation:
            reservation.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            reservation.bind(("127.0.0.1", 3310))
    if free_memory() < MIN_FREE_BYTES:
        raise RuntimeError("At least 2 GiB available RAM is required")
    tool = "freshclam" if updating else "clamd"
    command = [str(root / "runtime" / f"{tool}.exe"),
               f"--config-file={root / (tool + '.conf')}"]
    if not updating:
        command.append("--foreground")
    ready = root / "ready.json"
    if not updating:
        ready.unlink(missing_ok=True)
    with (root / "logs" / f"{tool}-console.log").open("ab") as log:
        process = subprocess.Popen(command, cwd=root / "runtime", stdout=log,
                                   stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        started = time.monotonic()
        announced = False
        minimum_available = free_memory()
        try:
            while process.poll() is None:
                available = free_memory()
                minimum_available = min(minimum_available, available)
                if available < MIN_FREE_BYTES:
                    raise RuntimeError("Stopped owned sidecar: available RAM fell below 2 GiB")
                if time.monotonic() - started > seconds:
                    raise TimeoutError(f"Owned {tool} exceeded {seconds}s budget")
                if not updating and not announced:
                    response = version()
                    if response:
                        state = {"pid": process.pid, "version": response,
                                 "host": "127.0.0.1", "port": 3310,
                                 "ready_seconds": time.monotonic() - started}
                        ready.write_text(json.dumps(state, indent=2), encoding="utf-8")
                        print(json.dumps(state), flush=True)
                        announced = True
                    elif time.monotonic() - started > 180:
                        raise TimeoutError("clamd was not ready in 180s")
                time.sleep(.5)
            if process.returncode:
                raise RuntimeError(f"{tool} exited {process.returncode}; inspect its log")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=15)
            if not updating:
                ready.unlink(missing_ok=True)
            print(json.dumps({"tool": tool, "pid": process.pid,
                              "returncode": process.returncode,
                              "minimum_available_bytes": minimum_available,
                              "owned_process_exited": process.poll() is not None}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "update", "run"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--seconds", type=int, default=1800)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.action == "prepare":
        if args.archive is None:
            parser.error("prepare requires --archive")
        prepare(args.archive.resolve(), root)
    else:
        managed(root, args.action == "update", args.seconds)


if __name__ == "__main__":
    main()
