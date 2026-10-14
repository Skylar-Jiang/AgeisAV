import socket
import struct
import time
from dataclasses import dataclass


@dataclass
class ClamAVEngine:
    host: str = "127.0.0.1"
    port: int = 3310
    timeout_seconds: float = 90.0
    engine_version: str = "unknown"
    artifact_version: str = "unknown"

    def __post_init__(self):
        if self.host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("ClamAV TCP connection must stay on loopback")

    def probe(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=0.2) as connection:
                connection.settimeout(0.2)
                connection.sendall(b"zVERSION\0")
                response = bytearray()
                while not response.endswith(b"\0") and len(response) < 1024:
                    part = connection.recv(1024)
                    if not part:
                        break
                    response.extend(part)
                if not response.endswith(b"\0"):
                    return False
                parts = bytes(response).rstrip(b"\0").decode("utf-8").split("/")
                if not parts[0].startswith("ClamAV ") or len(parts) < 2:
                    return False
                self.engine_version = parts[0]
                self.artifact_version = parts[1]
                return True
        except (OSError, UnicodeError):
            return False

    def scan(self, data: bytes) -> dict:
        started = time.perf_counter()
        status = "error"
        evidence = []
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout_seconds) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.sendall(b"zINSTREAM\0")
                for offset in range(0, len(data), 1024 * 1024):
                    chunk = data[offset:offset + 1024 * 1024]
                    connection.sendall(struct.pack("!I", len(chunk)) + chunk)
                connection.sendall(struct.pack("!I", 0))
                response = bytearray()
                while not response.endswith(b"\0") and len(response) < 4096:
                    part = connection.recv(4096)
                    if not part:
                        break
                    response.extend(part)
                message = bytes(response).rstrip(b"\0").decode("utf-8", errors="replace")
                if response.endswith(b"\0") and message == "stream: OK":
                    status = "no_match"
                elif response.endswith(b"\0") and message.startswith("stream: ") and message.endswith(" FOUND"):
                    signature = message[len("stream: "):-len(" FOUND")]
                    evidence = [{"signature": signature}]
                    status = "error" if signature.startswith("Heuristics.Limits.Exceeded") else "matched"
        except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            status = "timeout" if isinstance(exc, TimeoutError) else "unavailable"
        return {
            "engine_id": "clamav", "engine_version": self.engine_version,
            "artifact_version": self.artifact_version, "status": status,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "risk_signal": "suspicious" if status == "matched" else None, "evidence": evidence,
        }
