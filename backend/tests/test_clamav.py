import socket
import struct
import threading

import pytest

from aegisav.clamav_engine import ClamAVEngine


def fake_clamd(reply):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received = bytearray()

    def serve():
        conn, _ = listener.accept()
        with conn:
            command = bytearray()
            while not command.endswith(b"\0"):
                command.extend(conn.recv(1))
            assert command == b"zINSTREAM\0"
            while True:
                size = struct.unpack("!I", conn.recv(4))[0]
                if size == 0:
                    break
                while len(received) < size:
                    received.extend(conn.recv(size - len(received)))
            conn.sendall(reply)
        listener.close()

    thread = threading.Thread(target=serve)
    thread.start()
    return port, received, thread


def test_clamav_streams_bytes_and_reports_signature(pe_bytes):
    port, received, thread = fake_clamd(b"stream: Test.Signature FOUND\0")
    result = ClamAVEngine(port=port).scan(pe_bytes)
    thread.join(timeout=2)
    assert bytes(received) == pe_bytes
    assert result["status"] == "matched"
    assert result["evidence"][0]["signature"] == "Test.Signature"


def test_clamav_clean_and_unavailable_are_distinct(pe_bytes):
    port, _, thread = fake_clamd(b"stream: OK\0")
    clean = ClamAVEngine(port=port).scan(pe_bytes)
    thread.join(timeout=2)
    assert clean["status"] == "no_match"
    offline = ClamAVEngine(port=0).scan(pe_bytes)
    assert offline["status"] == "unavailable"


def test_clamav_protocol_error_is_not_clean(pe_bytes):
    port, _, thread = fake_clamd(b"stream: malformed ERROR\0")
    result = ClamAVEngine(port=port).scan(pe_bytes)
    thread.join(timeout=2)
    assert result["status"] == "error"


def test_clamav_truncated_ok_reply_is_error(pe_bytes):
    port, _, thread = fake_clamd(b"stream: OK")
    result = ClamAVEngine(port=port).scan(pe_bytes)
    thread.join(timeout=2)
    assert result["status"] == "error"


def test_clamav_rejects_unexpected_ok_prefix(pe_bytes):
    port, _, thread = fake_clamd(b"error: OK\0")
    result = ClamAVEngine(port=port).scan(pe_bytes)
    thread.join(timeout=2)
    assert result["status"] == "error"


@pytest.mark.parametrize("signature", ["Heuristics.Limits.Exceeded", "Heuristics.Limits.Exceeded.MaxScanSize"])
def test_clamav_scan_limit_is_not_a_malware_detection(pe_bytes, signature):
    port, _, thread = fake_clamd(f"stream: {signature} FOUND\0".encode())
    result = ClamAVEngine(port=port).scan(pe_bytes)
    thread.join(timeout=2)
    assert result["status"] == "error"
    assert result["risk_signal"] is None


def test_probe_reads_daemon_and_signature_version():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        with conn:
            assert conn.recv(9) == b"zVERSION\0"
            conn.sendall(b"ClamAV 1.4.0/27300/Mon Sep 28 2026\0")
        listener.close()

    thread = threading.Thread(target=serve)
    thread.start()
    engine = ClamAVEngine(port=port)
    assert engine.probe() is True
    thread.join(timeout=2)
    assert engine.engine_version == "ClamAV 1.4.0"
    assert engine.artifact_version == "27300"


def test_probe_marks_missing_daemon_unavailable():
    assert ClamAVEngine(port=0).probe() is False


def test_probe_rejects_unterminated_version_reply():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        with conn:
            assert conn.recv(9) == b"zVERSION\0"
            conn.sendall(b"ClamAV 1.4.0/27300")
        listener.close()

    thread = threading.Thread(target=serve)
    thread.start()
    assert ClamAVEngine(port=port).probe() is False
    thread.join(timeout=2)
