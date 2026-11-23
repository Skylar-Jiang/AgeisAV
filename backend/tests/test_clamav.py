import socket
import struct
import threading
import socketserver

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


def test_scanner_reprobes_outages_and_versions_before_reusing_complete_results(pe_bytes):
    from aegisav.hashes import HashDatabase
    from aegisav.scanner import StaticScanner
    state = {'online': True, 'version': '27300', 'matched': False, 'drop_stream': False, 'streams': 0}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            connection = self.request
            connection.settimeout(2)
            command = bytearray()
            while not command.endswith(b'\0'):
                command.extend(connection.recv(1))
            if command == b'zVERSION\0':
                if state['online']:
                    connection.sendall(f"ClamAV 1.4.0/{state['version']}/fixture\0".encode())
                return
            assert command == b'zINSTREAM\0'
            state['streams'] += 1
            if state['drop_stream']:
                return

            def read_exact(size):
                data = bytearray()
                while len(data) < size:
                    part = connection.recv(size - len(data))
                    if not part:
                        raise EOFError('Truncated fixture request')
                    data.extend(part)
                return bytes(data)

            received = bytearray()
            while size := struct.unpack('!I', read_exact(4))[0]:
                received.extend(read_exact(size))
            assert bytes(received) == pe_bytes
            connection.sendall(b'stream: Harmless.Fixture FOUND\0' if state['matched'] else b'stream: OK\0')

    class CleanYara:
        artifact_version = 'fixture'

        def scan(self, data):
            return dict(engine_id='yara_x', engine_version='fixture', artifact_version='fixture',
                        status='no_match', elapsed_ms=0., evidence=[], risk_signal=None)

    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        thread.start()
        try:
            scanner = StaticScanner(HashDatabase.from_records([]), yara_engine=CleanYara(),
                                    clamav_engine=ClamAVEngine(port=server.server_address[1]))
            assert scanner.scan(pe_bytes)['engines']['clamav']['status'] == 'no_match'
            assert scanner.scan(pe_bytes)['cached'] is True
            assert state['streams'] == 1
            state['online'] = False
            offline = scanner.scan(pe_bytes)
            assert offline['engines']['clamav']['status'] == 'unavailable'
            assert offline['cached'] is False and offline['verdict'] == 'undetermined'
            assert 'clamav' in offline['fusion']['abstained_engines']
            assert state['streams'] == 1
            state.update(online=True, version='27301', matched=True)
            recovered = scanner.scan(pe_bytes)
            assert recovered['verdict'] == 'suspicious' and recovered['cached'] is False
            assert recovered['engines']['clamav']['artifact_version'] == '27301'
            assert scanner.scan(pe_bytes)['cached'] is True
            state.update(version='27302', drop_stream=True)
            failed = scanner.scan(pe_bytes)
            assert failed['engines']['clamav']['status'] not in {'matched', 'no_match'}
            assert 'clamav' in failed['fusion']['abstained_engines'] and not failed['cached']
        finally:
            server.shutdown()
            thread.join(timeout=2)
