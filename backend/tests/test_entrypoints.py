from aegisav.main import app
from aegisav.benchmark import benchmark
from aegisav.clamav_engine import ClamAVEngine
from aegisav.hashes import HashDatabase
from aegisav.scanner import StaticScanner


def test_default_app_has_scan_route():
    assert any(route.path == "/v1/scan" for route in app.routes)


def test_benchmark_records_measured_latencies(tmp_path, pe_bytes):
    sample = tmp_path / "safe.bin"
    sample.write_bytes(pe_bytes)
    scanner = StaticScanner(HashDatabase.from_records([]), clamav_engine=ClamAVEngine(port=0))
    result = benchmark([sample], iterations=2, scanner=scanner)
    assert result["scan_count"] == 2
    assert result["p50_ms"] > 0
    assert result["p95_ms"] >= result["p50_ms"]
    assert result["engine_status_counts"]["clamav"]["unavailable"] == 2
