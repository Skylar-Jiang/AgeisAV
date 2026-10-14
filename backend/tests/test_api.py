import base64
import asyncio
import threading

import httpx
from fastapi.testclient import TestClient

from aegisav.api import create_app
from aegisav.hashes import HashDatabase
from aegisav.scanner import StaticScanner


def test_scan_api_returns_report_and_rejects_non_pe(pe_bytes):
    client = TestClient(create_app(StaticScanner(HashDatabase.from_records([]))))
    report = client.post("/v1/scan", content=pe_bytes, headers={"content-type": "application/octet-stream"})
    assert report.status_code == 200
    assert report.json()["sha256"]
    assert report.json()["verdict"] == "undetermined"
    assert client.post("/v1/scan", content=b"hello").status_code == 422


def test_scan_api_rejects_oversized_body(pe_bytes):
    client = TestClient(create_app(StaticScanner(HashDatabase.from_records([])), max_file_bytes=100))
    assert client.post("/v1/scan", content=pe_bytes).status_code == 413


def test_batch_api_reports_duplicates(pe_bytes):
    client = TestClient(create_app(StaticScanner(HashDatabase.from_records([]))))
    encoded = base64.b64encode(pe_bytes).decode("ascii")
    response = client.post("/v1/scan/batch", json={"files": [encoded, encoded]})
    assert response.status_code == 200
    assert response.json()["results"][1]["duplicate_of"] == 0


def test_inventory_exposes_installed_release_identity():
    scanner = StaticScanner(HashDatabase.from_records([]))
    client = TestClient(create_app(scanner, release_id='content-addressed-fixture'))
    inventory = client.get('/v1/engines').json()
    assert inventory['service_release'] == 'content-addressed-fixture'
    assert inventory['fusion_policy'] == 'evidence-or-v1'
    assert {engine['id'] for engine in inventory['engines']}=={'sha256','fuzzy','yara_x','clamav','lightgbm'}
    assert next(e for e in inventory['engines'] if e['id']=='lightgbm')['status']=='unavailable'
    assert inventory['task_limits']['persistent'] is False


def test_simultaneous_http_scans_do_not_block_the_event_loop(pe_bytes):
    barrier = threading.Barrier(2, timeout=0.5)

    class ConcurrentScanner:
        def scan(self, data):
            try:
                barrier.wait()
                return {"parallel": True}
            except threading.BrokenBarrierError:
                return {"parallel": False}

    async def run():
        transport = httpx.ASGITransport(app=create_app(ConcurrentScanner()))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await asyncio.gather(*(client.post("/v1/scan", content=pe_bytes) for _ in range(2)))

    results = asyncio.run(run())
    assert all(result.json()["parallel"] for result in results)
