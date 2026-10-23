import hashlib
import json
from unittest.mock import Mock

import pytest

from aegisav import hash_query as query


SHA = "a" * 64
OTHER = "b" * 64


def report(sha=SHA):
    return json.dumps({"data": {"id": sha, "type": "file", "attributes": {
        "sha256": sha, "last_analysis_stats": {"malicious": 2}}}}).encode()


def run(tmp_path, responses, hashes=None, **kwargs):
    transport = Mock(side_effect=responses)
    sleep = Mock()
    manifest = query.run_query(hashes or [SHA], tmp_path, transport=transport,
                               sleep=sleep, api_key="secret-test-key", **kwargs)
    return manifest, transport, sleep


def test_input_validation_normalizes_deduplicates_and_rejects_entire_bad_list(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text(f"# course\n{SHA.upper()}\n{SHA}\n{OTHER}\n", encoding="utf-8")
    assert query.read_hashes(path) == [SHA, OTHER]
    path.write_text(f"{SHA}\n../../path\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        query.read_hashes(path)


def test_fixed_get_report_is_saved_with_bound_identity_and_secret_is_absent(tmp_path):
    manifest, transport, _ = run(tmp_path, [(200, {}, report())])
    assert manifest["records"][SHA]["status"] == "found"
    assert transport.call_args.args == (SHA, "secret-test-key", 30.0)
    attempt = manifest["records"][SHA]["attempts"][0]
    raw = (tmp_path / attempt["raw_path"]).read_bytes()
    assert raw == report()
    assert attempt["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert "secret-test-key" not in (tmp_path / "manifest.json").read_text()


@pytest.mark.parametrize("body", [report(OTHER), b"not json", b'{}',
    json.dumps({"data": {"id": SHA, "type": "file", "attributes": {"sha256": OTHER}}}).encode()])
def test_malformed_or_mismatched_report_is_a_failure_with_raw_audit(tmp_path, body):
    manifest, _, _ = run(tmp_path, [(200, {}, body)])
    assert manifest["records"][SHA]["status"] == "invalid_report"
    assert (tmp_path / "audit.jsonl").exists()


def test_404_is_not_found_without_fabricated_report(tmp_path):
    body = b'{"error":{"code":"NotFoundError"}}'
    manifest, _, _ = run(tmp_path, [(404, {}, body)])
    record = manifest["records"][SHA]
    assert record["status"] == "not_found"
    assert "report" not in record
    assert (tmp_path / record["attempts"][0]["raw_path"]).read_bytes() == body


def test_rate_limit_retry_after_bounded_backoff_and_per_attempt_audit(tmp_path):
    manifest, transport, sleep = run(tmp_path, [
        (429, {"Retry-After": "60"}, b"rate limited"),
        (503, {}, b"unavailable"), (200, {}, report()),
        (200, {}, report(OTHER))], hashes=[SHA, OTHER])
    assert transport.call_count == 4
    assert sleep.call_args_list[0].args[0] == 60
    assert all(call.args[0] >= 15 for call in sleep.call_args_list)
    assert len(manifest["records"][SHA]["attempts"]) == 3
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) >= 4


def test_timeout_retries_exhaustion_and_auth_failure_stop_batch(tmp_path):
    manifest, transport, _ = run(tmp_path, [TimeoutError("secret-test-key")] * 3)
    assert transport.call_count == 3
    assert manifest["records"][SHA]["status"] == "network_error"
    assert "secret-test-key" not in (tmp_path / "manifest.json").read_text()
    other = tmp_path / "auth"
    manifest, transport, _ = run(other, [(401, {}, b"unauthorized")], hashes=[SHA, OTHER])
    assert transport.call_count == 1
    assert manifest["records"][OTHER]["status"] == "blocked_auth"


def test_resume_skips_verified_success_retries_failure_and_detects_tampering(tmp_path):
    first, _, _ = run(tmp_path, [(200, {}, report()), (500, {}, b"fail")] ,
                      hashes=[SHA, OTHER], retries=0)
    resumed, transport, _ = run(tmp_path, [(200, {}, report(OTHER))],
                               hashes=[SHA, OTHER], resume=True)
    assert transport.call_count == 1
    assert resumed["records"][OTHER]["status"] == "found"
    raw = tmp_path / first["records"][SHA]["attempts"][0]["raw_path"]
    raw.write_bytes(report(OTHER))
    with pytest.raises(ValueError, match="integrity"):
        run(tmp_path, [], hashes=[SHA, OTHER], resume=True)


def test_cverc_is_explicitly_blocked_without_network(tmp_path):
    manifest, transport, _ = run(tmp_path, [], provider="cverc")
    assert manifest["records"][SHA]["status"] == "blocked_no_documented_api"
    transport.assert_not_called()


def manual_import(tmp_path, sha=SHA):
    raw = tmp_path / "manual-report.json"
    raw.write_text(json.dumps({"sha256": sha, "result": "operator-provided"}))
    index = tmp_path / "imports.json"
    index.write_text(json.dumps([{"sha256": SHA, "report_file": raw.name,
        "report_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        "provenance": {"source_url": "https://www.cverc.org.cn/",
            "retrieved_at": "2026-10-23T10:00:00+08:00",
            "authenticated_by": "course-operator",
            "authentication_method": "authenticated official session; operator attestation"}}]))
    return index


def test_manual_import_requires_checksum_provenance_and_report_hash_binding(tmp_path):
    index = manual_import(tmp_path)
    manifest, transport, _ = run(tmp_path / "out", [], provider="cverc", imports=index)
    assert manifest["records"][SHA]["status"] == "manual_imported_unverified_origin"
    transport.assert_not_called()
    manual_import(tmp_path, OTHER)
    with pytest.raises(ValueError, match="binding"):
        run(tmp_path / "bad", [], provider="cverc", imports=index)


def test_cli_missing_key_is_actionable_and_does_not_make_network_request(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    source = tmp_path / "hashes.txt"
    source.write_text(SHA)
    assert query.main(["vt", "--input", str(source), "--output", str(tmp_path / "out")]) == 2
    assert "VT_API_KEY" in capsys.readouterr().err


def test_existing_output_requires_explicit_resume_and_manifest_identity(tmp_path):
    run(tmp_path, [(200, {}, report())])
    with pytest.raises(ValueError, match="resume"):
        run(tmp_path, [])
    with pytest.raises(ValueError, match="identity"):
        run(tmp_path, [], hashes=[OTHER], resume=True)


def test_response_echoing_credential_is_redacted_on_disk(tmp_path):
    manifest, _, _ = run(tmp_path, [(500, {}, b"secret-test-key")], retries=0)
    attempt = manifest["records"][SHA]["attempts"][0]
    assert attempt["raw_redacted"] is True
    assert b"secret-test-key" not in (tmp_path / attempt["raw_path"]).read_bytes()


def test_existing_vt_cache_is_reused_offline_without_key_or_network(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / f"{SHA}.json").write_bytes(report())
    manifest = query.run_query([SHA, OTHER], tmp_path / "out", cache_dir=cache)
    assert manifest["records"][SHA]["status"] == "cached_report"
    assert manifest["records"][OTHER]["status"] == "blocked_offline_cache_miss"
    assert manifest["requests"] == 0


def test_request_budget_persists_across_resume(tmp_path):
    manifest, transport, _ = run(tmp_path, [(500, {}, b"fail")], max_requests=1)
    assert transport.call_count == 1
    assert manifest["records"][SHA]["status"] == "blocked_request_budget"
    manifest, transport, _ = run(tmp_path, [], resume=True, max_requests=1)
    transport.assert_not_called()
    assert manifest["requests"] == 1


def test_transport_is_fixed_get_with_header_auth_and_no_redirects(monkeypatch):
    from io import BytesIO
    from urllib.request import Request

    response = BytesIO(report())
    response.code = 200
    response.headers = {}
    opener = Mock()
    opener.open.return_value = response
    factory = Mock(return_value=opener)
    monkeypatch.setattr(query, "build_opener", factory)
    assert query.fetch_vt(SHA, "test-key", 12)[0] == 200
    request = opener.open.call_args.args[0]
    assert request.full_url == f"https://www.virustotal.com/api/v3/files/{SHA}"
    assert request.get_method() == "GET" and request.data is None
    assert request.get_header("X-apikey") == "test-key"
    assert opener.open.call_args.kwargs["timeout"] == 12
    handler = factory.call_args.args[0]()
    assert handler.redirect_request(Request(request.full_url), None, 302, "", {}, "https://example.org") is None


@pytest.mark.parametrize("retry_after", ["NaN", "Infinity", "-1", "bad", "Wed, 21 Oct 2015 07:28:00 GMT"])
def test_malformed_or_stale_retry_after_is_bounded(retry_after):
    assert 16 <= query.retry_delay({"Retry-After": retry_after}, 0) <= 60


def test_corrupt_cache_cannot_be_reported_as_found_or_trigger_live_fallback(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / f"{SHA}.json").write_bytes(report(OTHER))
    manifest, transport, _ = run(tmp_path / "out", [], cache_dir=cache)
    transport.assert_not_called()
    assert manifest["records"][SHA]["status"] == "invalid_report"


def test_cli_offline_cache_needs_no_key_and_does_not_print_hashes(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    source = tmp_path / "hashes.txt"
    source.write_text(SHA)
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / f"{SHA}.json").write_bytes(report())
    assert query.main(["vt", "--input", str(source), "--cache-dir", str(cache),
                       "--output", str(tmp_path / "out")]) == 0
    output = capsys.readouterr().out
    assert SHA not in output and '"requests": 0' in output


def test_long_retry_after_defers_entire_batch_and_resume_until_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(query.time, "time", lambda: 1000.0)
    manifest, transport, sleep = run(tmp_path, [
        (429, {"Retry-After": "3600"}, b"quota")], hashes=[SHA, OTHER])
    assert transport.call_count == 1
    sleep.assert_not_called()
    assert manifest["not_before"] == 4600.0
    assert manifest["records"][SHA]["status"] == "deferred_retry_after"
    assert manifest["records"][OTHER]["status"] == "blocked_retry_after"
    resumed, transport, sleep = run(tmp_path, [], hashes=[SHA, OTHER], resume=True)
    transport.assert_not_called()
    sleep.assert_not_called()
    assert resumed["requests"] == 1
    monkeypatch.setattr(query.time, "time", lambda: 4601.0)
    resumed, transport, _ = run(tmp_path, [(200, {}, report()), (200, {}, report(OTHER))],
                               hashes=[SHA, OTHER], resume=True)
    assert transport.call_count == 2
    assert resumed["records"][SHA]["status"] == "found"


def test_large_response_read_is_bounded_and_failure_does_not_retry(tmp_path, monkeypatch):
    from io import BytesIO

    monkeypatch.setattr(query, "MAX_REPORT_BYTES", 1024)
    response = BytesIO(b"x" * 5000)
    response.code = 200
    response.headers = {}
    read = Mock(wraps=response.read)
    response.read = read
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(query, "build_opener", Mock(return_value=opener))
    manifest = query.run_query([SHA], tmp_path, api_key="test-key", live=True)
    assert manifest["records"][SHA]["status"] == "response_too_large"
    assert manifest["requests"] == 1
    assert read.call_args.args == (1025,)
    assert len((tmp_path / "manifest.json").read_bytes()) < 5000


def test_oversized_local_cache_and_manual_report_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(query, "MAX_REPORT_BYTES", 100)
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / f"{SHA}.json").write_bytes(b"x" * 101)
    with pytest.raises(ValueError, match="size limit"):
        query.run_query([SHA], tmp_path / "out", cache_dir=cache)
    index = manual_import(tmp_path)
    (tmp_path / "manual-report.json").write_bytes(b"x" * 101)
    with pytest.raises(ValueError, match="size limit"):
        query.run_query([SHA], tmp_path / "manual", provider="cverc", imports=index)


def test_resume_preserves_response_saved_before_manifest_commit(tmp_path):
    with pytest.raises(KeyboardInterrupt):
        run(tmp_path, [KeyboardInterrupt()])
    orphan = tmp_path / 'raw' / SHA / '0001.json'
    orphan.parent.mkdir(parents=True)
    orphan.write_bytes(b'original response persisted before crash')
    manifest, _, _ = run(tmp_path, [(200, {}, report())], resume=True)
    assert orphan.read_bytes() == b'original response persisted before crash'
    assert manifest['records'][SHA]['attempts'][-1]['raw_path'].endswith('/0002.json')
