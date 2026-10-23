"""Independent SHA-256 report CLI; no sample upload, download or execution."""
import argparse
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


VT_URL = "https://www.virustotal.com/api/v3/files/"
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
TERMINAL = {"found", "cached_report", "not_found", "manual_imported_unverified_origin"}


def read_hashes(path):
    hashes = []
    for number, line in enumerate(read_limited(path, MAX_INPUT_BYTES).decode("utf-8-sig").splitlines(), 1):
        value = line.strip().lower()
        if not value or value.startswith("#"):
            continue
        if not SHA256.fullmatch(value):
            raise ValueError(f"Invalid SHA-256 at line {number}")
        if value not in hashes:
            hashes.append(value)
    if not hashes:
        raise ValueError("No SHA-256 values supplied")
    return hashes


def read_limited(path, limit=None):
    if limit is None:
        limit = MAX_REPORT_BYTES
    with Path(path).open("rb") as stream:
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise ValueError("Local input exceeds size limit")
    return body


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".hash-query-")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


def vt_identity(body, sha):
    try:
        data = json.loads(body)["data"]
        return (data["type"] == "file" and data["id"] == sha
                and data["attributes"]["sha256"] == sha)
    except (ValueError, KeyError, TypeError):
        return False


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ResponseTooLarge(Exception):
    pass


def fetch_vt(sha, api_key, timeout):
    """Same fixed GET protocol as apicall/providers/virustotal.py; no redirects."""
    if not SHA256.fullmatch(sha):
        raise ValueError("Invalid SHA-256")
    request = Request(VT_URL + sha, headers={"x-apikey": api_key,
                      "Accept": "application/json"}, method="GET")
    try:
        response = build_opener(NoRedirect).open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(MAX_REPORT_BYTES + 1)
        if len(body) > MAX_REPORT_BYTES:
            raise ResponseTooLarge()
        return response.code, dict(response.headers), body


def retry_after_seconds(headers):
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), "")
    try:
        delay = float(value)
        if not math.isfinite(delay):
            raise ValueError()
    except (ValueError, TypeError):
        try:
            delay = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            delay = 0
    return max(0.0, delay)


def retry_delay(headers, attempt):
    delay = retry_after_seconds(headers)
    if delay > 60:
        return None  # Persist a deadline and defer; never shorten a server minimum.
    return min(60.0, max(16.0, 16.0 * (2 ** attempt), delay))


def load_imports(index, hashes):
    if index is None:
        return {}
    index = Path(index)
    result = {}
    for entry in json.loads(read_limited(index, MAX_INPUT_BYTES).decode("utf-8-sig")):
        sha = entry["sha256"]
        if sha not in hashes or sha in result:
            raise ValueError("Manual import identity mismatch or duplicate")
        provenance = entry["provenance"]
        url = urlsplit(provenance["source_url"])
        if (url.scheme != "https" or url.hostname not in {
                "cverc.org.cn", "www.cverc.org.cn", "virus.cverc.org.cn"}
                or url.username or url.password or url.query or url.fragment):
            raise ValueError("Manual import requires an official provenance URL without credentials")
        timestamp = datetime.fromisoformat(provenance["retrieved_at"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or any(not isinstance(provenance.get(key), str)
                or not provenance[key].strip() for key in ("authenticated_by", "authentication_method")):
            raise ValueError("Manual import requires timestamp and operator authentication attestation")
        path = (index.parent / entry["report_file"]).resolve()
        if index.parent.resolve() not in path.parents:
            raise ValueError("Manual report must be inside the import directory")
        body = read_limited(path)
        if hashlib.sha256(body).hexdigest() != entry["report_sha256"]:
            raise ValueError("Manual import checksum mismatch")
        if json.loads(body).get("sha256") != sha:
            raise ValueError("Manual report SHA-256 binding mismatch")
        result[sha] = (body, provenance)
    return result


def run_query(hashes, output, *, provider="vt", api_key=None, transport=None,
              sleep=time.sleep, timeout=30.0, retries=2, resume=False,
              imports=None, cache_dir=None, live=False, max_requests=400):
    hashes = list(dict.fromkeys(hashes))
    if not hashes or any(not isinstance(sha, str) or not SHA256.fullmatch(sha) for sha in hashes):
        raise ValueError("Invalid SHA-256 input")
    if (provider not in {"vt", "cverc"} or not math.isfinite(timeout) or timeout <= 0
            or not 0 <= retries <= 5 or not 1 <= max_requests <= 500):
        raise ValueError("Invalid provider, timeout, retries or request budget")
    if imports is not None and provider != "cverc":
        raise ValueError("Manual imports are CVERC only")
    if cache_dir is not None and provider != "vt":
        raise ValueError("Raw cache is VT only")
    network = provider == "vt" and (live or transport is not None)
    if network and not api_key:
        raise ValueError("VT_API_KEY is required for live VT queries")
    manual = load_imports(imports, hashes)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    lock = output / ".hash-query.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise ValueError("Output is locked; after confirming no process is running remove .hash-query.lock") from None
    os.close(descriptor)
    try:
        return _run(hashes, output, provider, api_key, transport or fetch_vt, sleep,
                    timeout, retries, resume, manual, cache_dir, network, max_requests)
    finally:
        lock.unlink(missing_ok=True)


def _run(hashes, output, provider, api_key, transport, sleep, timeout, retries,
         resume, manual, cache_dir, network, max_requests):
    path = output / "manifest.json"
    if path.exists():
        if not resume:
            raise ValueError("Output exists; use --resume")
        manifest = json.loads(read_limited(path).decode("utf-8"))
        if (manifest.get("schema") != 1 or manifest.get("provider") != provider
                or manifest.get("hashes") != hashes):
            raise ValueError("Resume manifest identity mismatch")
    else:
        manifest = {"schema": 1, "provider": provider, "hashes": hashes,
                    "requests": 0, "records": {sha: {"status": "pending", "attempts": []} for sha in hashes}}

    def save(sha):
        manifest["updated_at"] = datetime.now(UTC).isoformat()
        atomic_write(path, json_bytes(manifest))
        event = {"time": manifest["updated_at"], "sha256": sha,
                 "status": manifest["records"][sha]["status"], "requests": manifest["requests"]}
        if manifest.get("not_before"):
            event["not_before"] = manifest["not_before"]
        with (output / "audit.jsonl").open("ab") as stream:
            stream.write(json.dumps(event).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def store(sha, record, body, status, **metadata):
        redacted = bool(api_key and api_key.encode() in body)
        if redacted:
            body = body.replace(api_key.encode(), b"[REDACTED]")
        number = len(record['attempts']) + 1
        relative = f"raw/{sha}/{number:04d}.json"
        # A crash may persist raw bytes before committing their manifest entry.
        # Preserve those orphan responses instead of replacing them on resume.
        while (output / relative).exists():
            number += 1
            relative = f"raw/{sha}/{number:04d}.json"
        atomic_write(output / relative, body)
        record["attempts"].append({"raw_path": relative,
            "raw_sha256": hashlib.sha256(body).hexdigest(), "raw_redacted": redacted, **metadata})
        record["status"] = status
        save(sha)

    # Verify every completed raw artifact before allowing resume to skip it.
    for sha, record in manifest["records"].items():
        if record["status"] in TERMINAL:
            attempt = record["attempts"][-1]
            raw_path = (output / attempt["raw_path"]).resolve()
            if output.resolve() not in raw_path.parents:
                raise ValueError("Resume raw integrity failure")
            body = read_limited(raw_path)
            if (hashlib.sha256(body).hexdigest() != attempt["raw_sha256"]
                    or (record["status"] in {"found", "cached_report"} and not vt_identity(body, sha))):
                raise ValueError("Resume raw integrity failure")

    auth_blocked = False
    wait = 16.0 if manifest["requests"] else 0.0
    for sha in hashes:
        record = manifest["records"][sha]
        if record["status"] in TERMINAL:
            continue
        if provider == "cverc":
            if sha in manual:
                body, provenance = manual[sha]
                store(sha, record, body, "manual_imported_unverified_origin", provenance=provenance)
            else:
                record["status"] = "blocked_no_documented_api"
                save(sha)
            continue
        cached = Path(cache_dir) / f"{sha}.json" if cache_dir is not None else None
        if cached is not None and cached.exists():
            body = read_limited(cached)
            store(sha, record, body, "cached_report" if vt_identity(body, sha) else "invalid_report",
                  source="existing_apicall_cache", source_path=str(cached.resolve()))
            continue
        if not network or auth_blocked:
            record["status"] = "blocked_auth" if auth_blocked else "blocked_offline_cache_miss"
            save(sha)
            continue
        if manifest.get("not_before", 0) > time.time():
            if record["status"] != "deferred_retry_after":
                record["status"] = "blocked_retry_after"
            save(sha)
            continue
        for attempt in range(retries + 1):
            if manifest["requests"] >= max_requests:
                record["status"] = "blocked_request_budget"
                save(sha)
                break
            if wait:
                sleep(wait)
            manifest["requests"] += 1
            record["status"] = "requesting"
            save(sha)  # Reserve the request before sending, including interrupted requests.
            wait = 16.0
            try:
                status, headers, body = transport(sha, api_key, timeout)
                if len(body) > MAX_REPORT_BYTES:
                    raise ResponseTooLarge()
            except ResponseTooLarge:
                record["attempts"].append({"error": "response_too_large",
                    "limit_bytes": MAX_REPORT_BYTES, "time": datetime.now(UTC).isoformat()})
                record["status"] = "response_too_large"
                save(sha)
                break
            except (TimeoutError, URLError, OSError):
                record["attempts"].append({"error": "network_error", "time": datetime.now(UTC).isoformat()})
                record["status"] = "network_error"
                save(sha)
                wait = retry_delay({}, attempt)
                continue
            state = ("found" if vt_identity(body, sha) else "invalid_report") if status == 200 else {
                404: "not_found", 401: "authentication_error", 403: "authentication_error",
                429: "rate_limited"}.get(status, "http_error")
            retry_wait = retry_delay(headers, attempt)
            if retry_wait is None:
                manifest["not_before"] = time.time() + retry_after_seconds(headers)
                record["not_before"] = manifest["not_before"]
                state = "deferred_retry_after"
            store(sha, record, body, state, http_status=status, time=datetime.now(UTC).isoformat())
            if status in {401, 403}:
                auth_blocked = True
            if retry_wait is None:
                break
            if status != 429 and not 500 <= status <= 599:
                break
            wait = retry_wait
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=("vt", "cverc"))
    parser.add_argument("--input", type=Path, required=True, help="One SHA-256 per line; comments begin #")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--live", action="store_true", help="Explicitly authorize VT GET requests for cache misses")
    parser.add_argument("--cache-dir", type=Path, help="Reuse existing VT raw JSON files offline")
    parser.add_argument("--imports", type=Path, help="CVERC manual report provenance index")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--max-requests", type=int, default=400, help="Persistent output budget (1..500), including retries")
    args = parser.parse_args(argv)
    try:
        # Compatibility with the audited sibling app; never read dotenv or key files.
        key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
        if args.provider == "vt" and not args.cache_dir and not args.live:
            raise ValueError("Choose --cache-dir for offline reuse, or --live with VT_API_KEY")
        if args.provider == "cverc" and args.live:
            raise ValueError("CVERC live API blocked pending verified official documentation")
        manifest = run_query(read_hashes(args.input), args.output, provider=args.provider,
            api_key=key, live=args.live, resume=args.resume, cache_dir=args.cache_dir,
            imports=args.imports, timeout=args.timeout, retries=args.retries, max_requests=args.max_requests)
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        # Do not echo raw exceptions, input content, HTTP bodies or credentials.
        print("Query could not start or resume: check input/provenance, output lock/integrity, "
              "--resume and VT_API_KEY for --live. See COURSE_HASH_QUERY.md.", file=sys.stderr)
        return 2
    counts = {}
    for record in manifest["records"].values():
        counts[record["status"]] = counts.get(record["status"], 0) + 1
    print(json.dumps({"provider": args.provider, "unique_hashes": len(manifest["hashes"]),
                      "requests": manifest["requests"], "statuses": counts}))
    return 0 if all(record["status"] in TERMINAL for record in manifest["records"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
