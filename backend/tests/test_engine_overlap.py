import hashlib
import random
from threading import Event

import pytest

from aegisav.hashes import HashDatabase
from aegisav.scanner import StaticScanner


def test_fuzzy_work_does_not_delay_independent_engines_or_change_fusion_order(monkeypatch, pe_bytes):
    from aegisav import scanner as module
    started = Event()
    original = module.hash_scan

    def hash_scan(*args):
        assert started.wait(.5), 'ML could not start while fuzzy hashing was in progress'
        return original(*args)

    class Positive:
        artifact_version = 'fixture'

        def __init__(self, name):
            self.name = name

        def scan(self, data):
            if self.name == 'lightgbm':
                started.set()
            return dict(engine_id=self.name, engine_version='fixture', artifact_version='fixture',
                        status='matched', elapsed_ms=0., evidence=['harmless fixture'], risk_signal='suspicious')

    monkeypatch.setattr(module, 'hash_scan', hash_scan)
    pe_bytes += random.Random(0).randbytes(1024**2)
    database = HashDatabase.from_records([dict(sha256=hashlib.sha256(pe_bytes).hexdigest(),
                                              verdict='malicious', source='harmless fixture only')])
    scanner = StaticScanner(database, yara_engine=Positive('yara_x'), clamav_engine=Positive('clamav'),
                            ml_engine=Positive('lightgbm'))
    report = scanner.scan(pe_bytes)
    assert list(report['engines']) == ['sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm']
    assert report['fusion']['positive_engines'] == ['sha256', 'yara_x', 'clamav', 'lightgbm']
    assert report['verdict'] == 'malicious'
    assert scanner.scan(pe_bytes)['cached'] is True


@pytest.mark.parametrize('padding', [0, 1024**2])
def test_overlapping_failures_keep_existing_abstention_order(pe_bytes, padding):
    class OfflineClam:
        def probe(self):
            return False

    class Unavailable:
        def scan(self, data):
            return dict(status='timeout', evidence=[], risk_signal=None)

    report = StaticScanner(HashDatabase.from_records([]), yara_engine=Unavailable(),
                           clamav_engine=OfflineClam(), ml_engine=Unavailable()).scan(
                               pe_bytes + random.Random(0).randbytes(padding))
    assert report['fusion']['abstained_engines'] == ['clamav', 'yara_x', 'lightgbm']
    assert not report['cached']
