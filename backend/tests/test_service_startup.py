def test_late_clamav_start_keeps_adapter_available_for_request_reprobe(monkeypatch):
    from aegisav import runtime
    class DelayedClamAV:
        started = False
        probes = 0
        def probe(self):
            self.probes += 1
            return self.started
    engine = DelayedClamAV()
    monkeypatch.setattr(runtime, 'ClamAVEngine', lambda: engine)
    scanner = runtime.build_scanner()
    assert scanner.clamav_engine is engine
    assert engine.probes == 0
    engine.started = True
    assert scanner.clamav_engine.probe() is True
