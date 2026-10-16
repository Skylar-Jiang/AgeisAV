def test_late_clamav_start_keeps_adapter_available_for_request_reprobe(monkeypatch):
    from aegisav import runtime
    class DelayedClamAV:
        started = False
        def probe(self):
            return self.started
    engine = DelayedClamAV()
    monkeypatch.setattr(runtime, 'ClamAVEngine', lambda: engine)
    scanner = runtime.build_scanner()
    assert scanner.clamav_engine is engine
    engine.started = True
    assert scanner.clamav_engine.probe() is True
