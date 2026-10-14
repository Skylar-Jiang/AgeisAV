def test_late_clamav_start_keeps_adapter_available_for_request_reprobe(monkeypatch):
    from aegisav import main
    class DelayedClamAV:
        started = False
        def probe(self):
            return self.started
    engine = DelayedClamAV()
    monkeypatch.setattr(main, 'ClamAVEngine', lambda: engine)
    scanner = main.build_scanner()
    assert scanner.clamav_engine is engine
    engine.started = True
    assert scanner.clamav_engine.probe() is True
