import importlib.util
from pathlib import Path

import pytest

np = pytest.importorskip('numpy')


def test_histogram_is_exact_across_chunks_and_bounds_numpy_temporary(monkeypatch):
    from aegisav.ember_features import histogram_counts
    data = np.random.default_rng(12).integers(0, 256, 2 * 1024**2 + 29, dtype=np.uint8).tobytes()
    expected = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).tolist()
    sizes = []
    original = np.bincount
    def observed(array, **kwargs):
        sizes.append(array.size)
        return original(array, **kwargs)
    monkeypatch.setattr(np, 'bincount', observed)
    assert histogram_counts(data) == expected
    assert len(sizes) == 3 and max(sizes) <= 1024**2
    assert histogram_counts(b'') == [0] * 256


def test_complete_feature_vector_and_model_score_are_bitwise_equal():
    from aegisav.ember_features import build_extractor
    root = Path(__file__).resolve().parents[2] / 'models/ember2024'
    if not (root / 'features.py').exists():
        pytest.skip('Pinned local model bundle required')
    import lightgbm
    spec = importlib.util.spec_from_file_location('test_pinned_features', root / 'features.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    path = Path('C:/Windows/SysWOW64/webio.dll')
    if not path.exists():
        pytest.skip('Trusted installed Windows fixture unavailable')
    data = path.read_bytes()
    original = module.PEFeatureExtractor().feature_vector(data)
    chunked = build_extractor(module, 'chunked-histogram-v1').feature_vector(data)
    assert original.shape == chunked.shape == (2568,)
    assert original.tobytes() == chunked.tobytes()
    model = lightgbm.Booster(model_file=str(root / 'EMBER2024_PE.model'))
    assert model.predict(original.reshape(1, -1), num_threads=1).tobytes() == model.predict(chunked.reshape(1, -1), num_threads=1).tobytes()
