"""Exact byte counts with bounded NumPy conversion; all other upstream features unchanged."""


def histogram_counts(data):
    import numpy as np
    counts = np.zeros(256, dtype=np.int64)
    view = memoryview(data)
    for start in range(0, len(view), 1024**2):
        counts += np.bincount(np.frombuffer(view[start:start + 1024**2], dtype=np.uint8), minlength=256)
    return counts.tolist()


def build_extractor(module, implementation):
    extractor = module.PEFeatureExtractor()
    if implementation == 'upstream-v3':
        return extractor
    if implementation != 'chunked-histogram-v1':
        raise ValueError('Unsupported feature implementation')
    class ChunkedHistogram(module.ByteHistogram):
        def raw_features(self, bytez, pe):
            return histogram_counts(bytez)
    matches = [index for index, feature in enumerate(extractor.features) if isinstance(feature, module.ByteHistogram)]
    if len(matches) != 1:
        raise ValueError('Unexpected upstream histogram layout')
    extractor.features[matches[0]] = ChunkedHistogram()
    return extractor
