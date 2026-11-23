import math

from vm.static_ember import EmberEngine


class Vector:
    def __init__(self, shape=(2568,)):
        self.shape = shape

    def reshape(self, *shape):
        assert shape == (1, -1)
        return self


class Extractor:
    def __init__(self, vector):
        self.vector = vector

    def feature_vector(self, data):
        assert data == b'harmless'
        return self.vector


class Model:
    def __init__(self, score):
        self.score = score
        self.calls = 0

    def predict(self, vector, num_threads):
        self.calls += 1
        assert num_threads == 1
        return [self.score]


class Finite:
    @staticmethod
    def isfinite(vector):
        class Check:
            def all(self):
                return True
        return Check()


def engine(score=0.8, shape=(2568,)):
    result = EmberEngine.__new__(EmberEngine)
    result.np = Finite()
    result.extractor = Extractor(Vector(shape))
    result.model = Model(score)
    result.artifact_version = 'official-pretrained-test'
    return result


def test_model_threshold_is_predeclared_and_scores_preserved():
    assert engine(0.5).scan(b'harmless')['status'] == 'matched'
    result = engine(0.499).scan(b'harmless')
    assert result['status'] == 'no_match'
    assert result['score'] == 0.499


def test_wrong_feature_dimension_is_an_abstention_without_predicting():
    model = engine(shape=(2381,))
    result = model.scan(b'harmless')
    assert result['status'] == 'error'
    assert result['score'] is None
    assert model.model.calls == 0


def test_nonfinite_or_out_of_range_predictions_are_never_normal_negatives():
    for score in (math.nan, math.inf, -0.1, 1.1):
        result = engine(score).scan(b'harmless')
        assert result['status'] == 'error'
        assert result['score'] is None
