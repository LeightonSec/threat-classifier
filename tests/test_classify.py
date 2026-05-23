"""
Integration tests for the classify() public API.
Mocks _predict and _load_components — torch/transformers not required.
"""
from unittest.mock import MagicMock, patch

import pytest

from threat_classifier import classify
from threat_classifier.models import ClassificationResult


@pytest.fixture(autouse=True)
def clear_lru_cache():
    from threat_classifier.inference import _load_components
    _load_components.cache_clear()
    yield
    _load_components.cache_clear()


@patch("threat_classifier.inference._predict", return_value=("threat", 0.92))
@patch("threat_classifier.inference._load_components", return_value=(MagicMock(), MagicMock()))
def test_returns_classification_result(_mock_load, _mock_predict):
    result = classify("some input text")
    assert isinstance(result, ClassificationResult)


@patch("threat_classifier.inference._predict", return_value=("threat", 0.92))
@patch("threat_classifier.inference._load_components", return_value=(MagicMock(), MagicMock()))
def test_result_has_required_fields(_mock_load, _mock_predict):
    result = classify("some input text")
    assert result.label in ("threat", "benign")
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.escalate, bool)


@patch("threat_classifier.inference._predict")
@patch("threat_classifier.inference._load_components", return_value=(MagicMock(), MagicMock()))
def test_normalisation_applied_before_classification(_mock_load, mock_predict):
    mock_predict.return_value = ("benign", 0.95)
    classify("hello​world")  # zero-width space
    called_text = mock_predict.call_args[0][2]
    assert "​" not in called_text


@patch("threat_classifier.inference._predict", return_value=("threat", 0.92))
@patch("threat_classifier.inference._load_components", return_value=(MagicMock(), MagicMock()))
def test_threat_pipeline_end_to_end(_mock_load, _mock_predict):
    result = classify("any text")
    assert result.label == "threat"
    assert result.escalate is False


@patch("threat_classifier.inference._predict", return_value=("benign", 0.96))
@patch("threat_classifier.inference._load_components", return_value=(MagicMock(), MagicMock()))
def test_benign_pipeline_end_to_end(_mock_load, _mock_predict):
    result = classify("any text")
    assert result.label == "benign"
    assert result.escalate is False
