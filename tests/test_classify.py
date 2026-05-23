from threat_classifier import classify
from threat_classifier.models import ClassificationResult


def test_returns_classification_result():
    result = classify("some input text")
    assert isinstance(result, ClassificationResult)


def test_result_has_required_fields():
    result = classify("some input text")
    assert result.label in ("threat", "benign")
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.escalate, bool)


def test_normalisation_applied_before_classification():
    # Zero-width chars around a threat keyword — normalised input still hits the classifier
    result = classify("e​val(payload)")
    assert result.label == "threat"


def test_zero_width_stripped_before_benign_check():
    # Zero-width chars in clean text — still classified benign after normalisation
    result = classify("normal​ log entry")
    assert result.label == "benign"


def test_threat_pipeline_end_to_end():
    result = classify("/etc/passwd traversal attempt")
    assert result.label == "threat"
    assert result.escalate is False


def test_benign_pipeline_end_to_end():
    result = classify("DNS query for example.com")
    assert result.label == "benign"
    assert result.escalate is False
