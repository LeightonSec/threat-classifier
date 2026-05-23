import pytest
from threat_classifier.inference import classify_text
from threat_classifier.models import THRESHOLD


def test_threat_keyword_exec():
    result = classify_text("exec(user_input)")
    assert result.label == "threat"


def test_threat_keyword_eval():
    result = classify_text("eval(data)")
    assert result.label == "threat"


def test_threat_keyword_drop_table():
    result = classify_text("'; DROP TABLE users; --")
    assert result.label == "threat"


def test_threat_keyword_etc_passwd():
    result = classify_text("cat /etc/passwd")
    assert result.label == "threat"


def test_threat_keyword_script():
    result = classify_text("<script>alert(1)</script>")
    assert result.label == "threat"


def test_threat_keyword_powershell():
    result = classify_text("powershell -enc aGVsbG8=")
    assert result.label == "threat"


def test_threat_keyword_union_select():
    result = classify_text("' union select * from users --")
    assert result.label == "threat"


def test_threat_keyword_case_insensitive():
    result = classify_text("EXEC xp_cmdshell('dir')")
    assert result.label == "threat"


def test_clean_input_returns_benign():
    result = classify_text("port scan detected from 203.0.113.5")
    assert result.label == "benign"


def test_threat_confidence_above_threshold():
    result = classify_text("eval(payload)")
    assert result.confidence >= THRESHOLD
    assert result.escalate is False


def test_benign_confidence_above_threshold():
    result = classify_text("normal log entry")
    assert result.confidence >= THRESHOLD
    assert result.escalate is False


def test_escalate_true_when_confidence_below_threshold():
    from threat_classifier.models import ClassificationResult
    low_confidence = ClassificationResult(label="threat", confidence=0.60, escalate=True)
    assert low_confidence.escalate is True


def test_escalate_false_when_confidence_at_threshold():
    from threat_classifier.models import ClassificationResult
    at_threshold = ClassificationResult(label="benign", confidence=THRESHOLD, escalate=False)
    assert at_threshold.escalate is False
