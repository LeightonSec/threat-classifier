import re

from .models import THRESHOLD, ClassificationResult

# STUB — replace with fine-tuned DistilBERT in Phase 2
_THREAT_KEYWORDS = re.compile(
    r"exec|eval|drop\s+table|/etc/passwd|<script|cmd\.exe|powershell|base64|union\s+select",
    re.IGNORECASE,
)

_CONFIDENCE_THREAT = 0.91
_CONFIDENCE_BENIGN = 0.95


def classify_text(text: str) -> ClassificationResult:
    # STUB — replace with fine-tuned DistilBERT in Phase 2
    if _THREAT_KEYWORDS.search(text):
        label, confidence = "threat", _CONFIDENCE_THREAT
    else:
        label, confidence = "benign", _CONFIDENCE_BENIGN
    return ClassificationResult(
        label=label,
        confidence=confidence,
        escalate=confidence < THRESHOLD,
    )
