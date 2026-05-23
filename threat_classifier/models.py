from dataclasses import dataclass

THRESHOLD = 0.85


@dataclass
class ClassificationResult:
    label: str        # "threat" or "benign"
    confidence: float  # 0.0–1.0
    escalate: bool    # True if confidence < THRESHOLD
