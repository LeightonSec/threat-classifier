from .inference import classify_text
from .models import ClassificationResult
from .normalise import normalise


def classify(text: str) -> ClassificationResult:
    return classify_text(normalise(text))
