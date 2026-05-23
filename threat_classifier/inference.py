from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from .models import THRESHOLD, ClassificationResult
from .normalise import normalise

_LABEL_MAP = {0: "benign", 1: "threat"}


def _model_path() -> Path:
    raw = os.environ.get("MODEL_PATH")
    if not raw:
        raise KeyError(
            "MODEL_PATH environment variable is not set. "
            "Run train.py to produce a model, then set MODEL_PATH to the output directory."
        )
    return Path(raw)


@lru_cache(maxsize=1)
def _load_components() -> tuple:
    """Load tokenizer and model once, cache for the process lifetime."""
    try:
        from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast
    except ImportError as exc:
        raise ImportError(
            "transformers is not installed. Install with: pip install -r requirements-train.txt"
        ) from exc

    path = _model_path()
    tokenizer = DistilBertTokenizerFast.from_pretrained(str(path))
    model = DistilBertForSequenceClassification.from_pretrained(str(path))
    model.eval()
    return tokenizer, model


def _predict(tokenizer, model, text: str) -> tuple[str, float]:
    """Run model forward pass. Returns (label, confidence). Internal — do not call directly."""
    import torch

    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0]
    predicted_id = int(torch.argmax(probs))
    return _LABEL_MAP[predicted_id], float(probs[predicted_id])


def classify_text(text: str) -> ClassificationResult:
    tokenizer, model = _load_components()
    normalised = normalise(text)
    label, confidence = _predict(tokenizer, model, normalised)
    return ClassificationResult(
        label=label,
        confidence=confidence,
        escalate=confidence < THRESHOLD,
    )
