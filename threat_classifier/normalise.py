import unicodedata

# Zero-width and invisible characters that could be used for token manipulation
_ZERO_WIDTH = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "﻿",  # zero-width no-break space (BOM)
    "­",  # soft hyphen
    "⁠",  # word joiner
}


def normalise(text: str) -> str:
    """Apply NFKC unicode normalisation and strip zero-width characters."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if ch not in _ZERO_WIDTH)
