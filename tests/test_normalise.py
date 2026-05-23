from threat_classifier.normalise import normalise


def test_passthrough_clean_string():
    assert normalise("hello world") == "hello world"


def test_empty_string():
    assert normalise("") == ""


def test_nfkc_normalisation():
    # Fullwidth ASCII → standard ASCII
    assert normalise("ｈｅｌｌｏ") == "hello"


def test_homoglyph_normalisation():
    # Superscript digits → standard digits via NFKC
    assert normalise("x²") == "x2"


def test_strips_zero_width_space():
    assert normalise("hel​lo") == "hello"


def test_strips_zero_width_non_joiner():
    assert normalise("hel‌lo") == "hello"


def test_strips_zero_width_joiner():
    assert normalise("hel‍lo") == "hello"


def test_strips_bom():
    assert normalise("﻿hello") == "hello"


def test_strips_soft_hyphen():
    assert normalise("hel­lo") == "hello"


def test_strips_word_joiner():
    assert normalise("hel⁠lo") == "hello"


def test_strips_multiple_zero_width():
    assert normalise("a​‌‍b") == "ab"


def test_preserves_legitimate_unicode():
    # Non-ASCII legitimate characters should survive
    assert normalise("résumé") == "résumé"
