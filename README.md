# threat-classifier

SOC triage classifier — binary threat/benign classification pipeline for attacker-influenced signals.

## What it does

Takes input strings from SOC signal sources (IDS alerts, firewall detections, honeypot captures, PCAP metadata), applies input hardening, and classifies each as `threat` or `benign`. Returns a confidence score and an escalation flag.

Predictions with confidence below 0.85 set `escalate=True` — these route to analyst review rather than auto-triage. The classifier answers one question: *is this a threat?* Severity scoring is handled downstream.

Input hardening runs before every classification:
- NFKC unicode normalisation — collapses homoglyphs and fullwidth variants to standard ASCII equivalents
- Zero-width character stripping — removes U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060

These defences address token manipulation attacks described in the Gate 3 adversarial ML assessment.

## Architecture

```
threat_classifier/
    models.py      # ClassificationResult dataclass — label, confidence, escalate
    normalise.py   # NFKC normalisation + zero-width strip
    inference.py   # classifier — stub (Phase 1), DistilBERT (Phase 2)
    __init__.py    # public API: classify()
cli.py             # thin typer CLI for testing
```

The public interface is a single function. Downstream consumers (unified-dashboard, incident-tracker) import the library directly — no HTTP server, no auth layer, no additional trust boundary. The CLI exists for manual testing and is not the intended production interface.

## Usage

**Library:**

```python
from threat_classifier import classify

result = classify("exec(user_input)")
print(result.label)      # "threat"
print(result.confidence) # 0.91
print(result.escalate)   # False
```

`ClassificationResult` fields:

| Field | Type | Description |
|---|---|---|
| `label` | `str` | `"threat"` or `"benign"` |
| `confidence` | `float` | 0.0–1.0 |
| `escalate` | `bool` | `True` if confidence < 0.85 |

**CLI:**

```
python cli.py "suspicious input text"
```

```
label:      threat
confidence: 0.91
escalate:   False
```

## Gate docs

Trust boundary mapping and adversarial ML assessment were completed before any implementation code was written.

- [GATE_2_TRUST_BOUNDARIES.md](GATE_2_TRUST_BOUNDARIES.md) — five data flows defined and justified, pre-existing violations documented, AbuseIPDB risk accepted
- [GATE_3_ADVERSARIAL_ML.md](GATE_3_ADVERSARIAL_ML.md) — model selection, label set, four evasion vectors enumerated, mitigations and residual risk documented

## Current state

**Phase 1 — complete.** Inference pipeline wired with a keyword-heuristic stub classifier. All normalisation and thresholding logic is in place and tested. 31 tests, 100% coverage.

**Phase 2 — blocked on Gate 4.** The stub in `inference.py` is replaced by a fine-tuned DistilBERT model trained on security labels. Phase 2 is blocked on two Gate 4 pre-conditions: the llm-redteam payload decision (whether real attack payloads can be used as training data) and confirmation that the TC → Anthropic API payload contains classifier output only.

## Security notes

Raw input never leaves the trust boundary. Only classifier output — label and confidence score — is forwarded to downstream APIs. This is enforced by architecture: the DistilBERT classifier produces scores and labels, not text.

Input normalisation runs before classification on every call. It is not optional and cannot be bypassed through the public `classify()` API.

Model weights (Phase 2) will not be committed to this repository. See Gate 3 sign-off conditions.
