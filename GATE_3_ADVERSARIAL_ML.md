# Gate 3 — Adversarial ML Robustness Assessment
**Project:** threat-classifier  
**Status:** Complete — pending merge  
**Date:** 2026-05-23  
**Scope:** Model selection, label set, adversarial ML threat model, evasion attack surface, mitigations, honeypot.db retention policy, and TC → Anthropic API payload enforcement checkpoint.

---

## Gate 3 Inputs (all confirmed — do not re-open)

| Decision | Outcome |
|---|---|
| Model | DistilBERT fine-tuned on security labels |
| Label set | Binary: `threat` / `benign` |
| Retention window | 90 days (`honeypot.db`) |

---

## 1. Model Selection Rationale

**Selected model:** DistilBERT fine-tuned on security labels.

DistilBERT is selected over Mistral 7B or other instruction-tuned LLMs for three reasons that directly follow from Gate 2 architectural decisions:

**Boundary cleanliness.** The Gate 2 design requirement for the TC → Anthropic API flow is "classifier output only — scores and labels, not raw input." A fine-tuned DistilBERT produces a binary label and a confidence score by architecture — it cannot produce freeform text. This enforces the trust boundary structurally rather than requiring a sanitisation layer. A Mistral 7B produces text; enforcing the boundary would require an additional component with its own failure modes.

**Evasion surface enumerability.** A narrow classification head on a fixed two-class label set has a defined decision boundary that can be assessed at Gate 3. A 7B instruction-tuned model's decision space is too broad to assess without red-teaming infrastructure that does not exist at this stage.

**Operational feasibility.** DistilBERT runs on CPU without quantisation. Mistral 7B requires GPU or significant quantisation effort before it is viable in the target environment.

**Fallback:** RoBERTa if imbalanced class performance (high false-negative rate on minority threat class) becomes an issue during training. Same architectural properties apply.

---

## 2. Label Set Decision and Rationale

**Label set:** Binary — `threat` / `benign`.

TC answers one question: *is this a threat?* Severity scoring is a separate, downstream decision answered by the Anthropic API call on clean classifier output. Conflating these two decisions in the classifier would require a multi-class severity label set, which introduces three problems:

1. **Training data requirements multiply** — five severity classes require labelled examples across each class, with sufficient volume to avoid class imbalance driving the classifier toward majority-class predictions.
2. **Evasion surface widens** — a multi-class model exposes label demotion as an attack vector (critical → medium is not full evasion but significantly degrades analyst prioritisation).
3. **Boundary assessment at Gate 3 becomes impractical** — each additional class adds decision boundaries to enumerate.

Binary classification defers severity to a component (Anthropic API) that is better suited to nuanced judgement and does not require ML training data. The separation is architecturally clean and operationally correct.

---

## 3. Adversarial ML Threat Model

### Attacker goal

An adversary who knows or suspects their activity is being processed by a classifier has one objective: cause attacker-controlled content to be classified as `benign` rather than `threat`. A successful evasion means the signal does not reach SOC analyst review and the attack proceeds without detection.

### Threat actors with motivation to evade

| Signal source | Evasion motivation | Feasibility |
|---|---|---|
| `llm-honeypot` | Attacker knows their prompts are being captured and classified | HIGH — attacker is interacting with the system directly |
| `ai-firewall` | Attacker crafting prompts to bypass firewall detection | HIGH — evasion is already the attacker's stated goal |
| `llm-redteam` | Red team payloads engineered to evade detection | HIGH — by design |
| `pcap-analyser` | Network traffic manipulation to avoid classification | MEDIUM — requires knowing TC is downstream of pcap analysis |
| `intel-pipeline` | Public news summaries | LOW — attacker cannot control public reporting |

### What evasion achieves

A successfully evaded signal is classified `benign` and either suppressed or deprioritised. Depending on how TC output is consumed:
- If confidence thresholding is applied, near-boundary predictions escalate to review — evasion to boundary region is partial but not complete.
- If TC output gates automated triage, full evasion (high-confidence `benign`) suppresses the signal entirely.
- Label demotion is not applicable with a binary label set — the attacker must reach `benign`, not merely a lower severity tier.

---

## 4. Evasion Attack Surface

### 4.1 Token manipulation

DistilBERT uses a WordPiece tokenizer. Attacks that exploit token boundary behaviour:

- **Homoglyphs and unicode confusables:** replacing ASCII characters with visually identical unicode equivalents (e.g., Cyrillic `а` for Latin `a`) shifts token boundaries without changing human-readable meaning. The model produces a different embedding; the payload may evade a classifier trained on ASCII attack strings.
- **Whitespace injection:** inserting spaces within keywords (`p a s s w o r d`, `s c r i p t`) splits tokens differently. Effective against classifiers trained on un-normalised input.
- **Zero-width characters:** zero-width joiners, non-breaking spaces, and directional marks are invisible to human reviewers but present in the token stream.

**Mitigation path:** normalise unicode (NFKC normalisation) and strip zero-width characters before classification. Reduces but does not eliminate this surface.

### 4.2 Semantic-preserving perturbations

Attacks that preserve attacker intent while shifting the model's token distribution:

- **Synonym substitution:** replace attack-indicator keywords with synonyms or code equivalents. Effective against models with limited training vocabulary coverage.
- **Context injection:** prepend benign-looking preamble to malicious content. The [CLS] token embedding aggregates across the full input; a long benign preamble can shift the aggregate toward `benign` without removing the malicious payload.
- **Paraphrasing:** rephrase attack instructions in indirect or passive constructions. Reduces overlap with training examples that use direct imperative phrasing.

**Mitigation path:** training data diversity — include paraphrased and obfuscated variants of attack strings. Reduces but does not eliminate this surface. Fundamental limitation: semantic-preserving adversarial examples against transformer classifiers remain effective even with diverse training data.

### 4.3 Black-box probing

An attacker without model access can probe the classifier by submitting variants of their payload and observing classification outcomes. Over many probes, the decision boundary can be inferred.

**Conditions for feasibility:** TC must return classifier output (confidence scores) to the attacker, or the attacker must be able to observe downstream effects of classification (e.g., whether an alert was raised).

**Mitigation path:** do not expose raw confidence scores outside the operator's system. Confidence scores passed to the Anthropic API (Section 7) are an internal flow — Anthropic is a trusted processor, not an external observer the attacker can query. The constraint is that confidence scores must not be returned to callers outside the operator's control boundary (e.g., via a public API response or dashboard visible to unauthenticated users). If TC output is consumed internally only, black-box probing requires out-of-band observation of SOC activity — much higher operational cost for the attacker.

### 4.4 White-box attacks

If model weights are accessible (e.g., committed to a public repository), gradient-based attacks (FGSM, PGD against the embedding layer) can construct near-optimal adversarial inputs efficiently.

**Current risk level:** LOW — model weights are not yet trained or deployed. Risk becomes MEDIUM at Phase 3 if the fine-tuned model is committed to the public threat-classifier repo without access controls.

**Gate 4 checkpoint:** fine-tuned model weights must not be committed to the public repo. Store separately (private repo, object storage, or local only).

### 4.5 Training data poisoning

If llm-redteam payloads are used as positive (`threat`) training examples, an attacker who knows which payloads are in the training set can craft new payloads that are out-of-distribution with respect to the training distribution — the classifier has not seen them and may produce uncertain or incorrect predictions.

**Status:** deferred to Gate 4. The llm-redteam payload decision (whether real attack payloads can be used as training fixtures) has not been made. TC must not ingest llm-redteam data for training until Gate 4 sign-off.

---

## 5. Mitigations and Residual Risk

| Mitigation | Attack surface addressed | Implementation phase |
|---|---|---|
| Unicode NFKC normalisation + zero-width character stripping before classification | Token manipulation (4.1) | Phase 1 (pre-training) |
| Training data includes obfuscated/paraphrased variants | Semantic perturbations (4.2) | Phase 2 (training) |
| Confidence thresholding — predictions below 0.85 escalate to review, not auto-triage | All evasion vectors (reduces impact) | Phase 1 (inference pipeline) |
| Do not expose raw confidence scores externally | Black-box probing (4.3) | Phase 1 (API design) |
| Model weights stored outside public repo | White-box attacks (4.4) | Gate 4 checkpoint |
| llm-redteam payload decision before training | Training data poisoning (4.5) | Gate 4 pre-condition |

**Residual risk after mitigations:**

Semantic-preserving adversarial examples against DistilBERT cannot be fully mitigated with static defences. A sufficiently motivated attacker with sustained access to observable classification outcomes can iteratively craft inputs that evade the classifier. This is a fundamental property of neural text classifiers — acknowledged, not solved. Operational mitigation: treat classifier output as a triage signal, not a final verdict. Analyst review remains in the loop.

---

## 6. honeypot.db Retention Policy

**Decision:** 90-day retention window.

**Rationale:** 90 days provides sufficient data volume for classifier training and maintains a meaningful signal history for campaign detection. Starting longer (180 days) has no regulatory floor to justify the increased data-at-risk period. The window can be extended with evidence of training data insufficiency; starting short and extending is operationally easier than justifying retroactive purges.

**Policy:**
- All rows older than 90 days from insertion timestamp are eligible for purge.
- Purge runs on a scheduled basis (implementation TBD — Phase 2, pre-volume-ingestion).
- No TC ingestion of honeypot signals at volume until purge mechanism is implemented and verified.
- Purge must operate on non-comment code — a TTL comment in the schema does not satisfy this condition (see security-gate retention scanner logic).

**Purge mechanism options (Phase 2 decision):**
- Scheduled `DELETE WHERE timestamp < datetime('now', '-90 days')` on the SQLite db
- Row-level TTL if migrating to a database that supports it
- Archival to cold storage rather than deletion — requires separate data classification decision

---

## 7. TC → Anthropic API Payload Enforcement

Carried from Gate 2 (Flow 2 sign-off condition).

The PR that introduces the Anthropic API call in threat-classifier must include a code review checkpoint confirming that the `content`/`messages` payload contains only classifier output — specifically: the binary label (`threat` or `benign`) and confidence score. It must not contain:

- Raw alert text
- Attacker-supplied strings from any signal source
- Verbatim content from llm-honeypot, ai-firewall, or llm-redteam
- Any field that has not passed through the DistilBERT classifier first

This is a **Gate 4 PR review checkpoint** — it cannot be verified until the API call exists. Documented here as a carry-forward obligation so it is not lost between gates.

---

## Sign-off Conditions

| Condition | Status |
|---|---|
| Model selected: DistilBERT fine-tuned on security labels | ✅ |
| Label set defined: binary `threat` / `benign` | ✅ |
| Retention window set: 90 days (`honeypot.db`) | ✅ |
| Adversarial ML threat model documented | ✅ |
| Evasion attack surface enumerated (4 vectors) | ✅ |
| Mitigations documented with residual risk acknowledged | ✅ |
| honeypot.db purge mechanism implemented and verified | ☐ Phase 2 pre-condition |
| Model weights stored outside public repo | ☐ Gate 4 checkpoint |
| llm-redteam payload decision made before training | ☐ Gate 4 pre-condition |
| TC → Anthropic API payload confirmed at PR review | ☐ Gate 4 checkpoint |
| Gate 3 doc merged to threat-classifier repo | ☐ Pending |
