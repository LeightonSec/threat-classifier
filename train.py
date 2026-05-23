"""
Phase 2 training script — fine-tunes DistilBERT on llm-redteam JSONL output.

Usage:
    python train.py --data path/to/payloads.jsonl --output /path/to/model/dir

Requirements (install separately — see requirements-train.txt):
    torch, transformers, datasets, scikit-learn

The --data file must be llm-redteam JSONL output with schema_version=1.0.
Validation fails loudly if the file contains records from any other source.

Model weights are saved to --output, which should be the value you set for MODEL_PATH
when running inference. Never commit the --output directory to the public repo.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

DISTILBERT_MODEL_ID = "distilbert-base-uncased"
DISTILBERT_REVISION = "12040accade4e8a0f71eabdb258fecc2e7e948be"  # pinned — 2024-04 checkpoint

SCHEMA_VERSION = "1.0"
VALID_LABELS = {"threat", "benign"}
LABEL2ID = {"benign": 0, "threat": 1}
ID2LABEL = {0: "benign", 1: "threat"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _load_and_validate(data_path: Path) -> list[dict]:
    """Load JSONL, validate schema contract. Raises ValueError on any violation."""
    records = []
    errors = []
    for i, line in enumerate(data_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"  line {i}: JSON parse error — {e}")
            continue

        if d.get("schema_version") != SCHEMA_VERSION:
            errors.append(
                f"  line {i}: schema_version mismatch — expected {SCHEMA_VERSION!r}, "
                f"got {d.get('schema_version')!r}. This file was not produced by llm-redteam."
            )
        if d.get("label") not in VALID_LABELS:
            errors.append(f"  line {i}: invalid label {d.get('label')!r} — must be one of {VALID_LABELS}")
        if not d.get("text", "").strip():
            errors.append(f"  line {i}: empty text field")

        records.append(d)

    if errors:
        print("Validation failed — dataset does not meet schema contract:", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        raise ValueError(f"{len(errors)} validation error(s) in {data_path}")

    label_counts = {}
    for r in records:
        label_counts[r["label"]] = label_counts.get(r["label"], 0) + 1
    print(f"Loaded {len(records)} records: {label_counts}")

    return records


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(data_path: Path, output_path: Path, val_split: float) -> None:
    # Imports deferred — not available in the inference environment
    try:
        import torch
        from datasets import Dataset
        from sklearn.model_selection import train_test_split
        from transformers import (
            DistilBertForSequenceClassification,
            DistilBertTokenizerFast,
            Trainer,
            TrainingArguments,
        )
    except ImportError as e:
        print(f"Missing training dependency: {e}", file=sys.stderr)
        print("Install with: pip install -r requirements-train.txt", file=sys.stderr)
        sys.exit(1)

    from threat_classifier.normalise import normalise

    records = _load_and_validate(data_path)

    texts = [normalise(r["text"]) for r in records]
    labels = [LABEL2ID[r["label"]] for r in records]

    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=val_split, stratify=labels, random_state=42
    )
    print(f"Split: {len(train_texts)} train / {len(val_texts)} val (stratified)")

    tokenizer = DistilBertTokenizerFast.from_pretrained(
        DISTILBERT_MODEL_ID,
        revision=DISTILBERT_REVISION,
    )

    def tokenize(text_list: list[str]) -> dict:
        return tokenizer(text_list, truncation=True, padding=True, max_length=128)

    train_dataset = Dataset.from_dict({
        **tokenize(train_texts),
        "labels": train_labels,
    })
    val_dataset = Dataset.from_dict({
        **tokenize(val_texts),
        "labels": val_labels,
    })

    model = DistilBertForSequenceClassification.from_pretrained(
        DISTILBERT_MODEL_ID,
        revision=DISTILBERT_REVISION,
        num_labels=2,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    training_args = TrainingArguments(
        output_dir=str(output_path / "checkpoints"),
        num_train_epochs=3,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=32,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=10,
        seed=42,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
    )

    trainer.train()

    output_path.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(output_path))
    tokenizer.save_pretrained(str(output_path))
    print(f"Model saved to {output_path}")
    print(f"Set MODEL_PATH={output_path} before running inference.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fine-tune DistilBERT on llm-redteam JSONL output for threat classification.",
        epilog="Model weights are saved to --output. Set MODEL_PATH to that path for inference.",
    )
    parser.add_argument(
        "--data", required=True, metavar="FILE",
        help="Path to llm-redteam JSONL output (schema_version=1.0 required)",
    )
    parser.add_argument(
        "--output", required=True, metavar="DIR",
        help="Directory to save fine-tuned model weights (set as MODEL_PATH for inference)",
    )
    parser.add_argument(
        "--val-split", type=float, default=0.15, metavar="FLOAT",
        help="Fraction of data held out for validation (default: 0.15)",
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        parser.error(f"--data path does not exist: {data_path}")
    if not data_path.suffix == ".jsonl":
        parser.error(f"--data must be a .jsonl file, got: {data_path}")

    output_path = Path(args.output)
    if output_path.exists() and any(output_path.iterdir()):
        print(f"Warning: --output directory {output_path} is not empty. Weights will be overwritten.")

    train(data_path, output_path, args.val_split)


if __name__ == "__main__":
    main()
