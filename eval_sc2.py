#!/usr/bin/env python3
"""
Evaluate false positive rate on security-adjacent benign samples.

Usage:
    python eval_sc2.py --data ../llm-redteam/output/payloads.jsonl

Exit code 1 if FP rate >= 5%.
"""
import argparse
import sys
from pathlib import Path

from threat_classifier.inference import classify_text
from train import _load_and_validate

SC2_VARIANTS = {
    "security_education",
    "security_research",
    "security_analysis",
    "security_defensive",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, type=Path)
    args = parser.parse_args()

    records = _load_and_validate(args.data)

    sc2 = [
        r for r in records
        if r["label"] == "benign" and r["variant"] in SC2_VARIANTS
    ]

    if not sc2:
        print("ERROR: no sub-category 2 records found — check --data path and variant field names")
        sys.exit(1)

    false_positives = []
    for r in sc2:
        result = classify_text(r["text"])
        if result.label == "threat":
            false_positives.append((r["variant"], r["text"], result.confidence))

    total = len(sc2)
    fp_count = len(false_positives)
    fp_rate = fp_count / total * 100

    print(f"Sub-category 2 samples : {total}")
    print(f"False positives        : {fp_count}")
    print(f"FP rate                : {fp_rate:.1f}%  (target: <5%)")
    print()

    if false_positives:
        print("False positive samples:")
        for variant, text, confidence in false_positives:
            print(f"  [{variant}] confidence={confidence:.3f}")
            print(f"    {text[:120]}")
    else:
        print("No false positives.")

    print()
    if fp_rate < 5.0:
        print("PASS")
    else:
        print("FAIL — benign corpus needs work")
        sys.exit(1)


if __name__ == "__main__":
    main()
