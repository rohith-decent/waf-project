"""
label.py — merges traffic_legit.jsonl and traffic_attack.jsonl into
a single shuffled dataset.jsonl with consistent label fields.

Usage:
    python data/label.py
"""

import json
import random
import pathlib
from collections import Counter

DATA_DIR   = pathlib.Path("data")
LEGIT_FILE = DATA_DIR / "traffic_legit.jsonl"
ATTACK_FILE= DATA_DIR / "traffic_attack.jsonl"
OUTPUT     = DATA_DIR / "dataset.jsonl"

def load_jsonl(filepath):
    """Read a .jsonl file and return a list of dicts. Skip malformed lines."""
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  Warning: skipping malformed line {line_num} in {filepath}: {e}")
    return records

def normalise(record, label):
    """
    Ensure every record has the same keys regardless of which file it came from.
    """
    return {
        "label":     label,
        "method":    record.get("method", "GET"),
        "host":      record.get("host", ""),
        "path":      record.get("path", "/"),
        "query":     json.dumps(record.get("query", {})),    # flatten dict to string
        "body":      record.get("body", ""),
        "user_agent":record.get("headers", {}).get("user-agent", ""),
        "cookie":    record.get("headers", {}).get("cookie", ""),
    }

def main():
    print("Loading legit traffic...")
    legit   = load_jsonl(LEGIT_FILE)
    print(f"  {len(legit)} rows loaded")

    print("Loading attack traffic...")
    attacks = load_jsonl(ATTACK_FILE)
    print(f"  {len(attacks)} rows loaded")

    # Apply labels and normalise schema
    dataset = (
        [normalise(r, label=0) for r in legit] +
        [normalise(r, label=1) for r in attacks]
    )

    # Shuffle so legit and attack rows are interleaved
    random.seed(42)     # fixed seed = reproducible shuffle
    random.shuffle(dataset)

    # Write output
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for record in dataset:
            f.write(json.dumps(record) + "\n")

    # Summary
    labels = Counter(r["label"] for r in dataset)
    print(f"\nDataset written to {OUTPUT}")
    print(f"  Total rows : {len(dataset):,}")
    print(f"  Label 0 (legit)  : {labels[0]:,}  ({labels[0]/len(dataset)*100:.1f}%)")
    print(f"  Label 1 (attack) : {labels[1]:,}  ({labels[1]/len(dataset)*100:.1f}%)")
    print("\nSample record:")
    print(json.dumps(dataset[0], indent=2))

if __name__ == "__main__":
    main()