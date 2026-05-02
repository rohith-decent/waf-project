import csv
from pathlib import Path
from typing import List, Dict


def load_results(csv_path: str) -> List[Dict]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def recall_at_threshold(results: List[Dict], threshold: float) -> float:
    total = len(results)
    if total == 0:
        return 0.0
    detected = sum(1 for r in results if float(r["score"]) >= threshold)
    return detected / total


def score_distribution(results: List[Dict]) -> Dict:
    scores = [float(r["score"]) for r in results]
    return {
        "min":    min(scores),
        "max":    max(scores),
        "mean":   sum(scores) / len(scores),
        "below_0.3": sum(1 for s in scores if s < 0.3),
        "0.3_to_0.5": sum(1 for s in scores if 0.3 <= s < 0.5),
        "above_0.5": sum(1 for s in scores if s >= 0.5),
    }


def tuner_report(csv_path: str) -> None:
    results = load_results(csv_path)
    dist = score_distribution(results)

    print("\n========== SCORE DISTRIBUTION ==========")
    print(f"  Min score    : {dist['min']:.4f}")
    print(f"  Max score    : {dist['max']:.4f}")
    print(f"  Mean score   : {dist['mean']:.4f}")
    print(f"  Below 0.3    : {dist['below_0.3']} payloads  ← model missed badly")
    print(f"  0.3 → 0.5   : {dist['0.3_to_0.5']} payloads  ← borderline")
    print(f"  Above 0.5    : {dist['above_0.5']} payloads  ← detected")

    print("\n========== RECALL VS THRESHOLD =========")
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    for t in thresholds:
        recall = recall_at_threshold(results, t)
        bar = "█" * int(recall * 30)
        print(f"  t={t:.1f}  recall={recall * 100:6.2f}%  {bar}")
    print()

    # Flag payloads with suspiciously low scores for manual review
    low_score = [r for r in results if float(r["score"]) < 0.3]
    if low_score:
        print("[!] Payloads scoring below 0.3 — review these:")
        for r in low_score:
            print(f"    source={r['source']:10s} score={float(r['score']):.4f}  {r['raw_payload'][:60]}")


import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Find latest CSV in results/
        result_files = sorted(Path("results").glob("corpus_eval_*.csv"))
        if not result_files:
            print("No results CSV found. Run evaluate_corpus.py first.")
            sys.exit(1)
        csv_path = str(result_files[-1])    # latest run
    else:
        csv_path = sys.argv[1]

    print(f"[*] Analyzing: {csv_path}")
    tuner_report(csv_path)