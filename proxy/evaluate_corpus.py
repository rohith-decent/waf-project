import csv
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from proxy.corpus_loader import load_corpus, corpus_summary
# RIGHT — match model.py's actual imports
from proxy.normalizer import normalize_request
from proxy.scanner import sliding_score
from proxy.model import tokenizer, session, pt_model

# Threshold for classifying as malicious.
# 0.5 is the default — Section 04 (threshold_tuner.py) will tell you
# if this should be raised or lowered based on score distribution.
DEFAULT_THRESHOLD: float = 0.5

OUTPUT_DIR = Path("results")
OUTPUT_DIR.mkdir(exist_ok=True)


def evaluate(
    corpus_path: str = "attack_corpus.txt",
    threshold: float = DEFAULT_THRESHOLD,
) -> List[Dict[str, Any]]:
    """
    Run each corpus payload through normalizer → scanner.
    Returns list of result dicts.
    """
    entries = load_corpus(corpus_path)
    print(f"\n[*] Loaded corpus: {len(entries)} payloads")
    for src, count in corpus_summary(entries).items():
        print(f"    {src:12s}: {count}")
    print()

    results = []
    fn_count = 0    # false negatives

    for i, entry in enumerate(entries):
        raw     = entry["payload"]
        source  = entry["source"]

        # Step 1: Normalize (Fix 1)
        normalized = normalize_request(method="GET", path="/", body=raw, query="", user_agent="", cookie="")

        # Step 2: Scan with sliding window (Fix 2)
        # scanner.scan() returns the MAX score across all windows.
        t0 = time.perf_counter()
        scan_score, windows, blocked = sliding_score(normalized, tokenizer, session, threshold=0.5, pt_model=pt_model)
        latency_ms = (time.perf_counter() - t0) * 1000

        predicted = 1 if scan_score >= threshold else 0
        is_fn = (predicted == 0)   # all entries are attacks, so FN = missed

        if is_fn:
            fn_count += 1
            print(f"[FN] {source:10s} score={scan_score:.4f}  {raw[:60]}")

        results.append({
            "id":           i,
            "source":       source,
            "raw_payload":  raw,
            "normalized":   normalized,
            "score":        round(scan_score, 6),
            "predicted":    predicted,
            "true_label":   1,      # corpus is attack-only
            "false_negative": is_fn,
            "latency_ms":   round(latency_ms, 2),
        })

    return results, fn_count


def write_csv(results: List[Dict[str, Any]], path: Path) -> None:
    if not results:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)


def print_summary(results: List[Dict[str, Any]], fn_count: int, threshold: float) -> None:
    total = len(results)
    detected = total - fn_count
    recall = detected / total if total > 0 else 0
    avg_lat = sum(r["latency_ms"] for r in results) / total

    print("\n========== EVALUATION SUMMARY ==========")
    print(f"Threshold       : {threshold}")
    print(f"Total payloads  : {total}")
    print(f"Detected        : {detected}")
    print(f"False Negatives : {fn_count}")
    print(f"Recall          : {recall * 100:.2f}%")
    print(f"Avg Latency     : {avg_lat:.2f} ms")
    print("========================================\n")


if __name__ == "__main__":
    results, fn_count = evaluate()
    print_summary(results, fn_count, DEFAULT_THRESHOLD)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUTPUT_DIR / f"corpus_eval_{timestamp}.csv"
    write_csv(results, out_path)
    print(f"[*] Results written to: {out_path}")