# WAF Week 3 — The Two Fixes

## Context

The base model (DistilBERT fine-tuned on 15,791 HTTP requests, 99.79% accuracy) has two 
exploitable gaps at inference time. Both are bypasses that work not by fooling the model 
but by preventing the payload from ever reaching it in a recognizable form.

These two files close them.

---

## Fix 1 — Encoding Normalization (`proxy/normalizer.py`)

### The bypass

HTTP allows the same character to be represented multiple ways:

| Encoding | Representation | Decoded |
|---|---|---|
| Plain | `'` | `'` |
| URL encoded | `%27` | `'` |
| Double URL encoded | `%2527` | `'` |
| HTML entity | `&#x27;` | `'` |
| Unicode lookalike | `ʼ` (U+02BC) | `'` |
| Fullwidth | `＇` (U+FF07) | `'` |
| Zero-width injected | `UNI​ON` (U+200B inside) | `UNION` |

A model trained on decoded text has never seen `%2527 OR 1=1` during training.
It sees an unfamiliar token sequence and scores it low — the attack passes.

### The fix

Normalize every request through four steps in strict order before tokenization:
Order matters. NFKC runs first because some unicode characters have 
percent-encoded equivalents that only appear after compatibility mapping.

### Result
---

## Fix 2 — Sliding Window Scanner (`proxy/scanner.py`)

### The bypass

DistilBERT has a hard 512-token context limit. The WAF was using naive truncation:
```python
tokenizer(text, max_length=128, truncation=True)
```

This silently discards everything past token 128. An attacker can prepend enough 
benign content to push their payload beyond that cutoff:
### The proof

| | Score | Decision |
|---|---|---|
| Baseline (naive truncation) | 0.0000 | PASSED — vulnerable |
| Scanner (sliding window) | 0.9422 | BLOCKED — fixed |

The payload `' UNION SELECT username, password FROM users--` buried past token 128 
passes the naive baseline completely. The scanner catches it.

### The fix

Score the full request in overlapping 128-token windows, return the maximum:
Why max and not average? A 600-token padded request might have 9 benign windows 
scoring ~0.01 and 1 malicious window scoring 0.94. Average = 0.10 → passes. 
Max = 0.94 → blocked. For security, the most suspicious segment wins.

Short requests (<126 tokens) skip windowing entirely — no overhead for normal traffic.

---

## Pipeline order

Every request through the WAF runs in this exact order:
---

## Known limitations

- **Training distribution sensitivity** — the model was trained on DVWA traffic with 
  specific User-Agent strings. Requests with no UA or unfamiliar query formats may 
  score unexpectedly high. Fix: expand benign training data coverage.
- **ONNX not yet exported** — currently running PyTorch inference (~50-200ms/request). 
  ONNX export in Week 5 will bring this down to ~5-15ms.
- **No header inspection** — the normalizer and scanner operate on method, path, query, 
  body, UA, and cookie. Raw headers are not currently inspected.

---

## Test suite
