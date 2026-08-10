# ML-Based Web Application Firewall

A machine learning-based Web Application Firewall (WAF) that scores incoming HTTP requests for malicious intent using a fine-tuned DistilBERT classifier, served via ONNX Runtime for low-latency inference.

Built as a semester project comparing a transformer-based detection approach against traditional signature-based WAFs (ModSecurity).

---

## Overview

Traditional WAFs rely on regex-based signature matching, which is fast but brittle — attackers can often bypass known signatures through encoding, padding, or minor payload variation. This project explores whether a fine-tuned language model can generalize better against payload obfuscation while remaining fast enough for inline request scoring.

The system takes a raw HTTP request (method, path, query, body, headers), normalizes it to defeat common obfuscation techniques, scores it using a sliding-window inference pass, and returns a malicious/benign classification with a confidence score.

---

## Architecture

```
HTTP Request
     │
     ▼
normalizer.py   — NFKC unicode normalization, double URL decode,
                   HTML entity decode, zero-width char strip,
                   SQL hex literal decode
     │
     ▼
scanner.py      — sliding-window tokenization (128 tokens, stride 64),
                   scores every window, returns max score
     │
     ▼
ONNX Runtime    — DistilBERT classifier, fine-tuned on DVWA traffic
     │
     ▼
FastAPI         — /score and /batch_score endpoints
     │
     ▼
Verdict: malicious | benign, with confidence score
```

---

## Model Performance

Trained on 15,791 labeled HTTP requests captured from DVWA (Damn Vulnerable Web Application) via a custom mitmproxy capture pipeline.

| Metric | Value |
|---|---|
| Training accuracy | 99.79% |
| Precision | 100% |
| False positive rate (training set) | 0% |
| Recall (held-out attack corpus, 44 payloads) | 84.09% (37/44) |
| PyTorch inference latency (avg) | 38.67ms |
| ONNX inference latency (avg) | **21.04ms** (45.6% reduction, no recall change) |

Evaluation corpus: 44 payloads (4 from sqlmap, 40 generated via Ollama/llama3.2 across varied SQL injection patterns).

### Known limitations

The model has a measurable blind spot for DDL/DCL SQL statement injection (`CREATE TABLE`, `INSERT INTO`, `GRANT`, `xp_cmdshell`, etc.) — 7 of 44 evaluation payloads are false negatives, all in this category. Two score near the 0.5 decision threshold (0.39–0.45), suggesting partial learned signal; five score near zero (0.0006–0.076), indicating the training corpus under-represents this attack class entirely.

Threshold tuning was evaluated as a mitigation: lowering the threshold from 0.5 to 0.3 only recovers recall to 88.64%, at the cost of increased false-positive risk on legitimate traffic (a bare `SELECT * FROM <table>` query already scores ~0.99 as a false positive at the default threshold). The threshold was kept at 0.5, and this gap is documented here rather than patched, since closing it properly requires expanding training data coverage for this attack category, not further threshold adjustment.

---

## Two Original Contributions

Beyond standard fine-tuning, this project implements two fixes not present in default transformer-based classifiers or in ModSecurity's default rule set:

**1. Multi-layer input normalization** (`proxy/normalizer.py`)
Five sequential transformations — Unicode NFKC normalization, double URL-decoding, HTML entity decoding, zero-width character stripping, and SQL hex literal decoding — applied before tokenization. This closes obfuscation techniques where a payload is encoded or visually disguised to defeat naive string matching while remaining functionally identical to the target system.

**2. Sliding-window inference** (`proxy/scanner.py`)
Rather than truncating long requests to the model's 128-token limit, the scanner tokenizes the full request and scores overlapping 128-token windows (stride 64), taking the maximum score across all windows. This closes a padding bypass: an attacker padding the start of a request with benign filler text can no longer push the actual payload outside the model's field of view.

---

## Tech Stack

- **Model:** DistilBERT (fine-tuned), served via ONNX Runtime
- **API:** FastAPI, Uvicorn
- **Training:** PyTorch, Hugging Face Transformers, `optimum-onnx` for export
- **Data capture:** mitmproxy (custom addon for DVWA traffic capture and labeling)
- **Containerization:** Docker, Docker Compose
- **Model hosting:** Hugging Face Hub (`Shade63/waf-onnx`)

---

## Project Structure

```
waf-project/
├── data/
│   ├── capture.py          # mitmproxy addon — captures DVWA traffic
│   ├── label.py             # merges captured traffic into labeled dataset.jsonl
│   ├── dataset.jsonl         # 15,791 labeled training examples
│   ├── traffic_legit.jsonl
│   └── traffic_attack.jsonl
├── proxy/
│   ├── model.py             # FastAPI app — /score, /batch_score, /health
│   ├── normalizer.py        # input normalization pipeline
│   ├── scanner.py           # sliding-window scoring logic
│   ├── corpus_loader.py
│   ├── evaluate_corpus.py   # runs eval corpus against the model
│   └── threshold_tuner.py   # threshold sensitivity analysis
├── dashboard/
│   └── index.html            # live scoring console (single request + batch)
├── results/                  # eval run CSVs, timestamped
├── tests/
│   └── test_corpus_integration.py
├── attack_corpus.txt         # evaluation payloads
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .gitignore
```

---

## Setup

### Local development

```bash
python -m venv env
env\Scripts\activate          # Windows
pip install -r requirements.txt

uvicorn proxy.model:app --reload
```

The server checks for `waf-distilbert-final/model.onnx` on startup. If present, it loads the ONNX runtime session; otherwise it falls back to PyTorch (slower, intended for development only — not used in the containerized deployment).

### Docker

```bash
docker-compose up --build
```

The Dockerfile downloads the ONNX model and tokenizer directly from Hugging Face Hub (`Shade63/waf-onnx`) at build time — no local model files are required to build the image.

### Verify it's running

```bash
curl http://localhost:8000/health
# {"status":"ok","onnx":true}
```

---

## API

### `POST /score`

Scores a single request.

**Request:**
```json
{
  "method": "POST",
  "path": "/login.php",
  "body": "username=admin' OR 1=1--",
  "query": "",
  "user_agent": "",
  "cookie": ""
}
```

**Response:**
```json
{
  "score": 0.9996,
  "label": "attack",
  "blocked": true,
  "windows": 1,
  "latency_ms": 22.46,
  "threshold": 0.5
}
```

### `POST /batch_score`

Scores up to 500 payloads in a single request.

**Request:**
```json
{
  "payloads": ["admin' OR 1=1--", "SELECT * FROM users"],
  "threshold": 0.5
}
```

**Response:**
```json
{
  "total": 2,
  "malicious_count": 2,
  "benign_count": 0,
  "threshold": 0.5,
  "results": [
    { "payload": "admin' OR 1=1--", "score": 0.9996, "label": "malicious", "latency_ms": 22.46 },
    { "payload": "SELECT * FROM users", "score": 0.9929, "label": "malicious", "latency_ms": 14.49 }
  ]
}
```

### `GET /health`

Returns service status and confirms whether the ONNX runtime is active.

---

## Dashboard

`dashboard/index.html` is a self-contained static page (no build step) for live manual testing against a running instance. Open it in a browser, point the API base URL field at your running server (defaults to `http://localhost:8000`), and use the Single Request or Batch Scan tabs to test payloads interactively.

---

## Data Sources & Attribution

Training data was collected via a controlled mitmproxy capture of traffic against DVWA (Damn Vulnerable Web Application), a deliberately vulnerable application designed for security testing and training. No traffic was captured from any system outside this controlled local environment. The evaluation corpus combines payloads generated by sqlmap (an open-source penetration testing tool) and payloads synthetically generated via a locally-run Ollama/llama3.2 instance.

---

## License

MIT License. See `LICENSE` for details.
