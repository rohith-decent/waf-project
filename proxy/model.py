import time
import torch
import onnxruntime as ort
from pathlib import Path
from pydantic import BaseModel
from fastapi import FastAPI
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from proxy.normalizer import normalize_request
from proxy.scanner import sliding_score

# ── Configuration ──────────────────────────────────────────────────
MODEL_DIR  = Path("waf-distilbert-final")
ONNX_PATH  = MODEL_DIR / "model.onnx"   # after Week 5 ONNX export
THRESHOLD  = 0.5

# ── Load once at startup — not per request ─────────────────────────
tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))

if ONNX_PATH.exists():
    session  = ort.InferenceSession(str(ONNX_PATH))
    pt_model = None
    print(f"[model] ONNX session loaded from {ONNX_PATH}")
else:
    pt_model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    pt_model.eval()
    session  = None
    print("[model] ONNX not found — using PyTorch (slower, dev only)")

# ── FastAPI app ─────────────────────────────────────────────────────
app = FastAPI(title="WAF Scoring Endpoint")

# ── Request schema — what Member A's proxy sends ────────────────────
class HTTPRequest(BaseModel):
    method:     str = "GET"
    path:       str = "/"
    query:      str = ""
    body:       str = ""
    user_agent: str = ""
    cookie:     str = ""

# ── Response schema ─────────────────────────────────────────────────
class ScoreResponse(BaseModel):
    score:      float
    label:      str
    blocked:    bool
    windows:    int
    latency_ms: float
    threshold:  float

# ── Health check ────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "onnx": session is not None}

# ── Main scoring endpoint ────────────────────────────────────────────
@app.post("/score", response_model=ScoreResponse)
def score(req: HTTPRequest):
    t0 = time.perf_counter()

    # Step 1 — normalize
    normalized = normalize_request(
        method=req.method,
        path=req.path,
        body=req.body,
        query=req.query,
        user_agent=req.user_agent,
        cookie=req.cookie
    )

    # Step 2 — sliding window scan
    scan_score, windows, blocked = sliding_score(
        normalized, tokenizer, session, threshold=THRESHOLD, pt_model=pt_model
    )

    latency_ms = (time.perf_counter() - t0) * 1000

    return ScoreResponse(
        score=round(scan_score, 4),
        label="attack" if blocked else "benign",
        blocked=blocked,
        windows=windows,
        latency_ms=round(latency_ms, 2),
        threshold=THRESHOLD
    )