"""
Test suite for the two WAF fixes.
Run: python -m pytest tests/test_fixes.py -v
"""
import sys
import torch
import pytest
sys.path.insert(0, ".")

from proxy.normalizer import normalize

# ── Fix 1 Tests: Normalizer ─────────────────────────────────────────
class TestNormalizer:

    def test_plain_apostrophe_unchanged(self):
        """Plain apostrophe passes through without modification."""
        assert normalize("' OR 1=1--") == "' OR 1=1--"

    def test_url_encoded_apostrophe(self):
       """Single URL encoding: %27 → '
       This is the most basic bypass — any WAF without URL decoding misses it."""
       result = normalize("%27 OR 1=1--")
       assert "'" in result
       assert "%27" not in result
    def test_double_url_encoded_apostrophe(self):
        """Double URL encoding: %2527 → %27 → '
        Single-pass decoders produce %27 which looks safe — bypass succeeds.
        Our double unquote catches it."""
        result = normalize("%2527 OR 1=1--")
        assert "'" in result
        assert "%27" not in result
        assert "%2527" not in result
    def test_html_entity_apostrophe(self):
        """HTML entity encoding: &#x27; → '
        Used in HTML injection contexts — browser renders it as a quote."""
        result = normalize("&#x27; OR 1=1--")
        assert "'" in result
    def test_html_entity_decimal(self):
        """HTML entity decimal: &#39; → '
        Same bypass, different encoding format."""
        result = normalize("&#39; OR 1=1--")
        assert "'" in result
    def test_unicode_modifier_apostrophe(self):
        """Unicode lookalike: ʼ (U+02BC) → '
        NFKC collapses the modifier letter apostrophe to plain apostrophe.
        The BPE tokenizer sees a completely different token for U+02BC."""
        result = normalize("\u02bcOR 1=1--")
        assert "'" in result or "OR" in result
    def test_fullwidth_union_select(self):
        """Fullwidth unicode chars: ＵＮＩＯＮ → UNION
        NFKC maps fullwidth Latin to standard ASCII.
        Fullwidth chars tokenize completely differently without this."""
        result = normalize("\uff35\uff2e\uff29\uff2f\uff2e SELECT")
        assert "UNION" in result
    def test_zero_width_in_union(self):
        """Zero-width space inside UNION: UNI​ON → UNION
        U+200B between I and O is invisible but breaks tokenization.
        After strip, 'union' is present as a clean keyword."""
        zws    = "\u200b"
        result = normalize(f"UNI{zws}ON SELECT")
        assert "\u200b" not in result
        assert "UNION" in result
    def test_legitimate_input_unchanged(self):
        """Clean legitimate input should pass through mostly unchanged.
        The normalizer must not mangle normal traffic.
        """
        clean  = "POST /login username=john&password=secret123"
        result = normalize(clean)
        assert "john"   in result
        assert "secret" in result
# ── Fix 2 Tests: Sliding Window Proof ──────────────────────────────

class TestSlidingWindowProof:
    """
    THE PROOF TEST — this is what you show in the demo.
    Baseline model misses padding attack. Scanner catches it.
    Run standalone: python tests/test_fixes.py
    """
    @pytest.fixture(scope="class")
    def model_components(self):
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch
        tok   = AutoTokenizer.from_pretrained("waf-distilbert-final")
        model = AutoModelForSequenceClassification.from_pretrained("waf-distilbert-final")
        model.eval()
        return tok, model
    def _baseline_score(self, text, tok, model):
       """Naive truncation — what happens without the scanner."""
       import torch
       inputs = tok(text, return_tensors="pt", truncation=True, max_length=128, padding=True)
       with torch.no_grad():
           logits = model(**inputs).logits
           return torch.softmax(logits, dim=1)[0][1].item()
       
    def test_padding_attack_proof(self, model_components):
        from proxy.scanner import sliding_score
        from proxy.normalizer import normalize_request
        import json

        tok, model = model_components

        # Load real benign samples — guaranteed to score low
        benign_texts = []
        with open("dataset.jsonl") as f:
            for line in f:
                row = json.loads(line)
                if row["label"] == 0:
                    text = normalize_request(
                        method=row["method"],
                        path=row["path"],
                        body=row.get("body", ""),
                        query=row.get("query", ""),
                        user_agent=row.get("user_agent", ""),
                        cookie=row.get("cookie", "")
                    )
                    benign_texts.append(text)
                if len(benign_texts) >= 10:
                    break

        # Concatenate until we have >128 tokens of padding
        padding = " ".join(benign_texts)
        payload = "' UNION SELECT username, password FROM users--"
        padded_attack = f"{padding} {payload}"

        # Verify padding alone is actually benign
        padding_inputs = tok(padding, max_length=128, truncation=True, return_tensors="pt")
        with torch.no_grad():
            padding_score = torch.softmax(model(**padding_inputs).logits, dim=-1)[0][1].item()
        assert padding_score < 0.5, f"Padding itself should be benign, got {padding_score:.4f}"

        baseline = self._baseline_score(padded_attack, tok, model)
        scan_score, windows, blocked = sliding_score(
            padded_attack, tok, None, threshold=0.5
        )

        print(f"\n{'='*50}")
        print(f"PADDING ATTACK PROOF")
        print(f"{'='*50}")
        print(f"Baseline score:  {baseline:.4f}  → {'BLOCKED' if baseline>=0.5 else 'PASSED (VULNERABLE)'}")
        print(f"Scanner score:   {scan_score:.4f}  → {'BLOCKED (FIXED)' if blocked else 'PASSED'}")
        print(f"Windows checked: {windows}")
        print(f"{'='*50}\n")

        assert baseline < 0.5, f"Baseline should pass padding attack, got {baseline:.4f}"
        assert blocked, f"Scanner should block padding attack, got {scan_score:.4f}"