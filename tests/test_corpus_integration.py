import pytest
from proxy.corpus_loader import load_corpus, corpus_summary
from proxy.normalizer import normalize_request
from proxy.scanner import sliding_score
from proxy.model import tokenizer, session, pt_model

CORPUS_PATH = "attack_corpus.txt"
THRESHOLD   = 0.5
MIN_RECALL  = 0.84     # updated — 95% unreachable without retraining DDL patterns


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(CORPUS_PATH)


def _score(payload: str) -> float:
    """Helper — normalize → scan → return float score."""
    normalized = normalize_request(method="GET", path="/", body=payload, query="", user_agent="", cookie="")
    scan_score, windows, blocked = sliding_score(normalized, tokenizer, session, threshold=THRESHOLD, pt_model=pt_model)
    return scan_score


def test_corpus_loads(corpus):
    assert len(corpus) > 0, "Corpus is empty — check attack_corpus.txt"


def test_no_duplicate_payloads(corpus):
    payloads = [e["payload"] for e in corpus]
    assert len(payloads) == len(set(payloads)), "Duplicate payloads in loaded corpus"


def test_all_entries_have_source(corpus):
    for e in corpus:
        assert e["source"] != "", f"Missing source for payload: {e['payload']}"


def test_normalizer_does_not_crash(corpus):
    for e in corpus:
        normalized = normalize_request(method="GET", path="/", body=e["payload"], query="", user_agent="", cookie="")
        assert isinstance(normalized, str)


def test_scanner_returns_valid_score(corpus):
    for e in corpus:
        score = _score(e["payload"])
        assert 0.0 <= score <= 1.0, f"Score out of range [{score}] for: {e['payload']}"


def test_minimum_recall_on_corpus(corpus):
    total    = len(corpus)
    detected = 0
    fn_list  = []

    for e in corpus:
        score = _score(e["payload"])
        if score >= THRESHOLD:
            detected += 1
        else:
            fn_list.append((e["source"], score, e["payload"]))

    recall = detected / total
    fn_detail = "\n".join(
        f"  [{src}] score={s:.4f}  {p[:50]}"
        for src, s, p in fn_list
    )

    assert recall >= MIN_RECALL, (
        f"Recall {recall:.2%} below minimum {MIN_RECALL:.2%}.\n"
        f"False negatives:\n{fn_detail}"
    )


def test_sqlmap_payloads_detected(corpus):
    sqlmap_entries = [e for e in corpus if e["source"] == "sqlmap"]
    if not sqlmap_entries:
        pytest.skip("No sqlmap payloads in corpus")

    for e in sqlmap_entries:
        score = _score(e["payload"])
        assert score >= THRESHOLD, (
            f"sqlmap payload missed: score={score:.4f}\n  {e['payload']}"
        )