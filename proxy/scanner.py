from __future__ import annotations
import numpy as np
from typing import Tuple

# These come from model.py — passed in to avoid reloading the model
# for every request. Model and tokenizer are loaded once at startup.

WINDOW_SIZE = 128   # must match max_length used during training
STRIDE      = 64    # overlap = window - stride = 64 tokens
                    # every token is covered by at least 1 window
def _score_tokens(ids, tokenizer, session, pt_model=None):
    import torch
    import numpy as np

    input_ids = np.array([ids], dtype=np.int64)
    attention_mask = np.ones_like(input_ids)

    if session is not None:
        logits = session.run(None, {
            "input_ids": input_ids,
            "attention_mask": attention_mask
        })[0][0]
        e = np.exp(logits - logits.max())
        probs = e / e.sum()
        return float(probs[1])
    else:
        with torch.no_grad():
            out = pt_model(
                input_ids=torch.tensor(input_ids),
                attention_mask=torch.tensor(attention_mask)
            )
        return torch.softmax(out.logits, dim=-1)[0][1].item()

def sliding_score(
    text:      str,
    tokenizer,
    session,
    threshold: float = 0.5,
    pt_model=None
) -> Tuple[float, int, bool]:
    """
    Score a request using overlapping 128-token windows.
    Returns: (max_score, windows_checked, is_blocked)
    The sliding window closes the padding bypass:
    An attacker pads tokens 0–129 with junk, hides payload at token 135.
    Naive model: reads tokens 0–127 (junk), scores 0.05 → PASSES.
    This scanner: window 1 = 0–127 (junk, 0.05),
                  window 2 = 64–191 (payload visible, 0.97) → BLOCKS.
    """
    # Tokenize the FULL request — no truncation here
    all_ids = tokenizer.encode(
        text,
        add_special_tokens=False,  # we add CLS/SEP per window below
        truncation=False,
    )
    # Short request — single pass, no windowing overhead
    if len(all_ids) <= WINDOW_SIZE - 2:  # -2 for CLS + SEP
        ids_with_special = (
            [tokenizer.cls_token_id]
            + all_ids
            + [tokenizer.sep_token_id]
        )
        score = _score_tokens(ids_with_special, tokenizer, session, pt_model=pt_model)
        return score, 1, score >= threshold
    # Long request — slide the window
    scores       = []
    content_size = WINDOW_SIZE - 2   # space after CLS and SEP
    for start in range(0, len(all_ids), STRIDE):
        chunk = all_ids[start : start + content_size]
        if not chunk:
            break
        # Wrap each chunk with CLS and SEP — model expects these
        ids_with_special = (
            [tokenizer.cls_token_id]
            + chunk
            + [tokenizer.sep_token_id]
        )
        scores.append(_score_tokens(ids_with_special, tokenizer, session))
    max_score = max(scores)
    return max_score, len(scores), max_score >= threshold