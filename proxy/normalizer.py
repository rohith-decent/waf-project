import re
import html
import unicodedata
from urllib.parse import unquote

# Zero-width characters attackers inject to break up keywords
# e.g. UNI​ON (with U+200B between I and O) looks like UNION to humans
# but tokenizes differently — the model misses it without this strip
ZERO_WIDTH_PATTERN = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f'
    r'\u2028\u2029\u202a-\u202f'
    r'\u2060-\u206f\ufeff]'
)
def normalize(raw: str) -> str:
    """
    Normalize a raw HTTP request string before tokenization.
    Four transformations in this exact order:
      1. NFKC unicode normalization  — collapses lookalike chars to ASCII
      2. Double URL decode           — %2527 -> %27 -> '
      3. HTML entity decode          — &#x27; -> '
      4. Zero-width char strip       — removes invisible separators
    Order matters: unicode normalization must run first because some
    unicode chars have percent-encoded equivalents that only become
    visible after NFKC collapses them.
    """
    # Step 1 — NFKC unicode normalisation
    # Collapses visually identical unicode chars to their ASCII equivalents
    # e.g. ʼ (U+02BC modifier letter apostrophe) → ' (plain apostrophe)
    # e.g. ＵＮＩＯＮfullwidth)→UNION (ASCII)
    text = unicodedata.normalize("NFKC", raw)
    # Step 2 — Double URL decode
    # First pass: %2527 → %27
    # Second pass: %27 → '
    # Calling unquote twice is intentional — single call misses double encoding
    text = unquote(unquote(text))
    # Step 3 — HTML entity decode
    # ' → '    &quot; → "    &lt; → <
    text = html.unescape(text)
    # Step 4 — Strip zero-width characters
    # Attackers inject these between letters to break keyword detection
    # e.g. UNI​ON (U+200B after I) defeats naive regex but our model
    # has never seen UNION tokenized with an invisible char inside it
    text = ZERO_WIDTH_PATTERN.sub("", text)
    return text
def normalize_request(method: str, path: str,
                       body: str = "", query: str = "",
                       user_agent: str = "", cookie: str = "") -> str:
    """
    Build the structured input string from HTTP fields AND normalize it.
    This is what gets passed to the tokenizer.
    Field markers give the model positional context.
    """
    raw = (
        f"[METHOD] {method} "
        f"[PATH] {path} "
        f"[QUERY] {query} "
        f"[BODY] {body} "
        f"[UA] {user_agent} "
        f"[COOKIE] {cookie}"
    ).strip()
    return normalize(raw)[:1000]