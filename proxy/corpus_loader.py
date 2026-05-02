import re
from pathlib import Path
from typing import List, Dict

# Section markers defined in the corpus file
SECTION_PATTERNS: Dict[str, str] = {
    r"sqlmap":       "sqlmap",
    r"nikto":        "nikto",
    r"[Bb]urp":      "burp",
    r"[Oo]llama":    "ollama",
}

def detect_section(line: str, current: str) -> str:
    """Return updated section label if a section header is detected."""
    for pattern, label in SECTION_PATTERNS.items():
        if re.search(pattern, line, re.IGNORECASE):
            return label
    return current

def load_corpus(path: str = "attack_corpus.txt") -> List[Dict[str, str]]:
    """
    Load and parse the attack corpus file.

    Returns:
        List of dicts: [{"payload": "...", "source": "sqlmap"}, ...]
        Empty source sections are skipped gracefully (Nikto, Burp stubs).
    """
    corpus_path = Path(path)
    if not corpus_path.exists():
        raise FileNotFoundError(f"Corpus not found at: {path}")

    entries: List[Dict[str, str]] = []
    seen: set = set()        # dedup tracker
    current_section: str = "unknown"

    with open(corpus_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            # Skip blank lines
            if not line:
                continue

            # Detect section headers (lines starting with #)
            if line.startswith("#"):
                current_section = detect_section(line, current_section)
                continue

            # Deduplicate
            if line in seen:
                continue

            seen.add(line)
            entries.append({
                "payload": line,
                "source": current_section,
            })

    return entries

def corpus_summary(entries: List[Dict[str, str]]) -> Dict[str, int]:
    """Return count per source section."""
    summary: Dict[str, int] = {}
    for e in entries:
        summary[e["source"]] = summary.get(e["source"], 0) + 1
    return summary

if __name__ == "__main__":
    entries = load_corpus()
    summary = corpus_summary(entries)
    print(f"Loaded {len(entries)} unique payloads")
    for src, count in summary.items():
        print(f"  {src:12s}: {count} payloads")