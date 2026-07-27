"""Shannon entropy utilities used to flag high-randomness strings
(a strong signal for API keys, tokens, and passwords)."""

from __future__ import annotations

import math
import re
from collections import Counter

# Tokens shorter than this are almost never meaningful secrets and just
# add noise (variable names, short words, etc.)
MIN_TOKEN_LENGTH = 16

# Candidate token pattern: contiguous runs of base64/hex-ish characters,
# often assigned to a variable or quoted as a string literal.
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_\-/+=]{%d,}" % MIN_TOKEN_LENGTH)


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits/char) of the given string.

    Higher entropy means more randomness. Typical English words score
    ~2.5-3.5, while random base64/hex secrets typically score 4.0+.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def extract_candidate_tokens(line: str) -> list[str]:
    """Pull out substrings from a line that are long enough and
    "token-like" to be worth an entropy check."""
    return _TOKEN_PATTERN.findall(line)


def is_high_entropy(token: str, threshold: float = 4.0) -> bool:
    """Return True if a token's entropy exceeds the given threshold."""
    return shannon_entropy(token) >= threshold
