from __future__ import annotations

import hashlib
import re
from collections import Counter
from math import sqrt
from typing import Iterable


_SPACE_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    lowered = text.lower()
    return _SPACE_RE.sub(" ", lowered).strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def token_counts(text: str) -> Counter[str]:
    tokens = normalize_text(text).split(" ")
    return Counter([tok for tok in tokens if tok])


def cosine_similarity(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b.get(k, 0) for k in a.keys())
    na = sqrt(sum(v * v for v in a.values()))
    nb = sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def stable_key(parts: Iterable[str]) -> str:
    joined = "||".join(parts)
    return sha256_text(joined)

