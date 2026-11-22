"""Canonical serialisation and hashing.

Every hash in S.H.I.E.L.D (order hashes, action hashes, log entry hashes,
idempotency keys) is taken over the output of :func:`canonical_json`, so two
structurally equal values always hash the same regardless of key order,
whitespace or float formatting.

This module is part of the trusted core: no LLM, no I/O, no imports from
``agents``.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

ZERO_HASH = "0" * 64

# Unicode dashes that look like ASCII "-" and are the classic way to smuggle a
# second write past a naive duplicate check. Normalised to "-" before hashing.
_HYPHEN_LIKE = {
    "‐",  # hyphen
    "‑",  # non-breaking hyphen
    "‒",  # figure dash
    "–",  # en dash
    "—",  # em dash
    "―",  # horizontal bar
    "−",  # minus sign
    "﹘",  # small em dash
    "﹣",  # small hyphen-minus
    "－",  # fullwidth hyphen-minus
}


def _default(obj: Any) -> Any:
    """JSON fallback for the handful of non-JSON types used in our models."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return format(obj, "f")
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, "model_dump"):  # pydantic BaseModel
        return obj.model_dump(mode="json")
    raise TypeError(f"not canonicalisable: {type(obj).__name__}")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, ASCII-safe."""
    return json.dumps(
        obj,
        default=_default,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    """SHA-256 of the canonical JSON form of ``obj``."""
    return sha256_hex(canonical_json(obj))


def canonicalize_account(
    raw: str,
    *,
    upper: bool = True,
    strip: bool = True,
    normalize_unicode_hyphens: bool = True,
) -> str:
    """Fold the spellings of an account id that denote the same account.

    Driven by ``policy.idempotency.canonicalize_target`` so the rule lives in
    policy, not in scattered call sites. Used for idempotency keys and for
    comparing a proposal's target against the allowed-target set.
    """
    out = raw
    if normalize_unicode_hyphens:
        # NFKC first (folds fullwidth forms), then map the remaining dashes.
        out = unicodedata.normalize("NFKC", out)
        out = "".join("-" if ch in _HYPHEN_LIKE else ch for ch in out)
    if strip:
        out = out.strip()
    if upper:
        out = out.upper()
    return out
