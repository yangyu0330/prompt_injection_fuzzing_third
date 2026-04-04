from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from .io_utils import load_yaml


def _default_taxonomy_path() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "catalogs" / "analysis_taxonomy.yaml"
    if path.exists():
        return path
    # Fallback for CLI runs rooted at project cwd.
    return Path.cwd() / "catalogs" / "analysis_taxonomy.yaml"


@lru_cache(maxsize=1)
def load_analysis_taxonomy() -> dict[str, Any]:
    path = _default_taxonomy_path()
    if not path.exists():
        return {"canonical_fields": {}, "unknown_policy": {"empty": "keep_empty", "unknown_non_empty": "other"}}
    return load_yaml(path)


def normalize_canonical(field: str, value: str) -> str:
    raw = value or ""
    if not raw.strip():
        return ""

    taxonomy = load_analysis_taxonomy()
    fields = taxonomy.get("canonical_fields", {})
    field_cfg = fields.get(field, {})
    aliases = field_cfg.get("aliases", {}) or {}
    allowed = set(field_cfg.get("allowed", []) or [])

    mapped = aliases.get(raw, aliases.get(raw.lower(), raw))
    if not allowed:
        return mapped
    if mapped in allowed:
        return mapped
    return "other"


def normalize_source_stage(value: str) -> str:
    return normalize_canonical("source_stage", value)


def normalize_execution_layer(value: str) -> str:
    return normalize_canonical("execution_layer", value)


def normalize_policy_mode(value: str) -> str:
    return normalize_canonical("policy_mode", value)

