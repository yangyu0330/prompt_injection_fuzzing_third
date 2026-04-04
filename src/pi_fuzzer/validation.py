from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from typing import Iterable

from .models import CaseRecord, CoverageViolation
from .text_utils import cosine_similarity, normalize_text, sha256_text, stable_key, token_counts


def validate_pair_invariants(cases: list[CaseRecord]) -> list[str]:
    errors: list[str] = []
    idx = {c.case_id: c for c in cases}
    invariant_fields = (
        "user_goal",
        "protected_asset",
        "forbidden_action",
        "tool_scope",
        "entry_point",
        "severity",
    )
    for c in cases:
        if not c.paired_case_id:
            continue
        pair = idx.get(c.paired_case_id)
        if pair is None:
            errors.append(f"{c.case_id}: paired_case_id missing target {c.paired_case_id}")
            continue
        if pair.paired_case_id != c.case_id:
            errors.append(f"{c.case_id}: pair backlink mismatch")
        for field in invariant_fields:
            if getattr(c, field) != getattr(pair, field):
                errors.append(f"{c.case_id}: pair drift on {field}")
    return errors


def validate_split_contamination(cases: list[CaseRecord]) -> list[str]:
    errors: list[str] = []
    by_group: dict[str, set[str]] = defaultdict(set)
    for c in cases:
        by_group[c.semantic_equivalence_group].add(c.split)
    for group, splits in by_group.items():
        if len(splits) > 1:
            errors.append(f"{group}: split contamination {sorted(splits)}")
    return errors


def structural_fingerprint(c: CaseRecord) -> str:
    parts = [
        c.template_id,
        c.attack_family,
        c.attack_subfamily,
        c.directness,
        c.source_stage,
        c.turn_mode,
        c.entry_point,
        c.carrier_context,
        c.language,
        c.semantic_equivalence_group,
    ]
    return stable_key(parts)


def render_payload_text(c: CaseRecord) -> str:
    return "\n".join([c.trusted_instruction, c.user_goal, c.untrusted_content, c.expected_safe_behavior])


def dedup_cases(
    cases: list[CaseRecord],
    mode: str,
    similarity_threshold: float = 0.92,
) -> tuple[list[CaseRecord], list[dict[str, str]]]:
    exact_seen: set[str] = set()
    structural_seen: set[str] = set()
    kept: list[CaseRecord] = []
    drops: list[dict[str, str]] = []
    embedded_vectors: list[tuple[CaseRecord, dict[str, int]]] = []

    for c in sorted(cases, key=lambda x: x.case_id):
        text = normalize_text(render_payload_text(c))
        exact = sha256_text(text)
        if exact in exact_seen:
            drops.append({"case_id": c.case_id, "reason": "exact_hash"})
            continue
        exact_seen.add(exact)

        sfp = structural_fingerprint(c)
        if sfp in structural_seen:
            drops.append({"case_id": c.case_id, "reason": "structural_fingerprint"})
            continue
        structural_seen.add(sfp)

        if mode.startswith("hybrid"):
            vec = token_counts(text)
            near_dup = False
            for old_case, old_vec in embedded_vectors:
                if cosine_similarity(vec, old_vec) >= similarity_threshold:
                    drops.append(
                        {
                            "case_id": c.case_id,
                            "reason": f"embedding_similarity:{old_case.case_id}",
                        }
                    )
                    near_dup = True
                    break
            if near_dup:
                continue
            embedded_vectors.append((c, dict(vec)))

        kept.append(c)
    return kept, drops


def coverage_counts(cases: Iterable[CaseRecord], dims: list[str]) -> dict[tuple[str, ...], int]:
    counts: dict[tuple[str, ...], int] = defaultdict(int)
    for c in cases:
        key = tuple(str(getattr(c, d)) for d in dims)
        counts[key] += 1
    return dict(counts)


def enforce_min_cell_coverage(
    cases: list[CaseRecord],
    dims: list[str],
    min_count: int,
    splits: set[str] | None = None,
) -> list[CoverageViolation]:
    filtered = [c for c in cases if splits is None or c.split in splits]
    counts = coverage_counts(filtered, dims)
    violations: list[CoverageViolation] = []
    for key, count in counts.items():
        if count < min_count:
            violations.append(CoverageViolation(key=key, count=count, required=min_count))
    return violations

