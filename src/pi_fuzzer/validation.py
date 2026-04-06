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


def validate_kr_en_pair_links(cases: list[CaseRecord]) -> list[str]:
    errors: list[str] = []
    by_pair: dict[str, list[CaseRecord]] = defaultdict(list)
    for c in cases:
        pair_id = (c.kr_en_pair_id or "").strip()
        if pair_id:
            by_pair[pair_id].append(c)

    for pair_id, rows in by_pair.items():
        langs = {r.language.lower()[:2] for r in rows}
        if "ko" not in langs or "en" not in langs:
            errors.append(f"{pair_id}: must include both ko and en variants")
        if len(rows) < 2:
            errors.append(f"{pair_id}: requires at least 2 cases")
        row_ids = {r.case_id for r in rows}
        for row in rows:
            if row.paired_case_id and row.paired_case_id not in row_ids:
                errors.append(f"{row.case_id}: paired_case_id must stay within kr_en_pair_id={pair_id}")
    return errors


def validate_benign_sibling_and_contrast(cases: list[CaseRecord]) -> list[str]:
    errors: list[str] = []
    idx = {c.case_id: c for c in cases}
    groups: dict[str, list[CaseRecord]] = defaultdict(list)
    for c in cases:
        gid = (c.contrast_group_id or "").strip()
        if gid:
            groups[gid].append(c)
        sibling = (c.benign_sibling_id or "").strip()
        if not sibling:
            continue
        sib = idx.get(sibling)
        if sib is None:
            errors.append(f"{c.case_id}: benign_sibling_id missing target {sibling}")
            continue
        if c.attack_or_benign == sib.attack_or_benign:
            errors.append(f"{c.case_id}: benign_sibling_id must point to opposite attack_or_benign")
        if c.contrast_group_id and sib.contrast_group_id and c.contrast_group_id != sib.contrast_group_id:
            errors.append(f"{c.case_id}: benign sibling contrast_group_id mismatch")

    for gid, rows in groups.items():
        has_attack = any(r.attack_or_benign == "attack" for r in rows)
        has_benign = any(r.attack_or_benign == "benign" for r in rows)
        requires_benign = any((r.benign_sibling_id or "").strip() for r in rows) or any(
            (r.paired_case_role or "").strip().lower().startswith("benign") for r in rows
        )
        if requires_benign and has_attack and not has_benign:
            errors.append(f"{gid}: contrast group has attack without benign sibling/control")
    return errors


def validate_source_role_stage_coverage(cases: list[CaseRecord]) -> list[str]:
    errors: list[str] = []

    for c in cases:
        stage = (c.source_stage or "").strip().lower()
        role = (c.source_role or "").strip().lower()
        interp = (c.expected_interpretation or "").strip().lower()
        requires_role = bool(role or interp) or stage in {"retrieval", "tool_input", "tool_output", "replay"}
        if not requires_role:
            continue
        if not role:
            errors.append(f"{c.case_id}: source_role required when role-stage coverage is enabled")
            continue
        if not interp:
            errors.append(f"{c.case_id}: expected_interpretation required when source_role is present")
        if stage == "tool_output" and role != "tool_output":
            errors.append(f"{c.case_id}: source_stage=tool_output requires source_role=tool_output")
        if stage == "replay" and role not in {"memory_note", "tool_output"}:
            errors.append(f"{c.case_id}: source_stage=replay requires source_role in [memory_note, tool_output]")
        if stage == "retrieval" and role not in {"retrieved_doc", "assistant_quote", "system_note"}:
            errors.append(f"{c.case_id}: source_stage=retrieval requires retrieval-oriented source_role")
    return errors


def validate_analysis_linkage(cases: list[CaseRecord]) -> list[str]:
    return (
        validate_kr_en_pair_links(cases)
        + validate_benign_sibling_and_contrast(cases)
        + validate_source_role_stage_coverage(cases)
    )


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
