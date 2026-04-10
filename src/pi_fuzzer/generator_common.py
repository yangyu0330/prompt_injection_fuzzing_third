from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from itertools import product
from pathlib import Path
from typing import Any

from .io_utils import load_yaml, read_jsonl
from .models import CaseRecord, TemplateRecord
from .text_utils import stable_key
from .validation import dedup_cases


@dataclass(frozen=True)
class FamilyContrastPolicy:
    bilingual_pairing: bool
    require_benign: bool
    benign_template_id: str
    benign_template_pool: tuple[dict[str, Any], ...]


def project_root_from(config_path: Path, project_root: Path | None) -> Path:
    if project_root is not None:
        return project_root
    return config_path.resolve().parents[1]


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def unique(values: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    out: list[Any] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def intersect(preferred: list[str], allowed: list[str]) -> list[str]:
    if not preferred:
        return unique([v for v in allowed if v])
    allowed_set = {v for v in allowed if v}
    return unique([v for v in preferred if v in allowed_set])


def short_token(value: str, max_len: int = 12) -> str:
    cleaned = "".join(ch for ch in value.upper() if ch.isalnum())
    if not cleaned:
        return "NA"
    return cleaned[:max_len]


def language_code(language: str) -> str:
    key = (language or "").strip().lower()
    if key.startswith("ko"):
        return "KO"
    if key.startswith("en"):
        return "EN"
    return short_token(key, max_len=4)


def default_source_roles(template: TemplateRecord) -> list[str]:
    stage = (template.source_stage or "").strip().lower()
    if stage == "input":
        return ["user"]
    if stage == "retrieval":
        return ["retrieved_doc"]
    if stage == "tool_input":
        return ["tool_output"]
    if stage == "tool_output":
        return ["tool_output"]
    if stage == "replay":
        return ["memory_note"]
    return [""]


def default_expected_interpretations(source_role: str) -> list[str]:
    role = (source_role or "").strip().lower()
    if role == "user":
        return ["instruction"]
    if role:
        return ["data"]
    return [""]


def load_templates(paths: list[Path]) -> list[TemplateRecord]:
    rows: list[TemplateRecord] = []
    for path in paths:
        rows.extend(TemplateRecord(**row) for row in read_jsonl(path))
    return rows


def load_cases(paths: list[Path]) -> list[CaseRecord]:
    rows: list[CaseRecord] = []
    for path in paths:
        rows.extend(CaseRecord(**row) for row in read_jsonl(path))
    return rows


def recipe_map(mutation_recipe_path: Path) -> dict[str, str]:
    cfg = load_yaml(mutation_recipe_path)
    recipes = cfg.get("recipes", {}) or {}
    by_family: dict[str, str] = {}
    for recipe_id, meta in recipes.items():
        if not isinstance(meta, dict):
            continue
        family = str(meta.get("family", "")).strip()
        if family and family not in by_family:
            by_family[family] = str(recipe_id)
    return by_family


def family_contrast_policy(attack_family: str, contrast_cfg: dict[str, Any]) -> FamilyContrastPolicy:
    defaults = contrast_cfg.get("defaults", {}) or {}
    families = contrast_cfg.get("families", {}) or {}
    family_cfg = families.get(attack_family, {}) or {}
    pool = as_list(family_cfg.get("benign_template_pool"))
    normalized_pool = tuple(item for item in pool if isinstance(item, dict))
    return FamilyContrastPolicy(
        bilingual_pairing=bool(family_cfg.get("bilingual_pairing", defaults.get("bilingual_pairing", True))),
        require_benign=bool(family_cfg.get("require_benign", defaults.get("require_benign", False))),
        benign_template_id=str(family_cfg.get("benign_template_id", defaults.get("benign_template_id", ""))).strip(),
        benign_template_pool=normalized_pool,
    )


def _value_matches(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.strip().lower() == expected.strip().lower()
    return str(actual) == str(expected)


def _case_matches_filters(case: CaseRecord, filters: dict[str, Any]) -> bool:
    for field, expected in (filters or {}).items():
        actual = getattr(case, field, None)
        if isinstance(expected, list):
            if not any(_value_matches(actual, item) for item in expected):
                return False
        else:
            if not _value_matches(actual, expected):
                return False
    return True


def choose_benign_template_id(
    *,
    policy: FamilyContrastPolicy,
    example_case: CaseRecord,
    templates_by_id: dict[str, TemplateRecord],
) -> str:
    for item in policy.benign_template_pool:
        template_id = str(item.get("template_id", "")).strip()
        if not template_id:
            continue
        template = templates_by_id.get(template_id)
        if template is None:
            continue
        when = item.get("when", {}) or {}
        if not isinstance(when, dict):
            continue
        ok = True
        for field, expected in when.items():
            actual = getattr(example_case, str(field), None)
            if isinstance(expected, list):
                if not any(_value_matches(actual, e) for e in expected):
                    ok = False
                    break
            else:
                if not _value_matches(actual, expected):
                    ok = False
                    break
        if ok:
            return template_id
    return policy.benign_template_id


def semantic_group(case: CaseRecord, mutation_sensitive: bool) -> str:
    parts = [
        case.template_id,
        case.attack_or_benign,
        case.source_stage,
        case.entry_point,
        case.source_role,
        case.expected_interpretation,
        case.carrier_context,
        case.tool_transition_type,
        case.replay_window,
        case.structured_payload_type,
    ]
    if mutation_sensitive:
        parts.extend([case.primary_mutation, ",".join(sorted(case.secondary_mutations))])
    return f"SEG-GEN-{stable_key(parts)[:12].upper()}"


def deterministic_case_id(case: CaseRecord, *, uniqueness_salt: str = "") -> str:
    hash_parts = [
        case.template_id,
        case.language,
        case.source_stage,
        case.entry_point,
        case.carrier_context,
        case.source_role,
        case.expected_interpretation,
        case.primary_mutation,
        case.policy_requested,
        case.tool_transition_type,
        case.replay_window,
        str(case.delayed_injection_turn) if case.delayed_injection_turn is not None else "",
        case.structured_payload_type,
        case.threshold_profile,
        case.normalization_variant,
    ]
    if uniqueness_salt:
        hash_parts.append(uniqueness_salt)
    digest = stable_key(hash_parts)[:8].upper()
    return (
        f"CASE-{language_code(case.language)}-"
        f"{short_token(case.template_id)}-"
        f"{short_token(case.entry_point)}-"
        f"{short_token(case.carrier_context)}-"
        f"{short_token(case.source_role)}-"
        f"{short_token(case.expected_interpretation)}-"
        f"{digest}"
    )


def contrast_group_id(case: CaseRecord) -> str:
    parts = [
        case.template_id,
        case.attack_family,
        case.entry_point,
        case.carrier_context,
        case.source_role,
        case.expected_interpretation,
        case.primary_mutation,
        case.tool_transition_type,
        case.replay_window,
        case.structured_payload_type,
    ]
    return f"CG-{stable_key(parts)[:12].upper()}"


def pair_key(case: CaseRecord) -> str:
    parts = [
        case.template_id,
        case.source_stage,
        case.entry_point,
        case.carrier_context,
        case.source_role,
        case.expected_interpretation,
        case.primary_mutation,
        case.policy_requested,
        case.tool_transition_type,
        case.replay_window,
        str(case.delayed_injection_turn) if case.delayed_injection_turn is not None else "",
        case.structured_payload_type,
        case.threshold_profile,
        case.normalization_variant,
    ]
    return stable_key(parts)


def validate_placeholder_only(case: CaseRecord) -> list[str]:
    errors: list[str] = []
    placeholder_fields = {
        "user_goal": case.user_goal,
        "trusted_instruction": case.trusted_instruction,
        "untrusted_content": case.untrusted_content,
        "expected_safe_behavior": case.expected_safe_behavior,
    }
    for field_name, value in placeholder_fields.items():
        text = (value or "").strip()
        if not text:
            errors.append(f"{case.case_id}: {field_name} must not be empty")
            continue
        if "<" not in text or ">" not in text:
            errors.append(f"{case.case_id}: {field_name} must remain placeholder-style")
    return errors


def validate_template_capability(case: CaseRecord, template: TemplateRecord) -> list[str]:
    errors: list[str] = []

    if case.entry_point not in template.supported_entry_points:
        errors.append(
            f"{case.case_id}: entry_point={case.entry_point} is outside template.supported_entry_points={template.supported_entry_points}"
        )
    if case.carrier_context not in template.supported_carriers:
        errors.append(
            f"{case.case_id}: carrier_context={case.carrier_context} is outside template.supported_carriers={template.supported_carriers}"
        )

    allowed_mutations = set(template.allowed_mutation_families or [])
    if allowed_mutations:
        for mutation in [case.primary_mutation] + list(case.secondary_mutations):
            if mutation and mutation not in allowed_mutations:
                errors.append(
                    f"{case.case_id}: mutation={mutation} is outside template.allowed_mutation_families={sorted(allowed_mutations)}"
                )

    supported_roles = set(template.supported_source_roles or [])
    if supported_roles and case.source_role and case.source_role not in supported_roles:
        errors.append(
            f"{case.case_id}: source_role={case.source_role} is outside template.supported_source_roles={sorted(supported_roles)}"
        )

    supported_interps = set(template.supported_expected_interpretations or [])
    if supported_interps and case.expected_interpretation and case.expected_interpretation not in supported_interps:
        errors.append(
            f"{case.case_id}: expected_interpretation={case.expected_interpretation} is outside template.supported_expected_interpretations={sorted(supported_interps)}"
        )

    return errors


def build_case(
    *,
    template: TemplateRecord,
    seed: int,
    language: str,
    entry_point: str,
    carrier: str,
    source_role: str,
    expected_interpretation: str,
    primary_mutation: str,
    mutation_recipe_id: str | None,
    policy_requested: str,
    tool_transition_type: str,
    replay_window: str,
    delayed_injection_turn: int | None,
    structured_payload_type: str,
    threshold_profile: str,
    normalization_variant: str,
    mutation_sensitive_seg: bool,
) -> CaseRecord:
    case = CaseRecord(
        template_id=template.template_id,
        case_id="",
        language=language,
        attack_or_benign=template.attack_or_benign,
        attack_family=template.attack_family,
        attack_subfamily=template.attack_subfamily,
        directness=template.directness,
        source_stage=template.source_stage,
        source_role=source_role,
        expected_interpretation=expected_interpretation,
        turn_mode=template.turn_mode,
        entry_point=entry_point,
        carrier_context=carrier,
        mutation_family=[m for m in [primary_mutation] if m],
        user_goal=template.user_goal_skeleton,
        trusted_instruction=template.trusted_instruction_skeleton,
        untrusted_content=template.untrusted_content_skeleton,
        protected_asset=list(template.protected_asset),
        forbidden_action=list(template.forbidden_action),
        expected_safe_behavior=template.expected_safe_behavior,
        tool_scope=template.tool_scope,
        oracle_type=list(template.oracle_type),
        severity=template.severity,
        split="dev_calibration",
        source_origin=template.source_origin,
        license_note=template.license_note,
        redistribution_policy=template.redistribution_policy,
        notes=(
            "generated;"
            f"template={template.template_id};"
            f"family={template.attack_family};"
            f"mutation={primary_mutation}"
        ),
        mutation_recipe_id=mutation_recipe_id,
        reproducibility_seed=seed,
        canonical_attack_intent_id=f"intent.{template.attack_subfamily}",
        canonical_untrusted_content=template.untrusted_content_skeleton,
        primary_mutation=primary_mutation,
        secondary_mutations=[],
        analysis_axis="generated",
        primary_target_entity=template.protected_asset[0] if template.protected_asset else "",
        expected_sensitive_entities=list(template.protected_asset),
        expected_guard_stage="",
        execution_layer=template.recommended_layer[0] if template.recommended_layer else "",
        policy_requested=policy_requested,
        tool_transition_type=tool_transition_type or template.tool_transition_type or "",
        replay_window=replay_window,
        delayed_injection_turn=delayed_injection_turn,
        structured_payload_type=structured_payload_type,
        threshold_profile=threshold_profile,
        normalization_variant=normalization_variant,
        vendor_declared_support=list(template.vendor_declared_support),
    )
    case = case.model_copy(update={"semantic_equivalence_group": semantic_group(case, mutation_sensitive=mutation_sensitive_seg)})
    case = case.model_copy(update={"case_id": deterministic_case_id(case)})
    case = case.model_copy(update={"contrast_group_id": contrast_group_id(case)})
    return case


def capability_and_placeholder_self_check(cases: list[CaseRecord], templates_by_id: dict[str, TemplateRecord]) -> list[str]:
    errors: list[str] = []
    for case in cases:
        template = templates_by_id.get(case.template_id)
        if template is None:
            errors.append(f"{case.case_id}: unknown template_id={case.template_id}")
            continue
        errors.extend(validate_template_capability(case, template))
        errors.extend(validate_placeholder_only(case))
    return errors


def deterministic_split(case: CaseRecord, seed: int, targets: dict[str, float]) -> str:
    key = stable_key([case.semantic_equivalence_group or case.template_id, str(seed)])
    val = int(key[:8], 16) / 0xFFFFFFFF
    running = 0.0
    for split_name, pct in targets.items():
        running += float(pct)
        if val <= running:
            return split_name
    return list(targets.keys())[-1]


def assign_splits(cases: list[CaseRecord], seed: int, targets: dict[str, float]) -> list[CaseRecord]:
    by_group: dict[str, str] = {}
    assigned: list[CaseRecord] = []
    for c in cases:
        key = c.semantic_equivalence_group or c.template_id
        split = by_group.get(key)
        if split is None:
            split = deterministic_split(c, seed=seed, targets=targets)
            by_group[key] = split
        assigned.append(c.model_copy(update={"split": split}))
    return assigned


def resolve_coverage_profiles(cfg: dict[str, Any], project_root: Path) -> list[dict[str, Any]]:
    coverage_cfg = cfg.get("coverage_gate", {}) or {}
    profiles_ref = coverage_cfg.get("profiles")
    if not profiles_ref:
        return [
            {
                "name": "legacy_default",
                "required_dims": coverage_cfg.get("require_cells", ["language", "source_stage", "directness", "attack_family"]),
                "min_per_cell": int(coverage_cfg.get("min_per_cell", 1)),
                "filters": coverage_cfg.get("filters", {}) or {},
                "required_values": coverage_cfg.get("required_values", {}) or {},
            }
        ]

    matrix_rel = Path(str(coverage_cfg.get("matrix_path", "catalogs/coverage_matrix.yaml")))
    matrix_path = project_root / matrix_rel
    if not matrix_path.exists():
        matrix_path = project_root / "catalogs" / "coverage_matrix.yaml"
    matrix_cfg = load_yaml(matrix_path) if matrix_path.exists() else {}

    resolved: list[dict[str, Any]] = []
    for item in profiles_ref:
        profile: dict[str, Any]
        if isinstance(item, str):
            profile = dict(matrix_cfg.get(item) or {})
            if not profile:
                raise ValueError(f"coverage_gate.profiles references unknown profile: {item}")
            profile["name"] = item
        elif isinstance(item, dict):
            profile = dict(item)
            profile.setdefault("name", "inline_profile")
        else:
            raise ValueError("coverage_gate.profiles entries must be profile names or dict objects")
        profile.setdefault("required_dims", [])
        profile.setdefault("min_per_cell", 1)
        profile.setdefault("filters", {})
        profile.setdefault("required_values", {})
        resolved.append(profile)
    return resolved


def _coverage_profile_violations(cases: list[CaseRecord], profile: dict[str, Any], splits: set[str] | None) -> list[dict[str, Any]]:
    profile_name = str(profile.get("name", "unnamed_profile"))
    filtered = [
        c
        for c in cases
        if (splits is None or c.split in splits) and _case_matches_filters(c, profile.get("filters", {}) or {})
    ]
    min_count = int(profile.get("min_per_cell", 1))
    violations: list[dict[str, Any]] = []

    dims = list(profile.get("required_dims", []) or [])
    if dims:
        counts: Counter[tuple[str, ...]] = Counter()
        for c in filtered:
            key = tuple(str(getattr(c, d)) for d in dims)
            counts[key] += 1
        for key, count in counts.items():
            if count < min_count:
                violations.append(
                    {
                        "profile": profile_name,
                        "kind": "cell",
                        "key": list(key),
                        "dims": list(dims),
                        "count": int(count),
                        "required": min_count,
                    }
                )

    required_values = profile.get("required_values", {}) or {}
    required_value_lists: dict[str, list[Any]] = {}
    for field, spec in required_values.items():
        if isinstance(spec, dict):
            values = spec.get("values", []) or []
            required = int(spec.get("min_per_value", min_count))
        elif isinstance(spec, list):
            values = spec
            required = min_count
        else:
            values = [spec]
            required = min_count
        required_value_lists[field] = list(values)
        for required_value in values:
            count = sum(1 for c in filtered if _value_matches(getattr(c, field, None), required_value))
            if count < required:
                violations.append(
                    {
                        "profile": profile_name,
                        "kind": "required_value",
                        "key": [str(field), str(required_value)],
                        "dims": [str(field)],
                        "count": int(count),
                        "required": required,
                    }
                )

    if bool(profile.get("enforce_cartesian", False)):
        missing_dims = [d for d in dims if d not in required_value_lists]
        if missing_dims:
            raise ValueError(
                f"coverage profile '{profile_name}' requires required_values for all required_dims when enforce_cartesian=true; missing: {missing_dims}"
            )
        cartesian_counts: dict[tuple[str, ...], int] = {}
        if dims:
            for c in filtered:
                key = tuple(str(getattr(c, d)) for d in dims)
                cartesian_counts[key] = cartesian_counts.get(key, 0) + 1
        expected_lists = [required_value_lists[d] for d in dims]
        for combo in product(*expected_lists):
            combo_key = tuple(str(v) for v in combo)
            count = int(cartesian_counts.get(combo_key, 0))
            if count < min_count:
                violations.append(
                    {
                        "profile": profile_name,
                        "kind": "cartesian_cell",
                        "key": list(combo_key),
                        "dims": list(dims),
                        "count": int(count),
                        "required": min_count,
                    }
                )

    required_combinations = profile.get("required_combinations", []) or []
    for combo in required_combinations:
        if not isinstance(combo, dict):
            continue
        combo_min_count = int(combo.get("min_count", min_count))
        values = {k: v for k, v in combo.items() if k != "min_count"}
        count = sum(
            1
            for c in filtered
            if all(_value_matches(getattr(c, field, None), expected) for field, expected in values.items())
        )
        if count < combo_min_count:
            violations.append(
                {
                    "profile": profile_name,
                    "kind": "required_combination",
                    "key": [f"{k}={v}" for k, v in values.items()],
                    "dims": list(values.keys()),
                    "count": int(count),
                    "required": combo_min_count,
                }
            )
    return violations


def run_coverage_gate(cases: list[CaseRecord], profiles: list[dict[str, Any]], splits: set[str] | None) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for profile in profiles:
        violations.extend(_coverage_profile_violations(cases, profile, splits=splits))
    return violations


def coverage_split_scope_for_mode(mode: str) -> set[str] | None:
    if str(mode).lower() == "release":
        return {"heldout_static", "adaptive"}
    return None


def stable_fingerprint(value: Any) -> str:
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return stable_key([canonical])


def file_fingerprint(path: Path) -> str:
    data = path.read_bytes() if path.exists() else b""
    return stable_key([str(path.resolve()), data.hex()])


def ensure_build_export_contract(build_cfg: dict[str, Any], project_root: Path, export_jsonl: Path) -> None:
    case_sources = [project_root / Path(p) for p in build_cfg.get("case_sources", [])]
    export_resolved = export_jsonl.resolve()
    if not any(p.resolve() == export_resolved for p in case_sources):
        raise ValueError(
            "bulk preflight contract mismatch: build.case_sources must include output.export_jsonl "
            f"({export_jsonl})"
        )


def build_equivalent_preflight(
    candidates: list[CaseRecord],
    *,
    generator_cfg: dict[str, Any],
    project_root: Path,
    generated_out_path: Path,
    enforce_export_contract: bool,
) -> dict[str, Any]:
    preflight_cfg = generator_cfg.get("preflight", generator_cfg.get("coverage_preflight", {})) or {}
    if not bool(preflight_cfg.get("enabled", False)):
        return {"checked": False, "note": "coverage_preflight_disabled"}

    build_config_rel = str(preflight_cfg.get("build_config", "")).strip()
    if not build_config_rel:
        raise ValueError("generator.preflight.build_config is required when preflight.enabled=true")
    build_config_path = project_root / Path(build_config_rel)
    if not build_config_path.exists():
        raise ValueError(f"coverage preflight build config not found: {build_config_path}")

    build_cfg = load_yaml(build_config_path)
    if enforce_export_contract:
        ensure_build_export_contract(build_cfg, project_root, generated_out_path)

    build_meta = build_cfg.get("build", {}) or {}
    split_cfg = (build_cfg.get("split", {}) or {}).get("targets", {}) or {
        "dev_calibration": 0.2,
        "heldout_static": 0.45,
        "adaptive": 0.15,
        "benign_hard_negative": 0.2,
    }
    seed = int(build_meta.get("seed", 20260403))

    out_resolved = generated_out_path.resolve()
    case_sources = [project_root / Path(p) for p in build_cfg.get("case_sources", [])]
    case_sources = [p for p in case_sources if p.resolve() != out_resolved]
    existing_case_sources = [p for p in case_sources if p.exists()]
    existing_cases = load_cases(existing_case_sources) if existing_case_sources else []

    combined = list(existing_cases) + list(candidates)
    combined = assign_splits(combined, seed=seed, targets=split_cfg)

    dedup_cfg = build_cfg.get("dedup", {}) or {}
    dedup_mode = str(dedup_cfg.get("mode", "structured_only"))
    similarity_threshold = float(dedup_cfg.get("similarity_threshold", 0.92))
    release_mode = str(build_meta.get("mode", "dev")).lower() == "release"
    if release_mode:
        held_adp = [c for c in combined if c.split in {"heldout_static", "adaptive"}]
        other = [c for c in combined if c.split not in {"heldout_static", "adaptive"}]
        kept_release, _drops = dedup_cases(held_adp, mode="hybrid_mandatory", similarity_threshold=similarity_threshold)
        combined = sorted(other + kept_release, key=lambda c: c.case_id)
    else:
        combined, _drops = dedup_cases(combined, mode=dedup_mode, similarity_threshold=similarity_threshold)

    candidate_ids = {c.case_id for c in candidates}
    survivor_case_ids = sorted([c.case_id for c in combined if c.case_id in candidate_ids])
    generated_survivors = len(survivor_case_ids)

    profiles = resolve_coverage_profiles(build_cfg, project_root)
    split_scope = coverage_split_scope_for_mode(str(build_meta.get("mode", "dev")))
    coverage_violations = run_coverage_gate(combined, profiles=profiles, splits=split_scope)

    family_input = Counter(c.attack_family for c in candidates)
    family_survivor = Counter(c.attack_family for c in combined if c.case_id in candidate_ids)
    family_drop = {family: int(family_input.get(family, 0) - family_survivor.get(family, 0)) for family in family_input}

    return {
        "checked": True,
        "build_config": str(build_config_path),
        "split_scope": sorted(split_scope) if split_scope else "all_splits",
        "candidate_input_count": len(candidates),
        "generated_survivors_after_build_semantics": generated_survivors,
        "survivor_case_ids": survivor_case_ids,
        "coverage_violations": coverage_violations,
        "coverage_violation_count": len(coverage_violations),
        "family_input_counts": dict(sorted(family_input.items())),
        "family_survivor_counts": dict(sorted(family_survivor.items())),
        "family_drop_counts": dict(sorted(family_drop.items())),
        "case_sources_for_preflight": [str(p) for p in existing_case_sources],
    }


def fingerprint_build_context(
    *,
    generator_cfg: dict[str, Any],
    build_config_path: Path | None,
    template_sources: list[Path],
    curated_case_sources: list[Path],
    coverage_matrix_path: Path | None,
    seed: int,
) -> dict[str, str]:
    return {
        "effective_generator_config": stable_fingerprint(generator_cfg),
        "build_config": file_fingerprint(build_config_path) if build_config_path is not None else stable_fingerprint(""),
        "template_source": stable_fingerprint([file_fingerprint(p) for p in sorted(template_sources)]),
        "curated_case_source": stable_fingerprint([file_fingerprint(p) for p in sorted(curated_case_sources)]),
        "coverage_matrix": file_fingerprint(coverage_matrix_path) if coverage_matrix_path is not None else stable_fingerprint(""),
        "seed": stable_fingerprint(str(seed)),
    }


def resolve_build_paths_for_fingerprint(
    *,
    generator_cfg: dict[str, Any],
    project_root: Path,
    export_jsonl: Path,
) -> tuple[Path | None, list[Path], Path | None]:
    preflight_cfg = generator_cfg.get("preflight", generator_cfg.get("coverage_preflight", {})) or {}
    build_config_rel = str(preflight_cfg.get("build_config", "")).strip()
    if not build_config_rel:
        return (None, [], None)

    build_config_path = project_root / Path(build_config_rel)
    if not build_config_path.exists():
        return (build_config_path, [], None)

    build_cfg = load_yaml(build_config_path)
    case_sources = [project_root / Path(p) for p in build_cfg.get("case_sources", [])]
    export_resolved = export_jsonl.resolve()
    curated_case_sources = [p for p in case_sources if p.resolve() != export_resolved and p.exists()]

    coverage_cfg = build_cfg.get("coverage_gate", {}) or {}
    matrix_rel = Path(str(coverage_cfg.get("matrix_path", "catalogs/coverage_matrix.yaml")))
    coverage_matrix_path = project_root / matrix_rel
    if not coverage_matrix_path.exists():
        coverage_matrix_path = None

    return (build_config_path, curated_case_sources, coverage_matrix_path)
