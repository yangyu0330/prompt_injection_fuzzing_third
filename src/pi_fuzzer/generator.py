from __future__ import annotations

from itertools import product
from pathlib import Path
from typing import Any

from .generator_bulk import generate_cases_bulk
from .generator_common import (
    as_list,
    build_case,
    build_equivalent_preflight,
    capability_and_placeholder_self_check,
    choose_benign_template_id,
    default_expected_interpretations,
    default_source_roles,
    deterministic_case_id,
    family_contrast_policy,
    intersect,
    load_templates,
    pair_key,
    project_root_from,
    recipe_map,
    unique,
)
from .io_utils import load_yaml, write_jsonl
from .models import CaseRecord
from .text_utils import stable_key
from .validation import validate_analysis_linkage


def _generate_cases_mvp(
    *,
    template_sources: list[Path],
    config_path: Path,
    out_path: Path,
    project_root: Path | None,
) -> dict[str, Any]:
    root = project_root_from(config_path, project_root)
    cfg_raw = load_yaml(config_path)
    generator_cfg = cfg_raw.get("generator", {}) or {}

    seed = int(generator_cfg.get("seed", 20260409))
    mutation_recipe_path = root / Path(str(generator_cfg.get("mutation_recipe_path", "catalogs/mutation_recipes.yaml")))
    recipe_by_family = recipe_map(mutation_recipe_path)

    templates_abs = [(root / p) if not p.is_absolute() else p for p in template_sources]
    templates = load_templates(templates_abs)
    templates_by_id = {t.template_id: t for t in templates}
    family_rules = dict(generator_cfg.get("families", {}) or {})
    contrast_cfg = dict(generator_cfg.get("contrast_policy", {}) or {})

    generated: list[CaseRecord] = []
    skipped_templates: list[str] = []

    for template in sorted(templates, key=lambda t: t.template_id):
        family_rule = family_rules.get(template.attack_family)
        if not isinstance(family_rule, dict):
            skipped_templates.append(template.template_id)
            continue

        languages = unique([str(v) for v in as_list(family_rule.get("languages")) if str(v).strip()]) or ["ko", "en"]
        entry_points = intersect(
            [str(v) for v in as_list(family_rule.get("entry_points"))],
            list(template.supported_entry_points),
        )
        carriers = intersect(
            [str(v) for v in as_list(family_rule.get("carriers"))],
            list(template.supported_carriers),
        )
        source_roles_pref = [str(v) for v in as_list(family_rule.get("source_roles"))]
        source_roles = (
            intersect(source_roles_pref, list(template.supported_source_roles))
            if template.supported_source_roles
            else unique(source_roles_pref)
        )
        if not source_roles:
            source_roles = list(template.supported_source_roles) or default_source_roles(template)

        expected_pref = [str(v) for v in as_list(family_rule.get("expected_interpretations"))]
        expected_interpretations = (
            intersect(expected_pref, list(template.supported_expected_interpretations))
            if template.supported_expected_interpretations
            else unique(expected_pref)
        )
        if not expected_interpretations:
            if template.supported_expected_interpretations:
                expected_interpretations = list(template.supported_expected_interpretations)
            else:
                role_defaults: list[str] = []
                for role in source_roles:
                    role_defaults.extend(default_expected_interpretations(role))
                expected_interpretations = unique(role_defaults) or [""]

        mutations_pref = [str(v) for v in as_list(family_rule.get("mutations"))]
        if template.allowed_mutation_families:
            mutations = intersect(mutations_pref, list(template.allowed_mutation_families))
        else:
            mutations = unique(mutations_pref)
        if not mutations:
            mutations = list(template.allowed_mutation_families)

        policy_requested_values = [str(v) for v in as_list(family_rule.get("policy_requested"))] or [""]
        tool_transition_values = [str(v) for v in as_list(family_rule.get("tool_transition_types"))] or [
            template.tool_transition_type or ""
        ]
        replay_windows = [str(v) for v in as_list(family_rule.get("replay_windows"))] or [""]
        delayed_turn_values_raw = as_list(family_rule.get("delayed_injection_turns"))
        delayed_turn_values: list[int | None] = [int(v) if v is not None and str(v) != "" else None for v in delayed_turn_values_raw] or [
            None
        ]
        structured_payload_types = [str(v) for v in as_list(family_rule.get("structured_payload_types"))] or [""]
        threshold_profiles = [str(v) for v in as_list(family_rule.get("threshold_profiles"))] or [""]
        normalization_variants = [str(v) for v in as_list(family_rule.get("normalization_variants"))] or [""]
        mutation_sensitive_seg = bool(family_rule.get("seg_mutation_sensitive", False))
        max_cases = int(family_rule.get("max_cases_per_template", 100))

        if not entry_points or not carriers or not source_roles or not expected_interpretations or not mutations:
            skipped_templates.append(template.template_id)
            continue

        rows_for_template: list[CaseRecord] = []
        axis = product(
            languages,
            entry_points,
            carriers,
            source_roles,
            expected_interpretations,
            mutations,
            policy_requested_values,
            tool_transition_values,
            replay_windows,
            delayed_turn_values,
            structured_payload_types,
            threshold_profiles,
            normalization_variants,
        )
        for (
            language,
            entry_point,
            carrier,
            source_role,
            expected_interpretation,
            mutation,
            policy_requested,
            tool_transition_type,
            replay_window,
            delayed_turn,
            structured_payload_type,
            threshold_profile,
            normalization_variant,
        ) in axis:
            row = build_case(
                template=template,
                seed=seed,
                language=str(language),
                entry_point=str(entry_point),
                carrier=str(carrier),
                source_role=str(source_role),
                expected_interpretation=str(expected_interpretation),
                primary_mutation=str(mutation),
                mutation_recipe_id=recipe_by_family.get(str(mutation)),
                policy_requested=str(policy_requested),
                tool_transition_type=str(tool_transition_type),
                replay_window=str(replay_window),
                delayed_injection_turn=delayed_turn,
                structured_payload_type=str(structured_payload_type),
                threshold_profile=str(threshold_profile),
                normalization_variant=str(normalization_variant),
                mutation_sensitive_seg=mutation_sensitive_seg,
            )
            rows_for_template.append(row)

        dedup_rows: dict[str, CaseRecord] = {}
        for row in sorted(rows_for_template, key=lambda r: r.case_id):
            dedup_rows.setdefault(row.case_id, row)
        generated.extend(list(sorted(dedup_rows.values(), key=lambda r: r.case_id))[:max_cases])

    generated_by_id = {row.case_id: row for row in generated}
    generated = sorted(generated_by_id.values(), key=lambda r: r.case_id)

    by_pair_key: dict[str, list[CaseRecord]] = {}
    for row in generated:
        policy = family_contrast_policy(row.attack_family, contrast_cfg)
        if not policy.bilingual_pairing:
            continue
        key = pair_key(row)
        by_pair_key.setdefault(key, []).append(row)

    for key, rows in by_pair_key.items():
        ko_rows = sorted([r for r in rows if (r.language or "").lower().startswith("ko")], key=lambda r: r.case_id)
        en_rows = sorted([r for r in rows if (r.language or "").lower().startswith("en")], key=lambda r: r.case_id)
        if not ko_rows or not en_rows:
            continue
        ko = ko_rows[0]
        en = en_rows[0]
        pair_id = f"KRP-{stable_key([key])[:10].upper()}"
        generated_by_id[ko.case_id] = ko.model_copy(
            update={
                "paired_case_id": en.case_id,
                "kr_en_pair_id": pair_id,
                "paired_case_role": "ko_variant",
            }
        )
        generated_by_id[en.case_id] = en.model_copy(
            update={
                "paired_case_id": ko.case_id,
                "kr_en_pair_id": pair_id,
                "paired_case_role": "en_control",
            }
        )
    generated = sorted(generated_by_id.values(), key=lambda r: r.case_id)
    generated_by_id = {row.case_id: row for row in generated}

    attack_rows = [r for r in generated if r.attack_or_benign == "attack"]
    required_groups: dict[str, tuple[CaseRecord, str]] = {}
    for row in attack_rows:
        policy = family_contrast_policy(row.attack_family, contrast_cfg)
        if not policy.require_benign:
            continue
        benign_template_id = choose_benign_template_id(
            policy=policy,
            example_case=row,
            templates_by_id=templates_by_id,
        )
        if not benign_template_id:
            raise ValueError(
                f"contrast_policy for family={row.attack_family} requires benign_template_id when require_benign=true"
            )
        required_groups.setdefault(row.contrast_group_id, (row, benign_template_id))

    created_benign: dict[str, str] = {}
    for contrast_group_id, (example, benign_template_id) in required_groups.items():
        benign_template = templates_by_id.get(benign_template_id)
        if benign_template is None:
            raise ValueError(
                f"contrast_policy family={example.attack_family} references unknown benign_template_id={benign_template_id}"
            )

        entry_point = (
            example.entry_point
            if example.entry_point in benign_template.supported_entry_points
            else benign_template.supported_entry_points[0]
        )
        carrier = (
            example.carrier_context
            if example.carrier_context in benign_template.supported_carriers
            else benign_template.supported_carriers[0]
        )
        source_role = example.source_role
        if benign_template.supported_source_roles:
            source_role = (
                source_role
                if source_role in benign_template.supported_source_roles
                else benign_template.supported_source_roles[0]
            )
        expected_interpretation = example.expected_interpretation
        if benign_template.supported_expected_interpretations:
            expected_interpretation = (
                expected_interpretation
                if expected_interpretation in benign_template.supported_expected_interpretations
                else benign_template.supported_expected_interpretations[0]
            )
        benign_mutation = (benign_template.allowed_mutation_families or ["quote_wrapper"])[0]
        benign = build_case(
            template=benign_template,
            seed=seed,
            language=example.language,
            entry_point=entry_point,
            carrier=carrier,
            source_role=source_role,
            expected_interpretation=expected_interpretation,
            primary_mutation=benign_mutation,
            mutation_recipe_id=recipe_by_family.get(benign_mutation),
            policy_requested=example.policy_requested,
            tool_transition_type=example.tool_transition_type,
            replay_window=example.replay_window,
            delayed_injection_turn=example.delayed_injection_turn,
            structured_payload_type=example.structured_payload_type,
            threshold_profile=example.threshold_profile,
            normalization_variant=example.normalization_variant,
            mutation_sensitive_seg=False,
        ).model_copy(
            update={
                "contrast_group_id": contrast_group_id,
                "paired_case_role": "benign_control",
            }
        )
        benign = benign.model_copy(update={"case_id": deterministic_case_id(benign, uniqueness_salt=contrast_group_id)})
        generated_by_id[benign.case_id] = benign
        created_benign[contrast_group_id] = benign.case_id

    for row in attack_rows:
        benign_id = created_benign.get(row.contrast_group_id)
        if not benign_id:
            continue
        generated_by_id[row.case_id] = row.model_copy(
            update={
                "benign_sibling_id": benign_id,
                "paired_case_role": row.paired_case_role or "attack",
            }
        )
    generated = sorted(generated_by_id.values(), key=lambda r: r.case_id)

    self_check_errors = capability_and_placeholder_self_check(generated, templates_by_id)
    if self_check_errors:
        sample = "\n".join(self_check_errors[:20])
        raise ValueError(f"Generator self-check failed ({len(self_check_errors)}):\n{sample}")
    analysis_errors = validate_analysis_linkage(generated)
    if analysis_errors:
        sample = "\n".join(analysis_errors[:20])
        raise ValueError(f"Generator analysis-link self-check failed ({len(analysis_errors)}):\n{sample}")

    preflight = build_equivalent_preflight(
        generated,
        generator_cfg=generator_cfg,
        project_root=root,
        generated_out_path=out_path,
        enforce_export_contract=False,
    )
    if preflight.get("checked"):
        violations = preflight.get("coverage_violations", [])
        if violations:
            sample = ", ".join(
                f"{v['profile']}:{v['kind']}:{tuple(v['key'])}:{v['count']}/{v['required']}" for v in violations[:8]
            )
            raise ValueError(
                f"Coverage preflight failed ({len(violations)} violations, combined curated+generated scope): {sample}"
            )
        min_survivors = int((generator_cfg.get("dedup_preflight", {}) or {}).get("min_generated_survivors", 1))
        survivors = int(preflight.get("generated_survivors_after_build_semantics", 0))
        if survivors < min_survivors:
            raise ValueError(
                f"Dedup preflight left {survivors} generated survivors; requires >= {min_survivors}"
            )

    write_jsonl(out_path, [row.model_dump() for row in sorted(generated, key=lambda r: r.case_id)])
    return {
        "ok": True,
        "status": "success",
        "mode": "mvp",
        "generated_count": len(generated),
        "template_count": len(templates),
        "template_sources": [str(p) for p in template_sources],
        "out_path": str(out_path),
        "skipped_templates": sorted(skipped_templates),
        "preflight": preflight,
        "notes": {
            "split_semantics": "generator split is temporary; build reassignment remains source of truth",
            "preflight_scope": "combined curated + candidate generated",
            "dedup_semantics": "final dedup remains build source of truth",
        },
    }


def generate_cases(
    template_sources: list[Path],
    config_path: Path,
    out_path: Path,
    project_root: Path | None = None,
    *,
    resume: bool = False,
) -> dict[str, Any]:
    cfg_raw = load_yaml(config_path)
    generator_cfg = cfg_raw.get("generator", {}) or {}
    mode = str(generator_cfg.get("mode", "mvp")).strip().lower() or "mvp"

    if mode == "bulk":
        return generate_cases_bulk(
            template_sources=template_sources,
            config_path=config_path,
            out_path=out_path,
            project_root=project_root,
            resume=resume,
        )

    if resume:
        raise ValueError("--resume is only valid when generator.mode=bulk")
    if mode != "mvp":
        raise ValueError(f"unknown generator.mode: {mode}")

    return _generate_cases_mvp(
        template_sources=template_sources,
        config_path=config_path,
        out_path=out_path,
        project_root=project_root,
    )
