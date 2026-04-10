from __future__ import annotations

import math
from pathlib import Path

from pi_fuzzer.generator_bulk import _plan_bundles_for_template
from pi_fuzzer.generator_common import (
    build_case,
    capability_and_placeholder_self_check,
    default_expected_interpretations,
    default_source_roles,
    load_templates,
    recipe_map,
)
from pi_fuzzer.io_utils import load_yaml
from pi_fuzzer.models import TemplateRecord
from pi_fuzzer.validation import validate_analysis_linkage


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _templates_by_id() -> dict[str, TemplateRecord]:
    rows = load_templates([_repo_root() / "catalogs" / "sample_templates.jsonl"])
    return {row.template_id: row for row in rows}


def _build_single_case(template: TemplateRecord, recipe_by_family: dict[str, str]) -> object:
    source_role = template.supported_source_roles[0] if template.supported_source_roles else default_source_roles(template)[0]
    if template.supported_expected_interpretations:
        expected = template.supported_expected_interpretations[0]
    else:
        expected = default_expected_interpretations(source_role)[0]

    mutation = (template.allowed_mutation_families or ["quote_wrapper"])[0]
    return build_case(
        template=template,
        seed=20260409,
        language="ko",
        entry_point=template.supported_entry_points[0],
        carrier=template.supported_carriers[0],
        source_role=source_role,
        expected_interpretation=expected,
        primary_mutation=mutation,
        mutation_recipe_id=recipe_by_family.get(mutation),
        policy_requested="",
        tool_transition_type=template.tool_transition_type or "",
        replay_window="",
        delayed_injection_turn=None,
        structured_payload_type="",
        threshold_profile="",
        normalization_variant="",
        mutation_sensitive_seg=False,
    )


def test_bulk_config_has_12_family_budgets_and_formula() -> None:
    cfg = load_yaml(_repo_root() / "configs" / "generator_bulk.yaml")
    families = dict((cfg.get("generator", {}) or {}).get("families", {}) or {})

    expected = {
        "tool_agent_misuse",
        "replay_trajectory_injection",
        "structured_payload_misuse",
        "korean_service_context",
        "indirect_document_web_rag",
        "ko_native_mutation_layer",
        "repo_coding_agent_injection",
        "direct_user_injection",
        "email_agent_injection",
        "ko_detector_guardrail_track",
        "adaptive_fuzzing",
        "config_sensitivity_probe",
    }
    assert set(families.keys()) == expected

    target_sum = sum(int((rule or {}).get("target_survivors", 0)) for rule in families.values())
    assert target_sum == 2000

    for family, rule in families.items():
        target = int((rule or {}).get("target_survivors", 0))
        max_raw_rows = int((rule or {}).get("max_raw_rows", 0))
        max_bundles = int((rule or {}).get("max_bundles", 0))
        assert max_raw_rows == target * 2, family
        assert max_bundles >= math.ceil(max_raw_rows / 5), family


def test_new_templates_exist_and_mutations_are_recipe_backed() -> None:
    templates = _templates_by_id()
    cfg = load_yaml(_repo_root() / "configs" / "generator_bulk.yaml")
    families = dict((cfg.get("generator", {}) or {}).get("families", {}) or {})
    recipe_by_family = recipe_map(_repo_root() / "catalogs" / "mutation_recipes.yaml")

    required_template_ids = {
        "TMP-BENIGN-REPO-001",
        "TMP-BENIGN-YAML-001",
        "TMP-REPO-COMMENT-001",
        "TMP-REPO-WORKFLOW-001",
        "TMP-ADAPT-SEED-001",
        "TMP-ADAPT-TOOL-001",
        "TMP-CONFIG-THRESH-001",
        "TMP-CONFIG-NORM-001",
        "TMP-RAG-SEARCH-001",
        "TMP-RAG-REPOFILE-001",
        "TMP-STRUCT-YAML-001",
        "TMP-DIRECT-PSEUDO-SYSTEM-001",
        "TMP-KO-CONFIRM-ALREADY-001",
        "TMP-KO-SPACING-PARTICLE-001",
        "TMP-TOOL-JSON-STEER-001",
    }
    assert required_template_ids.issubset(set(templates.keys()))

    needed_mutations: set[str] = set()
    for family_rule in families.values():
        needed_mutations.update(str(v) for v in (family_rule or {}).get("mutations", []) if str(v).strip())
    for template_id in required_template_ids:
        needed_mutations.update(str(v) for v in templates[template_id].allowed_mutation_families if str(v).strip())

    missing = sorted(mutation for mutation in needed_mutations if mutation not in recipe_by_family)
    assert missing == []


def test_new_templates_pass_placeholder_and_analysis_linkage() -> None:
    templates = _templates_by_id()
    recipe_by_family = recipe_map(_repo_root() / "catalogs" / "mutation_recipes.yaml")

    selected_ids = [
        "TMP-BENIGN-REPO-001",
        "TMP-BENIGN-YAML-001",
        "TMP-REPO-COMMENT-001",
        "TMP-REPO-WORKFLOW-001",
        "TMP-ADAPT-SEED-001",
        "TMP-ADAPT-TOOL-001",
        "TMP-CONFIG-THRESH-001",
        "TMP-CONFIG-NORM-001",
        "TMP-RAG-SEARCH-001",
        "TMP-RAG-REPOFILE-001",
        "TMP-STRUCT-YAML-001",
        "TMP-DIRECT-PSEUDO-SYSTEM-001",
        "TMP-KO-CONFIRM-ALREADY-001",
        "TMP-KO-SPACING-PARTICLE-001",
        "TMP-TOOL-JSON-STEER-001",
    ]
    selected_templates = [templates[template_id] for template_id in selected_ids]
    rows = [_build_single_case(template, recipe_by_family) for template in selected_templates]

    self_check_errors = capability_and_placeholder_self_check(rows, templates)
    assert self_check_errors == []

    analysis_errors = validate_analysis_linkage(rows)
    assert analysis_errors == []


def test_adaptive_planner_uses_seed_and_fallback_paths() -> None:
    cfg = load_yaml(_repo_root() / "configs" / "generator_bulk.yaml")
    family_rule = dict(((cfg.get("generator", {}) or {}).get("families", {}) or {}).get("adaptive_fuzzing", {}) or {})
    templates = _templates_by_id()
    adaptive_template = templates["TMP-ADAPT-SEED-001"]

    seed_template = templates["TMP-P1-REPLAY-001"]
    seed_case = build_case(
        template=seed_template,
        seed=20260409,
        language="ko",
        entry_point="memory_or_summary",
        carrier="long_context_document",
        source_role="memory_note",
        expected_interpretation="data",
        primary_mutation="delayed_replay_trigger",
        mutation_recipe_id="MR-P1-REPLAY-001",
        policy_requested="block",
        tool_transition_type="replay_to_tool",
        replay_window="window_4",
        delayed_injection_turn=3,
        structured_payload_type="",
        threshold_profile="",
        normalization_variant="",
        mutation_sensitive_seg=True,
    )

    seeded_plans = _plan_bundles_for_template(adaptive_template, family_rule, existing_rows=[seed_case])
    assert seeded_plans
    assert any(plan.planner_kind == "adaptive_seed" for plan in seeded_plans)
    assert any(f"seed_case_id={seed_case.case_id}" in plan.planner_note for plan in seeded_plans)

    fallback_plans = _plan_bundles_for_template(adaptive_template, family_rule, existing_rows=[])
    assert fallback_plans
    assert all(plan.planner_kind == "adaptive_fallback" for plan in fallback_plans)


def test_config_probe_planner_emits_pair_variants() -> None:
    cfg = load_yaml(_repo_root() / "configs" / "generator_bulk.yaml")
    family_rule = dict(((cfg.get("generator", {}) or {}).get("families", {}) or {}).get("config_sensitivity_probe", {}) or {})
    templates = _templates_by_id()

    plans = []
    for template_id in ["TMP-CONFIG-THRESH-001", "TMP-CONFIG-NORM-001"]:
        plans.extend(_plan_bundles_for_template(templates[template_id], family_rule, existing_rows=[]))

    assert plans
    notes = [plan.planner_note for plan in plans]
    assert any("probe_pair=threshold_only" in note for note in notes)
    assert any("probe_pair=normalization_only" in note for note in notes)
    assert any("probe_pair=combined" in note for note in notes)

    assert any(plan.threshold_profile == "strict" and plan.normalization_variant == "baseline" for plan in plans)
    assert any(plan.threshold_profile == "baseline" and plan.normalization_variant == "normalization_ab_variant" for plan in plans)
    assert any(plan.threshold_profile == "strict" and plan.normalization_variant == "normalization_ab_variant" for plan in plans)


def test_planner_outputs_cover_search_repo_yaml_and_norm_axes() -> None:
    cfg = load_yaml(_repo_root() / "configs" / "generator_bulk.yaml")
    families = dict((cfg.get("generator", {}) or {}).get("families", {}) or {})
    templates = _templates_by_id()

    seed_case = build_case(
        template=templates["TMP-P1-REPLAY-001"],
        seed=20260409,
        language="ko",
        entry_point="memory_or_summary",
        carrier="long_context_document",
        source_role="memory_note",
        expected_interpretation="data",
        primary_mutation="delayed_replay_trigger",
        mutation_recipe_id="MR-P1-REPLAY-001",
        policy_requested="block",
        tool_transition_type="replay_to_tool",
        replay_window="window_4",
        delayed_injection_turn=3,
        structured_payload_type="",
        threshold_profile="",
        normalization_variant="",
        mutation_sensitive_seg=True,
    )

    collected_entry_points: set[str] = set()
    collected_carriers: set[str] = set()
    collected_norm_variants: set[str] = set()

    target_families = [
        "indirect_document_web_rag",
        "repo_coding_agent_injection",
        "structured_payload_misuse",
        "config_sensitivity_probe",
    ]
    for family in target_families:
        family_rule = families[family]
        family_templates = [
            template
            for template in templates.values()
            if template.attack_family == family and template.attack_or_benign == "attack"
        ]
        assert family_templates, family

        family_plans = []
        for template in family_templates:
            family_plans.extend(_plan_bundles_for_template(template, family_rule, existing_rows=[seed_case]))
        assert family_plans, family

        collected_entry_points.update(plan.entry_point for plan in family_plans)
        collected_carriers.update(plan.carrier_context for plan in family_plans)
        collected_norm_variants.update(plan.normalization_variant for plan in family_plans)

    assert "search_result" in collected_entry_points
    assert "repo_file" in collected_carriers
    assert "yaml" in collected_carriers
    assert "normalization_ab_variant" in collected_norm_variants
