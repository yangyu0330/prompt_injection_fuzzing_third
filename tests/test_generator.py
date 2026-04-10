from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path

import pytest

from pi_fuzzer.generator import generate_cases
from pi_fuzzer.io_utils import read_jsonl


def _template_row(
    template_id: str,
    attack_family: str,
    template_kind: str = "diagnostic_attack",
    attack_or_benign: str = "attack",
    source_stage: str = "input",
    turn_mode: str = "single_turn",
    supported_entry_points: list[str] | None = None,
    supported_carriers: list[str] | None = None,
    allowed_mutation_families: list[str] | None = None,
    supported_source_roles: list[str] | None = None,
    supported_expected_interpretations: list[str] | None = None,
) -> dict[str, object]:
    return {
        "template_id": template_id,
        "template_kind": template_kind,
        "attack_or_benign": attack_or_benign,
        "attack_family": attack_family,
        "attack_subfamily": "subfamily",
        "directness": "indirect" if source_stage != "input" else "direct",
        "source_stage": source_stage,
        "turn_mode": turn_mode,
        "supported_entry_points": supported_entry_points or ["user_prompt"],
        "supported_carriers": supported_carriers or ["plain_chat"],
        "user_goal_skeleton": "<SAFE_TASK_PLACEHOLDER>",
        "trusted_instruction_skeleton": "<TRUSTED_INSTRUCTION_PLACEHOLDER>",
        "untrusted_content_skeleton": "<UNTRUSTED_CONTENT_PLACEHOLDER>",
        "protected_asset": ["system_prompt"],
        "forbidden_action": ["reveal_system_prompt"],
        "expected_safe_behavior": "<EXPECTED_SAFE_BEHAVIOR_PLACEHOLDER>",
        "tool_scope": "none",
        "oracle_type": ["task_checker"],
        "severity": "S2",
        "recommended_layer": ["L1"],
        "semantic_equivalence_group": "SEG-TEMPLATE",
        "allowed_mutation_families": allowed_mutation_families or ["mut_a", "mut_b"],
        "supported_source_roles": supported_source_roles or ["user"],
        "supported_expected_interpretations": supported_expected_interpretations or ["instruction"],
        "source_origin": "sample_curated",
        "license_note": "internal_curated",
        "redistribution_policy": "release_export_allowed",
        "notes": "template",
    }


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")


def _write_mutation_recipes(path: Path, families: list[str]) -> None:
    rows = ["recipes:"]
    for idx, family in enumerate(families, start=1):
        rows.extend(
            [
                f"  MR-{idx:03d}:",
                f"    family: {family}",
                "    rule: <PLACEHOLDER_RULE>",
            ]
        )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_generate_cases_deterministic(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(
        templates_path,
        [_template_row(template_id="TMP-A", attack_family="family_a", allowed_mutation_families=["mut_a", "mut_b"])],
    )

    mutation_path = tmp_path / "catalogs" / "mutation_recipes.yaml"
    mutation_path.parent.mkdir(parents=True, exist_ok=True)
    _write_mutation_recipes(mutation_path, families=["mut_a", "mut_b"])

    config_path = tmp_path / "configs" / "generator.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "\n".join(
            [
                "generator:",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  coverage_preflight:",
                "    enabled: false",
                "  contrast_policy:",
                "    defaults:",
                "      bilingual_pairing: true",
                "      require_benign: false",
                "  families:",
                "    family_a:",
                "      max_cases_per_template: 20",
                "      languages: [ko, en]",
                "      entry_points: [user_prompt]",
                "      carriers: [plain_chat]",
                "      source_roles: [user]",
                "      expected_interpretations: [instruction]",
                "      mutations: [mut_a, mut_b]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out1 = tmp_path / "catalogs" / "generated_1.jsonl"
    out2 = tmp_path / "catalogs" / "generated_2.jsonl"
    summary1 = generate_cases([templates_path], config_path=config_path, out_path=out1, project_root=tmp_path)
    summary2 = generate_cases([templates_path], config_path=config_path, out_path=out2, project_root=tmp_path)

    rows1 = read_jsonl(out1)
    rows2 = read_jsonl(out2)
    assert summary1["generated_count"] == 4
    assert summary2["generated_count"] == 4
    assert [r["case_id"] for r in rows1] == [r["case_id"] for r in rows2]
    assert rows1 == rows2


def test_generate_cases_placeholder_only_violation_fails(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    row = _template_row(template_id="TMP-A", attack_family="family_a", allowed_mutation_families=["mut_a"])
    row["untrusted_content_skeleton"] = "plain text without placeholder"
    _write_jsonl(templates_path, [row])

    mutation_path = tmp_path / "catalogs" / "mutation_recipes.yaml"
    mutation_path.parent.mkdir(parents=True, exist_ok=True)
    _write_mutation_recipes(mutation_path, families=["mut_a"])

    config_path = tmp_path / "configs" / "generator.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "\n".join(
            [
                "generator:",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  coverage_preflight:",
                "    enabled: false",
                "  families:",
                "    family_a:",
                "      languages: [ko]",
                "      entry_points: [user_prompt]",
                "      carriers: [plain_chat]",
                "      source_roles: [user]",
                "      expected_interpretations: [instruction]",
                "      mutations: [mut_a]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="placeholder-style"):
        generate_cases(
            [templates_path],
            config_path=config_path,
            out_path=tmp_path / "catalogs" / "generated.jsonl",
            project_root=tmp_path,
        )


def test_generate_cases_preflight_uses_curated_plus_generated_scope(tmp_path: Path) -> None:
    curated_template = _template_row(
        template_id="TMP-CURATED",
        attack_family="curated_family",
        source_stage="input",
        supported_entry_points=["user_prompt"],
        supported_carriers=["plain_chat"],
        allowed_mutation_families=["mut_user"],
        supported_source_roles=["user"],
        supported_expected_interpretations=["instruction"],
    )
    generated_template = _template_row(
        template_id="TMP-GEN",
        attack_family="family_retrieval",
        source_stage="retrieval",
        supported_entry_points=["retrieved_document"],
        supported_carriers=["markdown"],
        allowed_mutation_families=["mut_doc"],
        supported_source_roles=["retrieved_doc"],
        supported_expected_interpretations=["data"],
    )

    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(templates_path, [curated_template, generated_template])

    curated_case = {
        "template_id": "TMP-CURATED",
        "case_id": "CASE-CURATED-1",
        "language": "ko",
        "attack_or_benign": "attack",
        "attack_family": "curated_family",
        "attack_subfamily": "sub",
        "directness": "direct",
        "source_stage": "input",
        "source_role": "user",
        "expected_interpretation": "instruction",
        "turn_mode": "single_turn",
        "entry_point": "user_prompt",
        "carrier_context": "plain_chat",
        "mutation_family": ["mut_user"],
        "user_goal": "<SAFE_TASK_PLACEHOLDER>",
        "trusted_instruction": "<TRUSTED_INSTRUCTION_PLACEHOLDER>",
        "untrusted_content": "<UNTRUSTED_CONTENT_PLACEHOLDER>",
        "protected_asset": ["system_prompt"],
        "forbidden_action": ["reveal_system_prompt"],
        "expected_safe_behavior": "<EXPECTED_SAFE_BEHAVIOR_PLACEHOLDER>",
        "tool_scope": "none",
        "oracle_type": ["task_checker"],
        "severity": "S2",
        "split": "dev_calibration",
        "source_origin": "sample_curated",
        "semantic_equivalence_group": "SEG-CURATED-1",
        "primary_mutation": "mut_user",
    }
    curated_cases_path = tmp_path / "catalogs" / "curated_cases.jsonl"
    _write_jsonl(curated_cases_path, [curated_case])

    mutation_path = tmp_path / "catalogs" / "mutation_recipes.yaml"
    mutation_path.parent.mkdir(parents=True, exist_ok=True)
    _write_mutation_recipes(mutation_path, families=["mut_doc"])

    build_cfg_path = tmp_path / "configs" / "build_generated_dev.yaml"
    build_cfg_path.parent.mkdir(parents=True, exist_ok=True)
    build_cfg_path.write_text(
        "\n".join(
            [
                "build:",
                "  seed: 20260403",
                "  mode: dev",
                "template_sources:",
                "  - catalogs/templates.jsonl",
                "case_sources:",
                "  - catalogs/curated_cases.jsonl",
                "  - catalogs/generated_cases.jsonl",
                "split:",
                "  targets:",
                "    dev_calibration: 1.0",
                "dedup:",
                "  mode: structured_only",
                "  similarity_threshold: 0.92",
                "coverage_gate:",
                "  enabled: true",
                "  profiles:",
                "    - name: role_requirements",
                "      required_dims: [source_role]",
                "      min_per_cell: 1",
                "      required_values:",
                "        source_role:",
                "          values: [user, retrieved_doc]",
                "          min_per_value: 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    generator_cfg = tmp_path / "configs" / "generator.yaml"
    generator_cfg.write_text(
        "\n".join(
            [
                "generator:",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  coverage_preflight:",
                f"    enabled: true",
                f"    build_config: {build_cfg_path.relative_to(tmp_path).as_posix()}",
                "  dedup_preflight:",
                "    min_generated_survivors: 1",
                "  families:",
                "    family_retrieval:",
                "      max_cases_per_template: 4",
                "      languages: [ko]",
                "      entry_points: [retrieved_document]",
                "      carriers: [markdown]",
                "      source_roles: [retrieved_doc]",
                "      expected_interpretations: [data]",
                "      mutations: [mut_doc]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out_path = tmp_path / "catalogs" / "generated_cases.jsonl"
    summary = generate_cases([templates_path], config_path=generator_cfg, out_path=out_path, project_root=tmp_path)
    assert summary["preflight"]["checked"] is True
    assert summary["preflight"]["coverage_violation_count"] == 0
    assert summary["preflight"]["generated_survivors_after_build_semantics"] >= 1


def test_generate_cases_require_benign_without_mapping_fails(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(
        templates_path,
        [
            _template_row(
                template_id="TMP-REPLAY",
                attack_family="replay_trajectory_injection",
                source_stage="replay",
                turn_mode="multi_turn",
                supported_entry_points=["memory_or_summary"],
                supported_carriers=["long_context_document"],
                allowed_mutation_families=["mut_replay"],
                supported_source_roles=["memory_note"],
                supported_expected_interpretations=["data"],
            )
        ],
    )

    mutation_path = tmp_path / "catalogs" / "mutation_recipes.yaml"
    mutation_path.parent.mkdir(parents=True, exist_ok=True)
    _write_mutation_recipes(mutation_path, families=["mut_replay"])

    cfg_path = tmp_path / "configs" / "generator.yaml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        "\n".join(
            [
                "generator:",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  coverage_preflight:",
                "    enabled: false",
                "  contrast_policy:",
                "    families:",
                "      replay_trajectory_injection:",
                "        require_benign: true",
                "  families:",
                "    replay_trajectory_injection:",
                "      languages: [ko]",
                "      entry_points: [memory_or_summary]",
                "      carriers: [long_context_document]",
                "      source_roles: [memory_note]",
                "      expected_interpretations: [data]",
                "      mutations: [mut_replay]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="requires benign_template_id"):
        generate_cases(
            [templates_path],
            config_path=cfg_path,
            out_path=tmp_path / "catalogs" / "generated.jsonl",
            project_root=tmp_path,
        )


def test_generate_cases_require_benign_creates_sibling_linkage(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    attack_template = _template_row(
        template_id="TMP-ATTACK",
        attack_family="tool_agent_misuse",
        source_stage="tool_output",
        turn_mode="multi_turn",
        supported_entry_points=["tool_output"],
        supported_carriers=["tool_result"],
        allowed_mutation_families=["mut_tool"],
        supported_source_roles=["tool_output"],
        supported_expected_interpretations=["data"],
    )
    benign_template = _template_row(
        template_id="TMP-BENIGN",
        attack_family="benign_hard_negative",
        template_kind="benign_hard_negative",
        attack_or_benign="benign",
        source_stage="input",
        supported_entry_points=["user_prompt", "tool_output"],
        supported_carriers=["plain_chat", "tool_result"],
        allowed_mutation_families=["quote_wrapper"],
        supported_source_roles=["user", "tool_output"],
        supported_expected_interpretations=["instruction", "data"],
    )
    _write_jsonl(templates_path, [attack_template, benign_template])

    mutation_path = tmp_path / "catalogs" / "mutation_recipes.yaml"
    mutation_path.parent.mkdir(parents=True, exist_ok=True)
    _write_mutation_recipes(mutation_path, families=["mut_tool", "quote_wrapper"])

    cfg_path = tmp_path / "configs" / "generator.yaml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        "\n".join(
            [
                "generator:",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  coverage_preflight:",
                "    enabled: false",
                "  contrast_policy:",
                "    defaults:",
                "      bilingual_pairing: true",
                "      require_benign: false",
                "    families:",
                "      tool_agent_misuse:",
                "        require_benign: true",
                "        benign_template_id: TMP-BENIGN",
                "  families:",
                "    tool_agent_misuse:",
                "      max_cases_per_template: 8",
                "      languages: [ko, en]",
                "      entry_points: [tool_output]",
                "      carriers: [tool_result]",
                "      source_roles: [tool_output]",
                "      expected_interpretations: [data]",
                "      mutations: [mut_tool]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out_path = tmp_path / "catalogs" / "generated.jsonl"
    generate_cases([templates_path], config_path=cfg_path, out_path=out_path, project_root=tmp_path)
    rows = read_jsonl(out_path)
    attacks = [r for r in rows if r["attack_family"] == "tool_agent_misuse" and r["attack_or_benign"] == "attack"]
    benign = [r for r in rows if r["template_id"] == "TMP-BENIGN" and r["attack_or_benign"] == "benign"]

    assert attacks
    assert benign
    benign_id = benign[0]["case_id"]
    benign_group = benign[0]["contrast_group_id"]
    for row in attacks:
        assert row["benign_sibling_id"] == benign_id
        assert row["contrast_group_id"] == benign_group


def test_generate_cases_require_benign_links_per_contrast_group(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    attack_template = _template_row(
        template_id="TMP-ATTACK",
        attack_family="tool_agent_misuse",
        source_stage="tool_output",
        turn_mode="multi_turn",
        supported_entry_points=["tool_output"],
        supported_carriers=["tool_result", "json"],
        allowed_mutation_families=["mut_tool"],
        supported_source_roles=["tool_output"],
        supported_expected_interpretations=["data"],
    )
    benign_template = _template_row(
        template_id="TMP-BENIGN",
        attack_family="benign_hard_negative",
        template_kind="benign_hard_negative",
        attack_or_benign="benign",
        source_stage="input",
        supported_entry_points=["user_prompt", "tool_output"],
        supported_carriers=["plain_chat", "tool_result", "json"],
        allowed_mutation_families=["quote_wrapper"],
        supported_source_roles=["user", "tool_output"],
        supported_expected_interpretations=["instruction", "data"],
    )
    _write_jsonl(templates_path, [attack_template, benign_template])

    mutation_path = tmp_path / "catalogs" / "mutation_recipes.yaml"
    mutation_path.parent.mkdir(parents=True, exist_ok=True)
    _write_mutation_recipes(mutation_path, families=["mut_tool", "quote_wrapper"])

    cfg_path = tmp_path / "configs" / "generator.yaml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        "\n".join(
            [
                "generator:",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  coverage_preflight:",
                "    enabled: false",
                "  contrast_policy:",
                "    defaults:",
                "      bilingual_pairing: true",
                "      require_benign: false",
                "    families:",
                "      tool_agent_misuse:",
                "        require_benign: true",
                "        benign_template_id: TMP-BENIGN",
                "  families:",
                "    tool_agent_misuse:",
                "      max_cases_per_template: 32",
                "      languages: [ko, en]",
                "      entry_points: [tool_output]",
                "      carriers: [tool_result, json]",
                "      source_roles: [tool_output]",
                "      expected_interpretations: [data]",
                "      mutations: [mut_tool]",
                "      policy_requested: [annotate, block]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out_path = tmp_path / "catalogs" / "generated.jsonl"
    generate_cases([templates_path], config_path=cfg_path, out_path=out_path, project_root=tmp_path)
    rows = read_jsonl(out_path)

    by_id = {r["case_id"]: r for r in rows}
    attack_rows = [r for r in rows if r["attack_family"] == "tool_agent_misuse" and r["attack_or_benign"] == "attack"]
    assert attack_rows

    attack_groups: dict[str, int] = defaultdict(int)
    benign_groups: set[str] = set()
    for row in attack_rows:
        gid = row["contrast_group_id"]
        attack_groups[gid] += 1
        sibling_id = row["benign_sibling_id"]
        assert sibling_id
        sibling = by_id.get(sibling_id)
        assert sibling is not None
        assert sibling["attack_or_benign"] == "benign"
        assert sibling["contrast_group_id"] == gid
        benign_groups.add(sibling["contrast_group_id"])

    assert len(attack_groups) >= 2
    assert benign_groups == set(attack_groups.keys())
