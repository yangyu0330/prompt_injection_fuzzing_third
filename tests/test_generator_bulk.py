from __future__ import annotations

import json
from pathlib import Path

import pytest

from pi_fuzzer.generator import generate_cases
from pi_fuzzer.generator_bulk import _build_context, _prepare_manifest
from pi_fuzzer.io_utils import read_json, read_jsonl


def _template_row(
    template_id: str,
    attack_family: str,
    *,
    template_kind: str = "diagnostic_attack",
    attack_or_benign: str = "attack",
    source_stage: str = "tool_output",
    turn_mode: str = "multi_turn",
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
        "directness": "indirect",
        "source_stage": source_stage,
        "turn_mode": turn_mode,
        "supported_entry_points": supported_entry_points or ["tool_output"],
        "supported_carriers": supported_carriers or ["tool_result"],
        "user_goal_skeleton": "<SAFE_TASK_PLACEHOLDER>",
        "trusted_instruction_skeleton": "<TRUSTED_INSTRUCTION_PLACEHOLDER>",
        "untrusted_content_skeleton": "<UNTRUSTED_CONTENT_PLACEHOLDER>",
        "protected_asset": ["system_prompt"],
        "forbidden_action": ["reveal_system_prompt"],
        "expected_safe_behavior": "<EXPECTED_SAFE_BEHAVIOR_PLACEHOLDER>",
        "tool_scope": "none",
        "oracle_type": ["task_checker"],
        "severity": "S2",
        "recommended_layer": ["L2"],
        "semantic_equivalence_group": "SEG-TEMPLATE",
        "allowed_mutation_families": allowed_mutation_families or ["mut_tool"],
        "supported_source_roles": supported_source_roles or ["tool_output"],
        "supported_expected_interpretations": supported_expected_interpretations or ["data"],
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _write_build_config(path: Path, export_rel: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "build:",
                "  seed: 20260403",
                "  mode: dev",
                "template_sources:",
                "  - catalogs/templates.jsonl",
                "case_sources:",
                f"  - {export_rel}",
                "split:",
                "  targets:",
                "    dev_calibration: 1.0",
                "dedup:",
                "  mode: structured_only",
                "  similarity_threshold: 0.92",
                "coverage_gate:",
                "  profiles:",
                "    - name: role_requirements",
                "      required_dims: [source_role]",
                "      min_per_cell: 1",
                "      required_values:",
                "        source_role:",
                "          values: [tool_output]",
                "          min_per_value: 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_bulk_config(path: Path, build_cfg_rel: str, *, seed: int = 20260409, max_passes: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "generator:",
                "  mode: bulk",
                f"  seed: {seed}",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  survivor_target: 1",
                f"  max_passes: {max_passes}",
                "  output:",
                "    out_dir: catalogs/generated_bulk",
                "    export_jsonl: catalogs/generated_cases.jsonl",
                "    max_rows_per_shard: 100",
                "  preflight:",
                "    enabled: true",
                f"    build_config: {build_cfg_rel}",
                "    fail_on_survivor_shortfall: true",
                "  dedup_index:",
                "    enabled: true",
                "    path: catalogs/generated_bulk/indexes",
                "  contrast_policy:",
                "    defaults:",
                "      bilingual_pairing: true",
                "      require_benign: false",
                "    families:",
                "      tool_agent_misuse:",
                "        require_benign: true",
                "        benign_template_pool:",
                "          - template_id: TMP-BENIGN",
                "            when:",
                "              source_role: [tool_output]",
                "              expected_interpretation: [data]",
                "  refill:",
                "    enabled: true",
                "    driving_profiles: [role_requirements]",
                "    min_new_survivors_per_pass: 0",
                "  families:",
                "    tool_agent_misuse:",
                "      target_survivors: 1",
                "      max_raw_rows: 20",
                "      max_bundles: 10",
                "      priority: 100",
                "      languages: [ko, en]",
                "      entry_points: [tool_output]",
                "      carriers: [tool_result]",
                "      source_roles: [tool_output]",
                "      expected_interpretations: [data]",
                "      mutations: [mut_tool]",
                "      tool_transition_types: [user_to_tool]",
                "      policy_requested: [annotate]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _setup_bulk_fixture(tmp_path: Path, *, seed: int = 20260409, max_passes: int = 2, export_rel: str = "catalogs/custom_export.jsonl") -> tuple[Path, Path]:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(
        templates_path,
        [
            _template_row(
                template_id="TMP-ATTACK",
                attack_family="tool_agent_misuse",
                supported_entry_points=["tool_output"],
                supported_carriers=["tool_result"],
                allowed_mutation_families=["mut_tool"],
                supported_source_roles=["tool_output"],
                supported_expected_interpretations=["data"],
            ),
            _template_row(
                template_id="TMP-BENIGN",
                attack_family="benign_hard_negative",
                template_kind="benign_hard_negative",
                attack_or_benign="benign",
                source_stage="input",
                turn_mode="single_turn",
                supported_entry_points=["tool_output", "user_prompt"],
                supported_carriers=["tool_result", "plain_chat"],
                allowed_mutation_families=["quote_wrapper"],
                supported_source_roles=["tool_output", "user"],
                supported_expected_interpretations=["data", "instruction"],
            ),
        ],
    )

    _write_mutation_recipes(tmp_path / "catalogs" / "mutation_recipes.yaml", families=["mut_tool", "quote_wrapper"])
    build_cfg = tmp_path / "configs" / "build_generated_dev.yaml"
    _write_build_config(build_cfg, export_rel=export_rel)
    bulk_cfg = tmp_path / "configs" / "generator_bulk.yaml"
    _write_bulk_config(
        bulk_cfg,
        build_cfg_rel=build_cfg.relative_to(tmp_path).as_posix(),
        seed=seed,
        max_passes=max_passes,
    )
    return templates_path, bulk_cfg


def test_bulk_mode_creates_dirs_and_export_with_out_override(tmp_path: Path) -> None:
    templates, bulk_cfg = _setup_bulk_fixture(tmp_path)
    out_override = tmp_path / "catalogs" / "custom_export.jsonl"

    summary = generate_cases(
        [templates],
        config_path=bulk_cfg,
        out_path=out_override,
        project_root=tmp_path,
    )

    assert summary["status"].startswith("success")
    assert out_override.exists()
    manifest = read_json(tmp_path / "catalogs" / "generated_bulk" / "manifest.json")
    assert manifest["output"]["export_jsonl"] == "catalogs/custom_export.jsonl"
    assert manifest["completed_passes"]
    assert (tmp_path / "catalogs" / "generated_bulk" / "shards").exists()
    assert read_jsonl(out_override)


def test_bulk_resume_reuses_existing_state_without_new_rows(tmp_path: Path) -> None:
    templates, bulk_cfg = _setup_bulk_fixture(tmp_path, max_passes=2)
    out_override = tmp_path / "catalogs" / "custom_export.jsonl"

    first = generate_cases(
        [templates],
        config_path=bulk_cfg,
        out_path=out_override,
        project_root=tmp_path,
    )
    rows_first = read_jsonl(out_override)

    second = generate_cases(
        [templates],
        config_path=bulk_cfg,
        out_path=out_override,
        project_root=tmp_path,
        resume=True,
    )
    rows_second = read_jsonl(out_override)

    assert first["status"].startswith("success")
    assert second["status"].startswith("success")
    assert second["reason"] == "target_met"
    assert rows_first == rows_second


def test_bulk_resume_rebuilds_stale_export_from_committed_shards(tmp_path: Path) -> None:
    templates, bulk_cfg = _setup_bulk_fixture(tmp_path, max_passes=2)
    out_override = tmp_path / "catalogs" / "custom_export.jsonl"

    generate_cases(
        [templates],
        config_path=bulk_cfg,
        out_path=out_override,
        project_root=tmp_path,
    )
    expected_rows = read_jsonl(out_override)

    # Corrupt derived export intentionally. Resume should rebuild from committed shards.
    out_override.write_text("", encoding="utf-8")
    summary = generate_cases(
        [templates],
        config_path=bulk_cfg,
        out_path=out_override,
        project_root=tmp_path,
        resume=True,
    )

    assert summary["status"].startswith("success")
    assert summary["reason"] == "target_met"
    assert read_jsonl(out_override) == expected_rows


def test_prepare_manifest_resume_uses_manifest_shards_only(tmp_path: Path) -> None:
    templates, bulk_cfg = _setup_bulk_fixture(tmp_path, max_passes=2)
    out_override = tmp_path / "catalogs" / "custom_export.jsonl"
    generate_cases(
        [templates],
        config_path=bulk_cfg,
        out_path=out_override,
        project_root=tmp_path,
    )

    manifest_path = tmp_path / "catalogs" / "generated_bulk" / "manifest.json"
    manifest = read_json(manifest_path)
    assert manifest["shards"]
    manifest["shards"] = []
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    stray_shard = tmp_path / "catalogs" / "generated_bulk" / "shards" / "family=tool_agent_misuse" / "part-9999.jsonl"
    _write_jsonl(stray_shard, [{"case_id": "CASE-STRAY"}])

    ctx = _build_context(
        template_sources=[templates],
        config_path=bulk_cfg,
        out_override=out_override,
        project_root=tmp_path,
    )
    _manifest, shard_relpaths, _fps = _prepare_manifest(
        ctx=ctx,
        template_sources=[templates],
        resume=True,
    )
    assert shard_relpaths == []


def test_bulk_without_resume_rejects_existing_state(tmp_path: Path) -> None:
    templates, bulk_cfg = _setup_bulk_fixture(tmp_path)
    out_override = tmp_path / "catalogs" / "custom_export.jsonl"
    generate_cases([templates], config_path=bulk_cfg, out_path=out_override, project_root=tmp_path)

    with pytest.raises(ValueError, match="already has state"):
        generate_cases([templates], config_path=bulk_cfg, out_path=out_override, project_root=tmp_path)


def test_bulk_resume_fingerprint_mismatch_returns_failed_config_mismatch(tmp_path: Path) -> None:
    templates, bulk_cfg = _setup_bulk_fixture(tmp_path, seed=20260409)
    out_override = tmp_path / "catalogs" / "custom_export.jsonl"
    generate_cases([templates], config_path=bulk_cfg, out_path=out_override, project_root=tmp_path)

    _write_bulk_config(
        bulk_cfg,
        build_cfg_rel="configs/build_generated_dev.yaml",
        seed=20260410,
        max_passes=2,
    )

    summary = generate_cases(
        [templates],
        config_path=bulk_cfg,
        out_path=out_override,
        project_root=tmp_path,
        resume=True,
    )
    assert summary["status"] == "failed_config_mismatch"


def test_mvp_mode_rejects_resume(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(
        templates_path,
        [_template_row(template_id="TMP-A", attack_family="tool_agent_misuse", source_stage="input", turn_mode="single_turn")],
    )
    _write_mutation_recipes(tmp_path / "catalogs" / "mutation_recipes.yaml", families=["mut_tool"])
    mvp_cfg = tmp_path / "configs" / "generator_mvp.yaml"
    mvp_cfg.parent.mkdir(parents=True, exist_ok=True)
    mvp_cfg.write_text(
        "\n".join(
            [
                "generator:",
                "  mode: mvp",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  coverage_preflight:",
                "    enabled: false",
                "  families:",
                "    tool_agent_misuse:",
                "      languages: [ko]",
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

    with pytest.raises(ValueError, match="only valid when generator.mode=bulk"):
        generate_cases(
            [templates_path],
            config_path=mvp_cfg,
            out_path=tmp_path / "catalogs" / "generated_cases.jsonl",
            project_root=tmp_path,
            resume=True,
        )


def test_bulk_shortfall_without_family_targets_is_not_reported_as_success(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(
        templates_path,
        [
            _template_row(
                template_id="TMP-A",
                attack_family="tool_agent_misuse",
                supported_entry_points=["tool_output"],
                supported_carriers=["tool_result"],
                allowed_mutation_families=["mut_tool"],
                supported_source_roles=["tool_output"],
                supported_expected_interpretations=["data"],
            )
        ],
    )
    _write_mutation_recipes(tmp_path / "catalogs" / "mutation_recipes.yaml", families=["mut_tool"])

    build_cfg = tmp_path / "configs" / "build_generated_dev.yaml"
    _write_build_config(build_cfg, export_rel="catalogs/generated_cases.jsonl")

    bulk_cfg = tmp_path / "configs" / "generator_bulk.yaml"
    bulk_cfg.parent.mkdir(parents=True, exist_ok=True)
    bulk_cfg.write_text(
        "\n".join(
            [
                "generator:",
                "  mode: bulk",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  survivor_target: 5",
                "  max_passes: 1",
                "  output:",
                "    out_dir: catalogs/generated_bulk",
                "    export_jsonl: catalogs/generated_cases.jsonl",
                "  preflight:",
                "    enabled: true",
                "    build_config: configs/build_generated_dev.yaml",
                "    fail_on_survivor_shortfall: true",
                "  families: {}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    summary = generate_cases(
        [templates_path],
        config_path=bulk_cfg,
        out_path=tmp_path / "catalogs" / "generated_cases.jsonl",
        project_root=tmp_path,
    )
    assert summary["status"] == "failed_survivor_shortfall"


def test_bulk_runtime_failure_flushes_summary_and_manifest(tmp_path: Path) -> None:
    templates, bulk_cfg = _setup_bulk_fixture(tmp_path)
    out_override = tmp_path / "catalogs" / "custom_export.jsonl"

    # Break preflight contract intentionally: build config must include export_jsonl in case_sources.
    bad_build_cfg = tmp_path / "configs" / "build_generated_dev.yaml"
    bad_build_cfg.write_text(
        "\n".join(
            [
                "build:",
                "  seed: 20260403",
                "  mode: dev",
                "case_sources:",
                "  - catalogs/not_export.jsonl",
                "coverage_gate:",
                "  enabled: false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="bulk preflight contract mismatch"):
        generate_cases(
            [templates],
            config_path=bulk_cfg,
            out_path=out_override,
            project_root=tmp_path,
        )

    manifest = read_json(tmp_path / "catalogs" / "generated_bulk" / "manifest.json")
    summary = read_json(tmp_path / "catalogs" / "generated_bulk" / "summary.json")
    assert manifest["status"] == "failed_runtime"
    assert summary["status"] == "failed_runtime"


def test_bulk_allows_same_exact_payload_when_structural_envelope_differs(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(
        templates_path,
        [
            _template_row(
                template_id="TMP-ATTACK-A",
                attack_family="tool_agent_misuse",
                supported_entry_points=["tool_output"],
                supported_carriers=["tool_result"],
                allowed_mutation_families=["mut_tool"],
                supported_source_roles=["tool_output"],
                supported_expected_interpretations=["data"],
            ),
            _template_row(
                template_id="TMP-ATTACK-B",
                attack_family="tool_agent_misuse",
                supported_entry_points=["tool_output"],
                supported_carriers=["tool_result"],
                allowed_mutation_families=["mut_tool"],
                supported_source_roles=["tool_output"],
                supported_expected_interpretations=["data"],
            ),
            _template_row(
                template_id="TMP-BENIGN",
                attack_family="benign_hard_negative",
                template_kind="benign_hard_negative",
                attack_or_benign="benign",
                source_stage="input",
                turn_mode="single_turn",
                supported_entry_points=["tool_output", "user_prompt"],
                supported_carriers=["tool_result", "plain_chat"],
                allowed_mutation_families=["quote_wrapper"],
                supported_source_roles=["tool_output", "user"],
                supported_expected_interpretations=["data", "instruction"],
            ),
        ],
    )
    _write_mutation_recipes(tmp_path / "catalogs" / "mutation_recipes.yaml", families=["mut_tool", "quote_wrapper"])

    build_cfg = tmp_path / "configs" / "build_generated_dev.yaml"
    _write_build_config(build_cfg, export_rel="catalogs/generated_cases.jsonl")

    bulk_cfg = tmp_path / "configs" / "generator_bulk.yaml"
    bulk_cfg.parent.mkdir(parents=True, exist_ok=True)
    bulk_cfg.write_text(
        "\n".join(
            [
                "generator:",
                "  mode: bulk",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  survivor_target: 0",
                "  max_passes: 1",
                "  output:",
                "    out_dir: catalogs/generated_bulk",
                "    export_jsonl: catalogs/generated_cases.jsonl",
                "  preflight:",
                "    enabled: true",
                "    build_config: configs/build_generated_dev.yaml",
                "    fail_on_survivor_shortfall: true",
                "  contrast_policy:",
                "    defaults:",
                "      bilingual_pairing: true",
                "      require_benign: false",
                "    families:",
                "      tool_agent_misuse:",
                "        require_benign: true",
                "        benign_template_pool:",
                "          - template_id: TMP-BENIGN",
                "            when:",
                "              source_role: [tool_output]",
                "              expected_interpretation: [data]",
                "  refill:",
                "    driving_profiles: [role_requirements]",
                "  families:",
                "    tool_agent_misuse:",
                "      target_survivors: 1",
                "      max_raw_rows: 100",
                "      max_bundles: 100",
                "      priority: 100",
                "      languages: [ko, en]",
                "      entry_points: [tool_output]",
                "      carriers: [tool_result]",
                "      source_roles: [tool_output]",
                "      expected_interpretations: [data]",
                "      mutations: [mut_tool]",
                "      policy_requested: [annotate]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out_path = tmp_path / "catalogs" / "generated_cases.jsonl"
    summary = generate_cases(
        [templates_path],
        config_path=bulk_cfg,
        out_path=out_path,
        project_root=tmp_path,
    )
    assert summary["status"].startswith("success")

    rows = read_jsonl(out_path)
    by_id = {r["case_id"]: r for r in rows}
    attacks = [r for r in rows if r["attack_or_benign"] == "attack"]
    benign = [r for r in rows if r["attack_or_benign"] == "benign"]
    assert attacks
    assert len(benign) >= 2

    for row in attacks:
        sibling_id = row["benign_sibling_id"]
        assert sibling_id
        sib = by_id.get(sibling_id)
        assert sib is not None
        assert sib["attack_or_benign"] == "benign"
        assert sib["contrast_group_id"] == row["contrast_group_id"]


def test_bulk_remaps_benign_sibling_when_duplicate_benign_bundle_is_dropped(tmp_path: Path) -> None:
    templates_path = tmp_path / "catalogs" / "templates.jsonl"
    _write_jsonl(
        templates_path,
        [
            _template_row(
                template_id="TMP-ATTACK",
                attack_family="tool_agent_misuse",
                supported_entry_points=["tool_output"],
                supported_carriers=["tool_result"],
                allowed_mutation_families=["mut_tool"],
                supported_source_roles=["tool_output"],
                supported_expected_interpretations=["data"],
            ),
            _template_row(
                template_id="TMP-BENIGN",
                attack_family="benign_hard_negative",
                template_kind="benign_hard_negative",
                attack_or_benign="benign",
                source_stage="input",
                turn_mode="single_turn",
                supported_entry_points=["tool_output", "user_prompt"],
                supported_carriers=["tool_result", "plain_chat"],
                allowed_mutation_families=["quote_wrapper"],
                supported_source_roles=["tool_output", "user"],
                supported_expected_interpretations=["data", "instruction"],
            ),
        ],
    )
    _write_mutation_recipes(tmp_path / "catalogs" / "mutation_recipes.yaml", families=["mut_tool", "quote_wrapper"])

    build_cfg = tmp_path / "configs" / "build_generated_dev.yaml"
    _write_build_config(build_cfg, export_rel="catalogs/generated_cases.jsonl")

    bulk_cfg = tmp_path / "configs" / "generator_bulk.yaml"
    bulk_cfg.parent.mkdir(parents=True, exist_ok=True)
    bulk_cfg.write_text(
        "\n".join(
            [
                "generator:",
                "  mode: bulk",
                "  seed: 20260409",
                "  mutation_recipe_path: catalogs/mutation_recipes.yaml",
                "  survivor_target: 0",
                "  max_passes: 1",
                "  output:",
                "    out_dir: catalogs/generated_bulk",
                "    export_jsonl: catalogs/generated_cases.jsonl",
                "  preflight:",
                "    enabled: true",
                "    build_config: configs/build_generated_dev.yaml",
                "    fail_on_survivor_shortfall: true",
                "  contrast_policy:",
                "    defaults:",
                "      bilingual_pairing: true",
                "      require_benign: false",
                "    families:",
                "      tool_agent_misuse:",
                "        require_benign: true",
                "        benign_template_pool:",
                "          - template_id: TMP-BENIGN",
                "            when:",
                "              source_role: [tool_output]",
                "              expected_interpretation: [data]",
                "  refill:",
                "    driving_profiles: [role_requirements]",
                "  families:",
                "    tool_agent_misuse:",
                "      target_survivors: 1",
                "      max_raw_rows: 100",
                "      max_bundles: 100",
                "      priority: 100",
                "      languages: [ko, en]",
                "      entry_points: [tool_output]",
                "      carriers: [tool_result]",
                "      source_roles: [tool_output]",
                "      expected_interpretations: [data]",
                "      mutations: [mut_tool]",
                "      policy_requested: [annotate, block]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out_path = tmp_path / "catalogs" / "generated_cases.jsonl"
    summary = generate_cases(
        [templates_path],
        config_path=bulk_cfg,
        out_path=out_path,
        project_root=tmp_path,
    )
    assert summary["status"].startswith("success")

    rows = read_jsonl(out_path)
    by_id = {r["case_id"]: r for r in rows}
    attacks = [r for r in rows if r["attack_or_benign"] == "attack"]
    benign = [r for r in rows if r["attack_or_benign"] == "benign"]
    assert attacks
    assert benign

    for row in attacks:
        sibling_id = row["benign_sibling_id"]
        assert sibling_id
        sibling = by_id.get(sibling_id)
        assert sibling is not None
        assert sibling["attack_or_benign"] == "benign"
        assert sibling["contrast_group_id"] == row["contrast_group_id"]
