import json
from pathlib import Path

from pi_fuzzer.build import _resolve_coverage_profiles, _run_coverage_gate, validate_package
from pi_fuzzer.models import CaseRecord, TemplateRecord


def _case(case_id: str, source_stage: str, entry_point: str, turn_mode: str = "multi_turn") -> CaseRecord:
    return CaseRecord(
        template_id="TMP",
        case_id=case_id,
        language="ko",
        attack_or_benign="attack",
        attack_family="tool_agent_misuse",
        attack_subfamily="x",
        directness="indirect",
        source_stage=source_stage,
        source_role="tool_output" if entry_point == "tool_output" else "memory_note",
        expected_interpretation="data",
        turn_mode=turn_mode,
        entry_point=entry_point,
        carrier_context="json",
        mutation_family=[],
        user_goal="<U>",
        trusted_instruction="<T>",
        untrusted_content="<X>",
        protected_asset=[],
        forbidden_action=[],
        expected_safe_behavior="<E>",
        tool_scope="none",
        oracle_type=[],
        severity="S2",
        split="heldout_static",
        source_origin="test",
        semantic_equivalence_group=f"SEG-{case_id}",
        tool_transition_type="replay_to_tool" if source_stage == "replay" else "user_to_tool",
    )


def test_resolve_coverage_profiles_from_matrix() -> None:
    cfg = {
        "coverage_gate": {
            "enabled": True,
            "matrix_path": "catalogs/coverage_matrix.yaml",
            "profiles": ["p0_stage_role", "p1_replay_tool_transition"],
        }
    }
    profiles = _resolve_coverage_profiles(cfg, Path.cwd())
    names = {p["name"] for p in profiles}
    assert "p0_stage_role" in names
    assert "p1_replay_tool_transition" in names


def test_run_coverage_gate_enforces_required_values() -> None:
    cfg = {
        "coverage_gate": {
            "enabled": True,
            "matrix_path": "catalogs/coverage_matrix.yaml",
            "profiles": ["p1_replay_tool_transition"],
        }
    }
    profiles = _resolve_coverage_profiles(cfg, Path.cwd())

    rows = [_case("A", source_stage="tool_input", entry_point="tool_output")]
    violations = _run_coverage_gate(rows, profiles=profiles, splits={"heldout_static"})
    assert any(v["kind"] == "required_value" and v["key"] == ["source_stage", "replay"] for v in violations)


def test_run_coverage_gate_enforces_required_combinations() -> None:
    profiles = [
        {
            "name": "combo",
            "required_dims": [],
            "min_per_cell": 1,
            "required_combinations": [
                {"source_stage": "replay", "source_role": "memory_note", "min_count": 1},
            ],
        }
    ]
    rows = [_case("A", source_stage="tool_input", entry_point="tool_output")]
    violations = _run_coverage_gate(rows, profiles=profiles, splits={"heldout_static"})
    assert any(v["kind"] == "required_combination" for v in violations)


def test_validate_package_uses_release_split_scope_for_coverage(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir(parents=True, exist_ok=True)

    template = TemplateRecord(
        template_id="TMP-1",
        template_kind="diagnostic_attack",
        attack_or_benign="attack",
        attack_family="direct_user_injection",
        attack_subfamily="x",
        directness="direct",
        source_stage="input",
        turn_mode="single_turn",
        supported_entry_points=["user_prompt"],
        supported_carriers=["plain_chat"],
        user_goal_skeleton="<U>",
        trusted_instruction_skeleton="<T>",
        untrusted_content_skeleton="<X>",
        protected_asset=["policy"],
        forbidden_action=["deny"],
        expected_safe_behavior="<E>",
        tool_scope="none",
        oracle_type=["task_checker"],
        severity="S2",
        recommended_layer=["L1"],
        semantic_equivalence_group="SEG-TMP",
        source_origin="test",
        license_note="internal_curated",
        redistribution_policy="release_export_allowed",
    )
    (package_dir / "templates.jsonl").write_text(
        json.dumps(template.model_dump(), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    held_1 = _case("H1", source_stage="replay", entry_point="memory_or_summary")
    held_1.split = "heldout_static"
    held_1.semantic_equivalence_group = "SEG-H1"
    held_1.source_role = "memory_note"
    held_1.expected_interpretation = "data"
    held_1.template_id = "TMP-1"
    held_1.entry_point = "memory_or_summary"

    held_2 = _case("H2", source_stage="replay", entry_point="memory_or_summary")
    held_2.split = "adaptive"
    held_2.semantic_equivalence_group = "SEG-H2"
    held_2.source_role = "memory_note"
    held_2.expected_interpretation = "data"
    held_2.template_id = "TMP-1"
    held_2.entry_point = "memory_or_summary"

    dev_row = _case("D1", source_stage="input", entry_point="user_prompt", turn_mode="single_turn")
    dev_row.split = "dev_calibration"
    dev_row.semantic_equivalence_group = "SEG-D1"
    dev_row.source_role = "user"
    dev_row.expected_interpretation = "instruction"
    dev_row.template_id = "TMP-1"

    case_lines = [held_1.model_dump(), held_2.model_dump(), dev_row.model_dump()]
    (package_dir / "cases.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in case_lines) + "\n",
        encoding="utf-8",
    )

    cfg_path = tmp_path / "release_cfg.yaml"
    cfg_path.write_text(
        "build:\n  mode: release\ncoverage_gate:\n  enabled: true\n  profiles:\n    - name: parity\n      required_dims:\n        - source_stage\n      min_per_cell: 2\n",
        encoding="utf-8",
    )

    result = validate_package(package_dir=package_dir, config_path=cfg_path)
    assert result["ok"] is True
    assert result["coverage"]["split_scope"] == ["adaptive", "heldout_static"]
