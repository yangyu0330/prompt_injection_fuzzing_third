import json
from pathlib import Path

from pi_fuzzer.cli import _resolve_score_coverage_summary
from pi_fuzzer.models import CaseRecord, TemplateRecord


def _template() -> TemplateRecord:
    return TemplateRecord(
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


def _case() -> CaseRecord:
    return CaseRecord(
        template_id="TMP-1",
        case_id="CASE-1",
        language="ko",
        attack_or_benign="attack",
        attack_family="direct_user_injection",
        attack_subfamily="x",
        directness="direct",
        source_stage="input",
        source_role="user",
        expected_interpretation="instruction",
        turn_mode="single_turn",
        entry_point="user_prompt",
        carrier_context="plain_chat",
        mutation_family=[],
        user_goal="<U>",
        trusted_instruction="<T>",
        untrusted_content="<X>",
        protected_asset=["policy"],
        forbidden_action=["deny"],
        expected_safe_behavior="<E>",
        tool_scope="none",
        oracle_type=["task_checker"],
        severity="S2",
        split="heldout_static",
        source_origin="test",
        semantic_equivalence_group="SEG-1",
    )


def _write_package(package_dir: Path) -> None:
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "templates.jsonl").write_text(
        json.dumps(_template().model_dump(), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (package_dir / "cases.jsonl").write_text(
        json.dumps(_case().model_dump(), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def test_score_coverage_summary_without_config_is_not_evaluated(tmp_path: Path) -> None:
    summary = _resolve_score_coverage_summary(package=tmp_path, config=None)
    assert summary["checked"] is False
    assert summary["passed"] is None
    assert summary["note"] == "coverage_not_evaluated_in_score"


def test_score_coverage_summary_uses_validate_result(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    _write_package(package_dir)

    cfg_path = tmp_path / "release_cfg.yaml"
    cfg_path.write_text(
        "build:\n  mode: release\ncoverage_gate:\n  enabled: true\n  profiles:\n    - name: strict\n      required_dims:\n        - source_stage\n      min_per_cell: 2\n",
        encoding="utf-8",
    )

    summary = _resolve_score_coverage_summary(package=package_dir, config=cfg_path)
    assert summary["checked"] is True
    assert summary["passed"] is False
    assert summary["validation_ok"] is False
    assert len(summary["violations"]) == 1
