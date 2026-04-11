from __future__ import annotations

from pi_fuzzer.models import CaseRecord
from pi_fuzzer.runtime_render import (
    render_runtime_trusted_instruction,
    render_runtime_untrusted_input,
)


def _case(
    *,
    case_id: str,
    language: str,
    attack_or_benign: str,
    attack_family: str = "direct_user_injection",
    attack_subfamily: str = "direct_override",
    mutation_family: list[str] | None = None,
    trusted_instruction: str = "<TRUSTED_INSTRUCTION_PLACEHOLDER>",
    untrusted_content: str = "<UNTRUSTED_CONTENT_PLACEHOLDER>",
) -> CaseRecord:
    return CaseRecord(
        template_id="TMP",
        case_id=case_id,
        language=language,
        attack_or_benign=attack_or_benign,  # type: ignore[arg-type]
        attack_family=attack_family,
        attack_subfamily=attack_subfamily,
        directness="direct",
        source_stage="input",
        turn_mode="single_turn",
        entry_point="user_prompt",
        carrier_context="plain_chat",
        mutation_family=mutation_family or [],
        user_goal="<SAFE_TASK_PLACEHOLDER>",
        trusted_instruction=trusted_instruction,
        untrusted_content=untrusted_content,
        protected_asset=[],
        forbidden_action=[],
        expected_safe_behavior="<EXPECTED_SAFE_BEHAVIOR_PLACEHOLDER>",
        tool_scope="none",
        oracle_type=[],
        severity="S2",
        split="dev_calibration",
        source_origin="test",
        semantic_equivalence_group="SEG",
    )


def test_render_runtime_untrusted_attack_placeholder_has_case_metadata() -> None:
    case = _case(
        case_id="CASE-EN-ATTACK-001",
        language="en",
        attack_or_benign="attack",
    )
    rendered = render_runtime_untrusted_input(case)
    assert "[fam:" in rendered
    assert "CASE-EN-ATTACK-001" not in rendered
    assert "stage:input" in rendered


def test_render_runtime_untrusted_ko_attack_varies_by_case_id() -> None:
    case_a = _case(
        case_id="CASE-KO-ATTACK-A",
        language="ko",
        attack_or_benign="attack",
        attack_family="ko_native_mutation_layer",
        attack_subfamily="choseong_obfuscation",
        mutation_family=["choseong"],
    )
    case_b = _case(
        case_id="CASE-KO-ATTACK-B",
        language="ko",
        attack_or_benign="attack",
        attack_family="ko_native_mutation_layer",
        attack_subfamily="choseong_obfuscation",
        mutation_family=["choseong"],
    )
    rendered_a = render_runtime_untrusted_input(case_a)
    rendered_b = render_runtime_untrusted_input(case_b)
    assert rendered_a != rendered_b
    assert "family=ko_native_mutation_layer" in rendered_a
    assert "family=ko_native_mutation_layer" in rendered_b


def test_render_runtime_untrusted_ko_attack_reflects_subfamily() -> None:
    case = _case(
        case_id="CASE-KO-SVC-001",
        language="ko",
        attack_or_benign="attack",
        attack_family="korean_service_context",
        attack_subfamily="table_csv_cell_injection",
        mutation_family=["table_csv_cell_injection"],
    )
    rendered = render_runtime_untrusted_input(case)
    assert "sub=table_csv_cell_injection" in rendered
    assert "carrier=plain_chat" in rendered


def test_render_runtime_untrusted_benign_placeholder_has_safe_marker() -> None:
    case = _case(
        case_id="CASE-KO-BENIGN-001",
        language="ko",
        attack_or_benign="benign",
    )
    rendered = render_runtime_untrusted_input(case)
    assert "[safe-case=CASE-KO-BENIGN-001]" in rendered
    assert "Ignore previous" not in rendered


def test_render_runtime_does_not_change_non_placeholder_text() -> None:
    case = _case(
        case_id="CASE-EN-NONPH-001",
        language="en",
        attack_or_benign="attack",
        trusted_instruction="Use policy A.",
        untrusted_content="Normal user question.",
    )
    assert render_runtime_trusted_instruction(case) == "Use policy A."
    assert render_runtime_untrusted_input(case) == "Normal user question."
