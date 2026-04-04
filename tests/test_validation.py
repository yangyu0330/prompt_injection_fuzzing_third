from pi_fuzzer.models import CaseRecord
from pi_fuzzer.validation import enforce_min_cell_coverage


def _case(case_id: str, lang: str, stage: str, directness: str, family: str) -> CaseRecord:
    return CaseRecord(
        template_id="TMP",
        case_id=case_id,
        language=lang,
        attack_or_benign="attack",
        attack_family=family,
        attack_subfamily="x",
        directness=directness,  # type: ignore[arg-type]
        source_stage=stage,  # type: ignore[arg-type]
        turn_mode="single_turn",
        entry_point="user_prompt",
        carrier_context="plain_chat",
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
    )


def test_coverage_dims_include_source_stage() -> None:
    rows = [
        _case("A", "ko", "input", "direct", "direct_user_injection"),
        _case("B", "ko", "output", "direct", "direct_user_injection"),
    ]
    violations = enforce_min_cell_coverage(
        rows,
        dims=["language", "source_stage", "directness", "attack_family"],
        min_count=1,
        splits={"heldout_static"},
    )
    assert violations == []

