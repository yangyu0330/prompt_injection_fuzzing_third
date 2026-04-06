from pi_fuzzer.models import CaseRecord
from pi_fuzzer.validation import (
    enforce_min_cell_coverage,
    validate_benign_sibling_and_contrast,
    validate_kr_en_pair_links,
    validate_source_role_stage_coverage,
)


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


def test_kr_en_pair_id_requires_ko_and_en() -> None:
    ko = _case("KO", "ko", "input", "direct", "direct_user_injection")
    en = _case("EN", "en", "input", "direct", "direct_user_injection")
    ko.kr_en_pair_id = "PAIR-1"
    en.kr_en_pair_id = "PAIR-1"
    ko.paired_case_id = en.case_id
    en.paired_case_id = ko.case_id
    assert validate_kr_en_pair_links([ko, en]) == []


def test_benign_sibling_requires_opposite_label() -> None:
    atk = _case("ATK", "ko", "replay", "indirect", "tool_agent_misuse")
    ben = _case("BEN", "ko", "replay", "indirect", "benign_hard_negative")
    ben.attack_or_benign = "benign"
    atk.benign_sibling_id = ben.case_id
    atk.contrast_group_id = "CG-1"
    ben.contrast_group_id = "CG-1"
    assert validate_benign_sibling_and_contrast([atk, ben]) == []


def test_source_role_stage_validation_requires_interpretation() -> None:
    row = _case("R1", "ko", "tool_output", "indirect", "tool_agent_misuse")
    row.source_role = "tool_output"
    row.expected_interpretation = "data"
    assert validate_source_role_stage_coverage([row]) == []
