from pi_fuzzer.models import CaseRecord
from pi_fuzzer.validation import (
    dedup_cases,
    enforce_min_cell_coverage,
    structural_fingerprint,
    validate_benign_sibling_and_contrast,
    validate_kr_en_pair_links,
    validate_source_role_stage_coverage,
    validate_split_contamination,
    validate_template_references,
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


def test_structural_fingerprint_includes_role_and_replay_axes() -> None:
    base = _case("F1", "ko", "replay", "indirect", "tool_agent_misuse")
    base.source_role = "memory_note"
    base.expected_interpretation = "data"
    base.kr_en_pair_id = "PAIR-A"
    base.benign_sibling_id = "B1"
    base.tool_transition_type = "replay_to_tool"
    base.replay_window = "window_4"
    base.delayed_injection_turn = 3

    changed = base.model_copy(update={"source_role": "tool_output"})
    assert structural_fingerprint(base) != structural_fingerprint(changed)


def test_dedup_keeps_same_payload_when_envelope_differs() -> None:
    a = _case("D1", "ko", "replay", "indirect", "tool_agent_misuse")
    b = _case("D2", "ko", "replay", "indirect", "tool_agent_misuse")
    a.source_role = "memory_note"
    b.source_role = "tool_output"
    a.expected_interpretation = "data"
    b.expected_interpretation = "data"
    a.untrusted_content = "<SAME_PAYLOAD>"
    b.untrusted_content = "<SAME_PAYLOAD>"
    a.semantic_equivalence_group = "SEG-D1"
    b.semantic_equivalence_group = "SEG-D1"

    kept, drops = dedup_cases([a, b], mode="structured_only")
    assert {c.case_id for c in kept} == {"D1", "D2"}
    assert drops == []


def test_structural_fingerprint_differs_when_primary_mutation_differs() -> None:
    a = _case("M1", "ko", "input", "direct", "ko_native_mutation_layer")
    b = _case("M2", "ko", "input", "direct", "ko_native_mutation_layer")
    a.source_role = "user"
    b.source_role = "user"
    a.expected_interpretation = "instruction"
    b.expected_interpretation = "instruction"
    a.primary_mutation = "jamo"
    b.primary_mutation = "choseong"
    assert structural_fingerprint(a) != structural_fingerprint(b)


def test_structural_fingerprint_differs_when_contrast_group_differs() -> None:
    a = _case("C1", "ko", "tool_output", "indirect", "tool_agent_misuse")
    b = _case("C2", "ko", "tool_output", "indirect", "tool_agent_misuse")
    a.source_role = "tool_output"
    b.source_role = "tool_output"
    a.expected_interpretation = "data"
    b.expected_interpretation = "data"
    a.contrast_group_id = "CG-A"
    b.contrast_group_id = "CG-B"
    assert structural_fingerprint(a) != structural_fingerprint(b)


def test_validate_template_references_detects_unknown_template_id() -> None:
    row = _case("T1", "ko", "input", "direct", "direct_user_injection")
    row.template_id = "TMP-UNKNOWN"
    errors = validate_template_references([row], {"TMP"})
    assert errors == ["T1: unknown template_id TMP-UNKNOWN"]


def test_split_contamination_uses_template_fallback_for_empty_group() -> None:
    a = _case("S1", "ko", "input", "direct", "direct_user_injection")
    b = _case("S2", "en", "input", "direct", "direct_user_injection")
    a.semantic_equivalence_group = ""
    b.semantic_equivalence_group = ""
    a.template_id = "TMP-A"
    b.template_id = "TMP-B"
    a.split = "heldout_static"
    b.split = "adaptive"
    assert validate_split_contamination([a, b]) == []
