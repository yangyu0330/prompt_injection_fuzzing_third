from __future__ import annotations

from pi_fuzzer.models import CaseRecord, RunRecord, TargetConfig
from pi_fuzzer.runners import _base_run_record, _populate_common_analysis_fields
from pi_fuzzer.scoring import build_scorecard


def _case(case_id: str, attack_or_benign: str = "attack", language: str = "ko") -> CaseRecord:
    return CaseRecord(
        template_id="TMP",
        case_id=case_id,
        language=language,
        paired_case_id="",
        attack_or_benign=attack_or_benign,  # type: ignore[arg-type]
        attack_family="direct_user_injection" if attack_or_benign == "attack" else "benign_hard_negative",
        attack_subfamily="direct_override",
        directness="direct",
        source_stage="input",
        turn_mode="single_turn",
        entry_point="user_prompt",
        carrier_context="plain_chat",
        mutation_family=["direct_override"],
        user_goal="<U>",
        trusted_instruction="<T>",
        untrusted_content="<X>",
        protected_asset=["system_prompt"],
        forbidden_action=["reveal_system_prompt"],
        expected_safe_behavior="<E>",
        tool_scope="none",
        oracle_type=["task_checker"],
        severity="S2",
        split="dev_calibration",
        source_origin="test",
        semantic_equivalence_group=f"SEG-{case_id}",
    )


def _run(
    case_id: str,
    *,
    language: str = "ko",
    source_stage: str = "input",
    enforcement_mode: str = "block",
    execution_layer: str = "L1_guardrail_only",
    policy_mode: str = "block",
    blocked_effectively: bool = True,
    detected_pre: bool = True,
    secret_exposed: bool = False,
    benign_overblocked: bool = False,
    failure_stage: str = "",
) -> RunRecord:
    return RunRecord(
        run_id=f"R-{case_id}-{enforcement_mode}",
        case_id=case_id,
        template_id="TMP",
        layer="L2",
        target_id="T",
        dispatcher_id="local",
        system_config_id="C",
        repeat_index=1,
        run_seed=1,
        language=language,
        source_stage=source_stage,
        turn_mode="single_turn",
        guardrail_toggle="on",
        enforcement_mode=enforcement_mode,  # type: ignore[arg-type]
        detected_pre=detected_pre,
        detected_post=False,
        masked=False,
        blocked_effectively=blocked_effectively,
        effective_pass=not blocked_effectively,
        secret_exposed=secret_exposed,
        benign_overblocked=benign_overblocked,
        latency_ms=1,
        ttft_ms=1,
        throughput_rps=1,
        execution_layer=execution_layer,
        policy_mode=policy_mode,
        failure_stage=failure_stage,
    )


def test_case_record_serializes_primary_target_and_expected_entities() -> None:
    case = _case("SER-1")
    case.primary_target_entity = "rrn"
    case.expected_sensitive_entities = ["rrn", "phone"]
    raw = case.model_dump_json()
    restored = CaseRecord.model_validate_json(raw)
    assert restored.primary_target_entity == "rrn"
    assert restored.expected_sensitive_entities == ["rrn", "phone"]


def test_scoring_contrast_group_outcome_aggregation() -> None:
    attack_case = _case("A1", attack_or_benign="attack", language="ko")
    benign_case = _case("B1", attack_or_benign="benign", language="ko")
    attack_case.contrast_group_id = "CG-1"
    benign_case.contrast_group_id = "CG-1"
    attack_case.paired_case_role = "attack"
    benign_case.paired_case_role = "benign"

    runs = [
        _run("A1", secret_exposed=True, blocked_effectively=False, enforcement_mode="allow", policy_mode="allow"),
        _run("B1", benign_overblocked=True, blocked_effectively=True),
    ]
    scorecard = build_scorecard(runs, [attack_case, benign_case], coverage_summary={"passed": True})
    cg = scorecard.by_contrast_group_outcome["CG-1"]
    assert cg["attack_run_count"] == 1
    assert cg["benign_run_count"] == 1
    assert cg["attack_success_rate"] == 1.0
    assert cg["benign_overblock_rate"] == 1.0


def test_runner_sets_normalization_changed_and_diff_tags() -> None:
    case = _case("N1")
    target = TargetConfig(
        target_id="T",
        mode="text_only",
        transport="local",
    )
    record = _base_run_record(case, "L1", target, run_seed=1, repeat_index=1, guardrail_toggle="on", enforcement_mode="annotate")
    _populate_common_analysis_fields(
        record,
        case,
        observed_text="ㄱㅏㄴㄷㅏ",
        mapped={
            "normalized_input_text": "간다",
            "applied_normalizers": ["jamo_compose"],
            "normalization_diff_tags": ["jamo_composed"],
        },
    )
    assert record.normalization_changed is True
    assert record.normalization_diff_tags == ["jamo_composed"]
    assert record.applied_normalizers == ["jamo_compose"]


def test_guard_stage_alignment_mismatch_aggregation() -> None:
    case = _case("G1")
    case.expected_guard_stage = "policy_match"
    run = _run("G1", secret_exposed=True, blocked_effectively=False, enforcement_mode="allow", policy_mode="allow", failure_stage="context_assembly")
    scorecard = build_scorecard([run], [case], coverage_summary={"passed": True})
    assert scorecard.by_guard_stage_alignment["mismatch"]["n"] == 1
    assert scorecard.by_guard_stage_alignment["mismatch"]["rate"] == 1.0


def test_scoring_groups_execution_layer_source_stage_policy_mode() -> None:
    case_input = _case("L1", language="ko")
    case_output = _case("L2", language="en")
    case_output.source_stage = "output"

    runs = [
        _run(
            "L1",
            language="ko",
            source_stage="input",
            enforcement_mode="mask",
            execution_layer="L3",
            policy_mode="MASK",
            blocked_effectively=False,
            detected_pre=True,
        ),
        _run(
            "L2",
            language="en",
            source_stage="OUTPUT",
            enforcement_mode="block",
            execution_layer="L4_e2e_rag",
            policy_mode="block",
            blocked_effectively=True,
            detected_pre=True,
        ),
    ]
    scorecard = build_scorecard(runs, [case_input, case_output], coverage_summary={"passed": True})

    assert "INPUT" in scorecard.by_source_stage
    assert "OUTPUT" in scorecard.by_source_stage
    assert "L3_full_stack" in scorecard.by_execution_layer
    assert "L4_e2e_rag" in scorecard.by_execution_layer
    assert "mask" in scorecard.by_policy_mode
    assert "block" in scorecard.by_policy_mode

