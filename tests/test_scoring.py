from pi_fuzzer.models import CaseRecord, RunRecord
from pi_fuzzer.scoring import build_scorecard


def _case(case_id: str, attack_or_benign: str, lang: str = "en") -> CaseRecord:
    return CaseRecord(
        template_id="TMP",
        case_id=case_id,
        language=lang,
        attack_or_benign=attack_or_benign,  # type: ignore[arg-type]
        attack_family="direct_user_injection" if attack_or_benign == "attack" else "benign_hard_negative",
        attack_subfamily="x",
        directness="direct",
        source_stage="input",
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
        split="dev_calibration",
        source_origin="test",
        semantic_equivalence_group="SEG",
    )


def _run(case_id: str, mode: str, blocked: bool, effective: bool) -> RunRecord:
    return RunRecord(
        run_id=f"R-{case_id}-{mode}",
        case_id=case_id,
        template_id="TMP",
        layer="L2",
        target_id="T",
        dispatcher_id="local",
        system_config_id="C",
        repeat_index=1,
        run_seed=1,
        language="en",
        source_stage="input",
        turn_mode="single_turn",
        guardrail_toggle="on",
        enforcement_mode=mode,  # type: ignore[arg-type]
        detected_pre=True,
        detected_post=False,
        masked=False,
        blocked_effectively=blocked,
        effective_pass=effective,
        latency_ms=1,
        ttft_ms=1,
        throughput_rps=1,
    )


def test_scorecard_has_enforcement_buckets() -> None:
    cases = [_case("A", "attack"), _case("B", "benign")]
    runs = [
        _run("A", "allow", blocked=False, effective=True),
        _run("A", "annotate", blocked=False, effective=True),
        _run("A", "mask", blocked=False, effective=True),
        _run("A", "block", blocked=True, effective=False),
    ]
    scorecard = build_scorecard(runs, cases, coverage_summary={"passed": True})
    assert "by_enforcement_mode" in scorecard.model_dump()
    for mode in ("allow", "annotate", "mask", "block"):
        assert mode in scorecard.by_enforcement_mode
        assert "effective_pass_rate" in scorecard.by_enforcement_mode[mode]
        assert "blocked_effectively_rate" in scorecard.by_enforcement_mode[mode]


def test_scorecard_run_meta_uses_scored_case_count() -> None:
    cases = [_case("A", "attack"), _case("B", "benign"), _case("C", "attack")]
    runs = [
        _run("A", "allow", blocked=False, effective=True),
        _run("B", "block", blocked=True, effective=False),
    ]
    scorecard = build_scorecard(runs, cases, coverage_summary={"passed": True})
    assert scorecard.run["total_cases"] == 2
    assert scorecard.run["package_case_count"] == 3


def test_scorecard_p0_p1_analysis_buckets_are_populated() -> None:
    case_a = _case("A", "attack", "ko")
    case_b = _case("B", "attack", "en")
    case_a.source_role = "tool_output"
    case_a.expected_interpretation = "data"
    case_a.policy_requested = "block"
    case_a.vendor_declared_support = ["trajectory_guard"]
    case_a.tool_transition_type = "replay_to_tool"
    case_b.source_role = "user"
    case_b.expected_interpretation = "instruction"
    case_b.policy_requested = "block"

    run_a1 = _run("A", "allow", blocked=False, effective=True)
    run_a1.secret_exposed = True
    run_a1.source_role = "tool_output"
    run_a1.expected_interpretation = "data"
    run_a1.policy_requested = "block"
    run_a1.policy_executed = "allow"
    run_a1.raw_policy_action = "alert"
    run_a1.detector_family = "replay_audit"
    run_a1.failure_cause_code = "execution_gap"
    run_a1.reason_codes = ["replay_trigger"]
    run_a1.tool_transition_type = "replay_to_tool"
    run_a1.config_fingerprint = "CFG-A"
    run_a1.final_user_visible = "tool_call"
    run_a1.vendor_declared_supported = True

    run_a2 = _run("A", "block", blocked=True, effective=False)
    run_a2.source_role = "tool_output"
    run_a2.expected_interpretation = "data"
    run_a2.policy_requested = "block"
    run_a2.policy_executed = "block"
    run_a2.raw_policy_action = "alert_and_deny"
    run_a2.detector_family = "replay_audit"
    run_a2.failure_cause_code = "none"
    run_a2.reason_codes = ["policy_denied"]
    run_a2.tool_transition_type = "replay_to_tool"
    run_a2.config_fingerprint = "CFG-B"
    run_a2.final_user_visible = "safe_refusal"
    run_a2.vendor_declared_supported = True

    run_b = _run("B", "block", blocked=True, effective=False)
    run_b.source_role = "user"
    run_b.expected_interpretation = "instruction"
    run_b.policy_requested = "block"
    run_b.policy_executed = "block"
    run_b.raw_policy_action = {"action": "sanitize", "mode": "output_rail"}
    run_b.detector_family = "pattern"
    run_b.failure_cause_code = "none"
    run_b.reason_codes = ["policy_denied"]
    run_b.tool_transition_type = "none"
    run_b.config_fingerprint = "CFG-B"
    run_b.final_user_visible = "safe_refusal"

    scorecard = build_scorecard(
        [run_a1, run_a2, run_b],
        [case_a, case_b],
        coverage_summary={"passed": True},
    )
    assert "tool_output" in scorecard.by_source_role
    assert "data" in scorecard.by_expected_interpretation
    assert "mismatch" in scorecard.by_policy_request_vs_execution
    assert "match" in scorecard.by_policy_request_vs_execution
    assert "alert" in scorecard.by_raw_policy_action
    assert any(k.startswith("object:") for k in scorecard.by_raw_policy_action)
    assert "replay_trigger" in scorecard.by_reason_code
    assert "replay_to_tool" in scorecard.by_tool_transition
    assert "sensitive" in scorecard.by_config_sensitivity
    assert "claim_gap" in scorecard.by_vendor_claim_gap


def test_vendor_claim_gap_uses_case_support_when_run_flag_missing() -> None:
    case = _case("A", "attack", "en")
    case.attack_family = "structured_payload_misuse"
    case.attack_subfamily = "structured_payload_function_call"
    case.source_stage = "tool_input"
    case.entry_point = "tool_output"
    case.vendor_declared_support = ["function_call_guard"]

    run = _run("A", "allow", blocked=False, effective=True)
    run.unauthorized_tool_used = True
    run.vendor_declared_supported = None

    scorecard = build_scorecard([run], [case], coverage_summary={"passed": True})
    assert "claim_gap" in scorecard.by_vendor_claim_gap


def test_scorecard_excludes_error_runs_from_metrics_and_tracks_errors() -> None:
    cases = [_case("A", "attack"), _case("B", "benign")]
    ok_run = _run("A", "allow", blocked=False, effective=True)
    error_run = _run("B", "block", blocked=True, effective=False)
    error_run.status = "error"
    error_run.error_code = "dispatch_http_error"
    error_run.detected_pre = True
    error_run.blocked_effectively = True

    scorecard = build_scorecard([ok_run, error_run], cases, coverage_summary={"passed": True})

    assert scorecard.run["total_runs"] == 2
    assert scorecard.run["scored_runs"] == 1
    assert scorecard.run["error_runs"] == 1
    assert scorecard.run["error_codes"] == {"dispatch_http_error": 1}
    assert scorecard.by_enforcement_mode["allow"]["n"] == 1
    assert scorecard.by_enforcement_mode["block"]["n"] == 0
