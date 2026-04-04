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
