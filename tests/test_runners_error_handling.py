from __future__ import annotations

from pathlib import Path

from pi_fuzzer.guardrail_adapters import ResponseAdapterError
from pi_fuzzer.models import CaseRecord, TargetConfig
import pi_fuzzer.runners as runners


def _case(case_id: str = "CASE-1") -> CaseRecord:
    return CaseRecord(
        template_id="TMP",
        case_id=case_id,
        language="ko",
        attack_or_benign="attack",
        attack_family="direct_user_injection",
        attack_subfamily="direct_override",
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


def _http_target() -> TargetConfig:
    return TargetConfig(
        target_id="text-http-test",
        mode="text_only",
        transport="http",
        url="http://localhost:9999/detect",
        method="POST",
        headers={"Content-Type": "application/json"},
        response_field_map={"detected": "result.detected"},
    )


def test_run_text_only_marks_dispatch_errors(monkeypatch, tmp_path: Path) -> None:
    def _fail_dispatch(_target, _payload):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(runners, "dispatch_http", _fail_dispatch)
    record = runners.run_text_only_case(
        _case(),
        _http_target(),
        tmp_path / "transcripts",
        run_seed=1,
        repeat_index=1,
        guardrail_toggle="on",
        enforcement_mode="annotate",
    )
    assert record.status == "error"
    assert record.error_code == "dispatch_http_error"
    assert Path(record.transcript_path).exists()


def test_run_text_only_marks_response_contract_errors(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(runners, "dispatch_http", lambda _target, _payload: {"result": {}})
    record = runners.run_text_only_case(
        _case(),
        _http_target(),
        tmp_path / "transcripts",
        run_seed=1,
        repeat_index=1,
        guardrail_toggle="on",
        enforcement_mode="annotate",
    )
    assert record.status == "error"
    assert record.error_code == "response_contract_error"
    assert Path(record.transcript_path).exists()


def test_run_text_only_marks_adapter_errors(monkeypatch, tmp_path: Path) -> None:
    target = _http_target()
    target.response_adapter = "generic_guardrail_v1"

    monkeypatch.setattr(runners, "dispatch_http", lambda _target, _payload: {"result": {"detected": True}})

    def _fail_adapter(*_args, **_kwargs):
        raise ResponseAdapterError("adapter failed")

    monkeypatch.setattr(runners, "apply_response_adapter", _fail_adapter)
    record = runners.run_text_only_case(
        _case(),
        target,
        tmp_path / "transcripts",
        run_seed=1,
        repeat_index=1,
        guardrail_toggle="on",
        enforcement_mode="annotate",
    )
    assert record.status == "error"
    assert record.error_code == "response_adapter_error"
    assert Path(record.transcript_path).exists()
