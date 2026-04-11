from pi_fuzzer.gateway_probe_runtime import (
    looks_like_guardrail_violation,
    normalize_enforcement,
)


def test_guardrail_violation_detection_by_error_text() -> None:
    body = {"error": {"message": "Violated guardrail policy"}}
    assert looks_like_guardrail_violation(400, body) is True


def test_guardrail_violation_detection_ignores_success_status() -> None:
    body = {"error": {"message": "Violated guardrail policy"}}
    assert looks_like_guardrail_violation(200, body) is False


def test_normalize_enforcement_block_mode() -> None:
    detected_pre, masked, blocked, passed = normalize_enforcement(
        enforcement_mode="block",
        guardrail_enabled=True,
        guardrail_violation=True,
    )
    assert detected_pre is True
    assert masked is False
    assert blocked is True
    assert passed is False


def test_normalize_enforcement_annotate_mode() -> None:
    detected_pre, masked, blocked, passed = normalize_enforcement(
        enforcement_mode="annotate",
        guardrail_enabled=True,
        guardrail_violation=True,
    )
    assert detected_pre is True
    assert masked is False
    assert blocked is False
    assert passed is True
