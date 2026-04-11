from __future__ import annotations

import pytest

from pi_fuzzer.guardrail_adapters import ResponseAdapterError, apply_response_adapter


def test_identity_adapter_returns_mapped_values() -> None:
    mapped = {"detected": True, "blocked_effectively": False}
    adapted = apply_response_adapter("", raw_response={"any": "value"}, mapped_response=mapped)
    assert adapted == mapped


def test_generic_guardrail_adapter_extracts_common_fields() -> None:
    raw = {
        "guardrail": {
            "pre": {"detected": "true"},
            "post": {"detected": "false"},
        },
        "enforcement": {
            "masked": 0,
            "blocked": 1,
            "passed": 0,
        },
        "telemetry": {"ttft_ms": "12.5", "latency_ms": 44},
    }
    adapted = apply_response_adapter(
        "generic_guardrail_v1",
        raw_response=raw,
        mapped_response={},
    )
    assert adapted["detected_pre"] is True
    assert adapted["detected_post"] is False
    assert adapted["masked"] is False
    assert adapted["blocked_effectively"] is True
    assert adapted["effective_pass"] is False
    assert adapted["ttft_ms"] == 12.5
    assert adapted["latency_ms"] == 44.0


def test_unknown_adapter_raises() -> None:
    with pytest.raises(ResponseAdapterError):
        apply_response_adapter(
            "unknown_adapter",
            raw_response={},
            mapped_response={},
        )
