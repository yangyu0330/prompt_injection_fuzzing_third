from __future__ import annotations

from typing import Any, Callable


class ResponseAdapterError(RuntimeError):
    """Raised when response adaptation fails."""


ResponseAdapterFn = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], dict[str, Any]]


def _dot_get(obj: Any, path: str) -> Any:
    cur = obj
    for token in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(token)
        else:
            return None
    return cur


def _first_non_none(raw: dict[str, Any], paths: list[str]) -> Any:
    for path in paths:
        value = _dot_get(raw, path)
        if value is not None:
            return value
    return None


def _coerce_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on", "allow", "allowed", "pass", "passed"}:
            return True
        if lowered in {"false", "0", "no", "n", "off", "block", "blocked", "deny", "denied"}:
            return False
    return None


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _identity_adapter(
    _raw: dict[str, Any],
    mapped: dict[str, Any],
    _config: dict[str, Any],
) -> dict[str, Any]:
    return dict(mapped)


def _generic_guardrail_v1_adapter(
    raw: dict[str, Any],
    mapped: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    out = dict(mapped)

    bool_path_defaults = {
        "detected": [
            "result.detected",
            "guardrail.detected",
            "guardrail.pre.detected",
            "decision.detected",
            "detected",
        ],
        "detected_pre": [
            "guardrail.pre.detected",
            "guardrail.detected_pre",
            "decision.detected_pre",
            "detected_pre",
        ],
        "detected_post": [
            "guardrail.post.detected",
            "guardrail.detected_post",
            "decision.detected_post",
            "detected_post",
        ],
        "masked": [
            "enforcement.masked",
            "guardrail.masked",
            "decision.masked",
            "masked",
        ],
        "blocked_effectively": [
            "enforcement.blocked",
            "guardrail.blocked",
            "decision.blocked",
            "blocked_effectively",
        ],
        "effective_pass": [
            "enforcement.passed",
            "guardrail.passed",
            "decision.passed",
            "effective_pass",
        ],
    }
    numeric_path_defaults = {
        "ttft_ms": ["telemetry.ttft_ms", "timing.ttft_ms", "metrics.ttft_ms", "ttft_ms"],
        "latency_ms": ["telemetry.latency_ms", "timing.latency_ms", "metrics.latency_ms", "latency_ms"],
    }

    for key, paths in bool_path_defaults.items():
        value = out.get(key)
        if value is None:
            override = config.get(f"{key}_paths")
            candidate_paths = list(override) if isinstance(override, list) else paths
            value = _first_non_none(raw, candidate_paths)
        coerced = _coerce_bool(value)
        if coerced is not None:
            out[key] = coerced

    for key, paths in numeric_path_defaults.items():
        value = out.get(key)
        if value is None:
            override = config.get(f"{key}_paths")
            candidate_paths = list(override) if isinstance(override, list) else paths
            value = _first_non_none(raw, candidate_paths)
        coerced = _coerce_float(value)
        if coerced is not None:
            out[key] = coerced

    return out


_ADAPTER_REGISTRY: dict[str, ResponseAdapterFn] = {
    "identity": _identity_adapter,
    "generic_guardrail_v1": _generic_guardrail_v1_adapter,
}


def list_response_adapters() -> list[str]:
    return sorted(_ADAPTER_REGISTRY.keys())


def has_response_adapter(name: str) -> bool:
    adapter_name = (name or "").strip()
    if not adapter_name:
        return True
    return adapter_name in _ADAPTER_REGISTRY


def apply_response_adapter(
    adapter_name: str,
    raw_response: dict[str, Any],
    mapped_response: dict[str, Any],
    adapter_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_name = (adapter_name or "").strip() or "identity"
    adapter = _ADAPTER_REGISTRY.get(normalized_name)
    if adapter is None:
        supported = ", ".join(list_response_adapters())
        raise ResponseAdapterError(
            f"unknown response adapter `{normalized_name}`; supported adapters: {supported}"
        )

    try:
        return adapter(raw_response, mapped_response, adapter_config or {})
    except ResponseAdapterError:
        raise
    except Exception as exc:  # pragma: no cover - defensive wrapping
        raise ResponseAdapterError(f"response adapter `{normalized_name}` failed: {exc}") from exc
