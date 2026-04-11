from __future__ import annotations

import json
import time
from typing import Any

import httpx


GUARDRAIL_ERROR_HINTS = (
    "guardrail",
    "violated guardrail policy",
    "blocked",
    "policy",
)


def _lower_text(value: Any) -> str:
    if isinstance(value, str):
        return value.lower()
    return json.dumps(value, ensure_ascii=False).lower()


def looks_like_guardrail_violation(status_code: int, response_body: Any) -> bool:
    if status_code < 400:
        return False
    lowered = _lower_text(response_body)
    return any(hint in lowered for hint in GUARDRAIL_ERROR_HINTS)


def normalize_enforcement(
    enforcement_mode: str,
    guardrail_enabled: bool,
    guardrail_violation: bool,
) -> tuple[bool, bool, bool, bool]:
    mode = (enforcement_mode or "").strip().lower()
    if mode not in {"allow", "annotate", "mask", "block"}:
        mode = "allow"

    if not guardrail_enabled:
        return False, False, False, True
    if not guardrail_violation:
        return False, False, False, True

    detected_pre = True
    if mode == "block":
        return detected_pre, False, True, False
    if mode == "mask":
        return detected_pre, True, False, True
    if mode == "annotate":
        return detected_pre, False, False, True
    return False, False, False, True


def _extract_mode(payload: dict[str, Any]) -> str:
    metadata = payload.get("metadata", {})
    if isinstance(metadata, dict):
        maybe = metadata.get("enforcement_mode")
        if isinstance(maybe, str) and maybe.strip():
            return maybe
    maybe = payload.get("enforcement_mode")
    if isinstance(maybe, str) and maybe.strip():
        return maybe
    return "allow"


def _extract_toggle(payload: dict[str, Any]) -> str:
    metadata = payload.get("metadata", {})
    if isinstance(metadata, dict):
        maybe = metadata.get("guardrail_toggle")
        if isinstance(maybe, str) and maybe.strip():
            return maybe
    maybe = payload.get("guardrail_toggle")
    if isinstance(maybe, str) and maybe.strip():
        return maybe
    return "on"


def create_gateway_probe_app(
    litellm_base_url: str,
    model_alias: str,
    guardrail_name: str,
    api_key: str = "sk-local-litellm",
    mock_response: str = "pi-fuzz gateway probe mock response",
    timeout_sec: float = 20.0,
):
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as exc:
        raise RuntimeError(
            "Gateway probe server dependencies are missing. "
            "Install with: pip install -e \".[guardrail]\""
        ) from exc

    app = FastAPI(title="PI Fuzzer LiteLLM Gateway Probe", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "litellm_base_url": litellm_base_url,
            "model_alias": model_alias,
            "guardrail_name": guardrail_name,
        }

    @app.post("/v1/evaluate")
    def evaluate(payload: dict[str, Any]) -> dict[str, Any]:
        mode = _extract_mode(payload)
        toggle = _extract_toggle(payload).strip().lower()
        guardrail_enabled = toggle == "on" and mode in {"annotate", "mask", "block"}

        messages = payload.get("messages")
        if not isinstance(messages, list):
            raise HTTPException(status_code=400, detail="`messages` must be a list")

        req_body: dict[str, Any] = {
            "model": model_alias,
            "messages": messages,
            "mock_response": mock_response,
        }
        if guardrail_enabled:
            req_body["guardrails"] = [guardrail_name]

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        endpoint = f"{litellm_base_url.rstrip('/')}/v1/chat/completions"
        t0 = time.perf_counter()
        with httpx.Client(timeout=timeout_sec) as client:
            response = client.post(endpoint, headers=headers, json=req_body)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        try:
            body = response.json()
        except ValueError:
            body = {"raw_text": response.text}

        guardrail_violation = looks_like_guardrail_violation(response.status_code, body)
        if response.status_code >= 400 and not guardrail_violation:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "litellm_request_failed",
                    "status_code": response.status_code,
                    "body": body,
                },
            )

        detected_pre, masked, blocked, passed = normalize_enforcement(
            enforcement_mode=mode,
            guardrail_enabled=guardrail_enabled,
            guardrail_violation=guardrail_violation,
        )

        return {
            "guardrail": {
                "pre": {"detected": detected_pre},
                "post": {"detected": False},
            },
            "enforcement": {
                "masked": masked,
                "blocked": blocked,
                "passed": passed,
            },
            "telemetry": {
                "latency_ms": latency_ms,
                "ttft_ms": max(1.0, latency_ms * 0.3),
            },
            "raw": {
                "status_code": response.status_code,
                "applied_guardrails": response.headers.get("x-litellm-applied-guardrails", ""),
                "response_body": body,
            },
        }

    return app


def run_gateway_probe_server(
    host: str = "127.0.0.1",
    port: int = 8012,
    litellm_base_url: str = "http://127.0.0.1:4000",
    model_alias: str = "pi-fuzz-smoke-model",
    guardrail_name: str = "prompt-guard-pre",
    api_key: str = "sk-local-litellm",
    timeout_sec: float = 20.0,
) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "uvicorn is required to run the Gateway probe server. "
            "Install with: pip install -e \".[guardrail]\""
        ) from exc

    app = create_gateway_probe_app(
        litellm_base_url=litellm_base_url,
        model_alias=model_alias,
        guardrail_name=guardrail_name,
        api_key=api_key,
        timeout_sec=timeout_sec,
    )
    uvicorn.run(app, host=host, port=port)
