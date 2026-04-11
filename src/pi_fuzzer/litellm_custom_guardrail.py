from __future__ import annotations

from typing import Any

import httpx

try:
    from litellm.integrations.custom_guardrail import CustomGuardrail
except ImportError:  # pragma: no cover - only needed when running LiteLLM proxy
    CustomGuardrail = object  # type: ignore[assignment]


def _flatten_messages(messages: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            chunks.append(content)
    return "\n".join(chunks)


class PromptGuardPreGuardrail(CustomGuardrail):
    def __init__(
        self,
        api_base: str = "http://127.0.0.1:8011",
        timeout_sec: float = 8.0,
        **kwargs: Any,
    ) -> None:
        if CustomGuardrail is object:
            raise RuntimeError(
                "litellm is required to use PromptGuardPreGuardrail. "
                "Install with: pip install -e \".[guardrail]\""
            )
        self.api_base = api_base.rstrip("/")
        self.timeout_sec = timeout_sec
        super().__init__(**kwargs)

    async def async_moderation_hook(self, data: dict, user_api_key_dict: Any, call_type: str) -> None:
        messages = data.get("messages")
        if not isinstance(messages, list):
            return

        text = _flatten_messages(messages)
        if not text.strip():
            return

        payload = {
            "text": text,
            "trusted_instruction": "",
            "metadata": {
                "source": "litellm_proxy",
                "call_type": str(call_type),
            },
        }
        async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
            response = await client.post(f"{self.api_base}/detect", json=payload)
        response.raise_for_status()
        body = response.json()
        detected = bool(body.get("result", {}).get("detected", False))
        if detected:
            raise ValueError("PromptGuard blocked request")
