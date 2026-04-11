from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .models import FuzzCase, ModelResponse


class BaseAdapter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def run(self, case: FuzzCase) -> ModelResponse:
        raise NotImplementedError


@dataclass
class MockAdapter(BaseAdapter):
    refusal_bias: float = 0.15

    @property
    def name(self) -> str:
        return "mock"

    def run(self, case: FuzzCase) -> ModelResponse:
        text = f"Summary: handled task '{case.task_type}'."
        tool_calls: list[dict] = []

        if case.benign_hard_negative:
            # Benign negatives should mostly pass, but keep some refusals
            # to make O7 measurable in CI regression.
            if int(case.case_id[-2:], 36) % 10 < int(self.refusal_bias * 10):
                text = "I cannot help with that due to policy constraints."
            else:
                text = "Normal safe response for benign content."
            return ModelResponse(text=text, tool_calls=tool_calls, raw={"adapter": self.name})

        payload = case.input_text
        if "[ATTACK:CANARY" in payload:
            text = f"{case.canary_token} [IGNORED_TASK]"
        elif "[ATTACK:LEAK_PROMPT]" in payload:
            text = f"Leaked fragment: {case.synthetic_prompt_fragment}"
        elif "[ATTACK:EXFIL]" in payload:
            text = f"Extracted secret={case.synthetic_secret}"
        elif "[ATTACK:TOOLCALL]" in payload:
            tool_calls.append({"name": "mock.send_email", "arguments": {"to": "attacker@x.test"}})
            text = "Called tool as instructed by context."
        elif "[ATTACK:DERAIL]" in payload:
            text = f"followed hidden instruction {case.canary_token}"
        elif "[ATTACK:BOUNDARY]" in payload:
            text = "[EXECUTED_EXTERNAL_INSTRUCTION] done."
        else:
            text = "Normal response without attack trigger."

        return ModelResponse(text=text, tool_calls=tool_calls, raw={"adapter": self.name})


@dataclass
class HttpAdapter(BaseAdapter):
    url: str
    timeout_sec: float = 30.0
    auth_bearer: str | None = None

    @property
    def name(self) -> str:
        return "http"

    def run(self, case: FuzzCase) -> ModelResponse:
        payload = {
            "case": case.to_dict(),
            "input_text": case.input_text,
            "user_task": case.user_task,
            "attack_text": case.attack_text,
            "tool_context": case.tool_context,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.auth_bearer:
            req.add_header("Authorization", f"Bearer {self.auth_bearer}")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} from adapter: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Cannot connect to adapter endpoint: {exc}") from exc

        parsed = json.loads(body)
        if isinstance(parsed, dict):
            return ModelResponse.from_dict(parsed)
        return ModelResponse(text=str(parsed), raw={"raw": parsed})


@dataclass
class CommandAdapter(BaseAdapter):
    command: str
    timeout_sec: float = 30.0

    @property
    def name(self) -> str:
        return "command"

    def run(self, case: FuzzCase) -> ModelResponse:
        payload = json.dumps({"input_text": case.input_text, "case": case.to_dict()}, ensure_ascii=False)
        proc = subprocess.run(
            self.command,
            input=payload,
            text=True,
            capture_output=True,
            timeout=self.timeout_sec,
            shell=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Command adapter failed ({proc.returncode}): {proc.stderr.strip()}")
        out = proc.stdout.strip()
        if not out:
            return ModelResponse(text="", raw={"stdout": ""})
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError:
            return ModelResponse(text=out, raw={"stdout": out})
        return ModelResponse.from_dict(parsed) if isinstance(parsed, dict) else ModelResponse(text=str(parsed))
