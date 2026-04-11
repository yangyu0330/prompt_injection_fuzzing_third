from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class FuzzCase:
    case_id: str
    language: str
    attack_surface: str
    goal_type: str
    task_type: str
    carrier_type: str
    carrier_position: str
    explicitness: str
    expected_oracle: str
    source_id: str
    split: str
    license_tag: str
    user_task: str
    attack_text: str
    input_text: str
    canary_token: str
    synthetic_secret: str
    paired_group_id: str | None = None
    tool_context: str | None = None
    mutation_chain: list[str] = field(default_factory=list)
    benign_hard_negative: bool = False
    allowed_tools: list[str] = field(default_factory=list)
    synthetic_prompt_fragment: str = "SYNTH_SYSTEM_FRAGMENT_001"
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "FuzzCase":
        return FuzzCase(
            case_id=data["case_id"],
            language=data["language"],
            attack_surface=data["attack_surface"],
            goal_type=data["goal_type"],
            task_type=data["task_type"],
            carrier_type=data.get("carrier_type", "plain"),
            carrier_position=data.get("carrier_position", "body"),
            explicitness=data.get("explicitness", "explicit"),
            expected_oracle=data.get("expected_oracle", "NONE"),
            source_id=data.get("source_id", "LOCAL"),
            split=data.get("split", "train_seed"),
            license_tag=data.get("license_tag", "internal"),
            user_task=data["user_task"],
            attack_text=data["attack_text"],
            input_text=data.get("input_text", ""),
            canary_token=data.get("canary_token", "CANARY_PI_000"),
            synthetic_secret=data.get("synthetic_secret", "SYNTH_SECRET_000"),
            paired_group_id=data.get("paired_group_id"),
            tool_context=data.get("tool_context"),
            mutation_chain=list(data.get("mutation_chain", [])),
            benign_hard_negative=bool(data.get("benign_hard_negative", False)),
            allowed_tools=list(data.get("allowed_tools", [])),
            synthetic_prompt_fragment=data.get(
                "synthetic_prompt_fragment", "SYNTH_SYSTEM_FRAGMENT_001"
            ),
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "paired_group_id": self.paired_group_id,
            "language": self.language,
            "attack_surface": self.attack_surface,
            "goal_type": self.goal_type,
            "task_type": self.task_type,
            "carrier_type": self.carrier_type,
            "carrier_position": self.carrier_position,
            "explicitness": self.explicitness,
            "tool_context": self.tool_context,
            "mutation_chain": self.mutation_chain,
            "benign_hard_negative": self.benign_hard_negative,
            "canary_token": self.canary_token,
            "synthetic_secret": self.synthetic_secret,
            "expected_oracle": self.expected_oracle,
            "source_id": self.source_id,
            "split": self.split,
            "license_tag": self.license_tag,
            "user_task": self.user_task,
            "attack_text": self.attack_text,
            "input_text": self.input_text,
            "allowed_tools": self.allowed_tools,
            "synthetic_prompt_fragment": self.synthetic_prompt_fragment,
            "metadata": self.metadata,
        }


@dataclass
class ModelResponse:
    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ModelResponse":
        return ModelResponse(
            text=str(data.get("text", "")),
            tool_calls=list(data.get("tool_calls", [])),
            raw=data,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "tool_calls": self.tool_calls, "raw": self.raw}


@dataclass
class RunResult:
    case_id: str
    adapter: str
    expected_oracle: str
    expected_oracle_hit: bool
    oracle_hits: dict[str, bool]
    benign_hard_negative: bool
    response: dict[str, Any]
    started_at: str
    ended_at: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "adapter": self.adapter,
            "expected_oracle": self.expected_oracle,
            "expected_oracle_hit": self.expected_oracle_hit,
            "oracle_hits": self.oracle_hits,
            "benign_hard_negative": self.benign_hard_negative,
            "response": self.response,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "error": self.error,
        }

