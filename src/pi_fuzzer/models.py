from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SplitName = Literal["dev_calibration", "heldout_static", "adaptive", "benign_hard_negative"]
SourceStage = Literal["input", "output"]
TurnMode = Literal["single_turn", "multi_turn"]
EnforcementMode = Literal["allow", "annotate", "mask", "block"]
AttackOrBenign = Literal["attack", "benign"]


class TemplateRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    template_id: str
    template_kind: Literal["diagnostic_attack", "benign_hard_negative", "outcome_scenario"]
    attack_or_benign: AttackOrBenign
    attack_family: str
    attack_subfamily: str
    directness: Literal["direct", "indirect"]
    source_stage: SourceStage
    turn_mode: TurnMode
    supported_entry_points: list[str]
    supported_carriers: list[str]
    user_goal_skeleton: str
    trusted_instruction_skeleton: str
    untrusted_content_skeleton: str
    protected_asset: list[str]
    forbidden_action: list[str]
    expected_safe_behavior: str
    tool_scope: str
    oracle_type: list[str]
    severity: str
    recommended_layer: list[str]
    semantic_equivalence_group: str
    allowed_mutation_families: list[str] = Field(default_factory=list)
    source_origin: str
    license_note: str
    redistribution_policy: str
    notes: str = ""


class CaseRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    template_id: str
    case_id: str
    language: str
    paired_case_id: str | None = None
    attack_or_benign: AttackOrBenign
    attack_family: str
    attack_subfamily: str
    directness: Literal["direct", "indirect"]
    source_stage: SourceStage
    turn_mode: TurnMode
    entry_point: str
    carrier_context: str
    mutation_family: list[str] = Field(default_factory=list)
    user_goal: str
    trusted_instruction: str
    untrusted_content: str
    protected_asset: list[str] = Field(default_factory=list)
    forbidden_action: list[str] = Field(default_factory=list)
    expected_safe_behavior: str
    tool_scope: str
    oracle_type: list[str] = Field(default_factory=list)
    severity: str
    split: SplitName
    source_origin: str
    license_note: str = "internal_curated"
    redistribution_policy: str = "release_export_allowed"
    notes: str = ""
    semantic_equivalence_group: str = ""
    mutation_recipe_id: str | None = None
    reproducibility_seed: int | None = None
    exclude_from_headline: bool = False


class RunRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_id: str
    case_id: str
    template_id: str
    layer: Literal["L1", "L2", "L3"]
    target_id: str
    dispatcher_id: str
    system_config_id: str
    repeat_index: int
    run_seed: int
    language: str
    source_stage: SourceStage
    turn_mode: TurnMode
    guardrail_toggle: Literal["on", "off"]
    enforcement_mode: EnforcementMode
    detected_pre: bool = False
    detected_post: bool = False
    masked: bool = False
    blocked_effectively: bool = False
    effective_pass: bool = True
    secret_exposed: bool = False
    unauthorized_tool_used: bool = False
    task_hijacked: bool = False
    task_completed_safely: bool = True
    benign_overblocked: bool = False
    latency_ms: float = 0.0
    ttft_ms: float = 0.0
    throughput_rps: float = 0.0
    status: str = "ok"
    error_code: str = ""
    request_hash: str = ""
    response_hash: str = ""
    transcript_path: str = ""
    notes: str = ""


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    target_id: str
    mode: Literal["text_only", "gateway", "scenario"]
    transport: Literal["http", "local"]
    url: str | None = None
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: dict[str, Any] = Field(default_factory=dict)
    request_field_map: dict[str, str] = Field(default_factory=dict)
    response_field_map: dict[str, str] = Field(default_factory=dict)
    timeout_sec: int = 60
    supports_pre_post: bool = False
    supports_mask: bool = False
    supports_tool_log: bool = False
    supports_ttft: bool = False
    auth: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class Scorecard(BaseModel):
    model_config = ConfigDict(extra="allow")

    run: dict[str, Any]
    coverage: dict[str, Any]
    metrics: dict[str, Any]
    by_layer: dict[str, Any]
    by_attack_family: dict[str, Any]
    by_mutation: dict[str, Any]
    by_entry_point: dict[str, Any]
    by_source_stage: dict[str, Any]
    by_turn_mode: dict[str, Any]
    by_guardrail_toggle: dict[str, Any]
    by_enforcement_mode: dict[str, Any]
    by_lang: dict[str, Any]
    latency: dict[str, Any]
    results: list[dict[str, Any]]


@dataclass(frozen=True)
class CoverageViolation:
    key: tuple[str, ...]
    count: int
    required: int

