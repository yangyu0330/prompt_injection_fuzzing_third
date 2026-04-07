from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SplitName = Literal["dev_calibration", "heldout_static", "adaptive", "benign_hard_negative"]
# Keep source stage permissive for backward compatibility across legacy/new values.
SourceStage = str
SourceRole = str
ExpectedInterpretation = str
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
    supported_source_roles: list[str] = Field(default_factory=list)
    supported_expected_interpretations: list[str] = Field(default_factory=list)
    tool_transition_type: str = ""
    replay_enabled: bool = False
    delayed_trigger: bool = False
    vendor_declared_support: list[str] = Field(default_factory=list)
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
    kr_en_pair_id: str = ""
    benign_sibling_id: str = ""
    attack_or_benign: AttackOrBenign
    attack_family: str
    attack_subfamily: str
    directness: Literal["direct", "indirect"]
    source_stage: SourceStage
    source_role: SourceRole = ""
    expected_interpretation: ExpectedInterpretation = ""
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
    canonical_attack_intent_id: str = ""
    canonical_untrusted_content: str = ""
    primary_mutation: str = ""
    secondary_mutations: list[str] = Field(default_factory=list)
    register_level: str = ""
    script_mix_profile: list[str] = Field(default_factory=list)
    normalization_required: list[str] = Field(default_factory=list)
    context_dependency_type: str = ""
    analysis_axis: str = ""
    benign_confounder_tags: list[str] = Field(default_factory=list)
    primary_target_entity: str = ""
    expected_sensitive_entities: list[str] = Field(default_factory=list)
    contrast_group_id: str = ""
    paired_case_role: str = ""
    expected_guard_stage: str = ""
    execution_layer: str = ""
    policy_requested: str = ""
    detector_family: str = ""
    failure_cause_code: str = ""
    reason_codes: list[str] = Field(default_factory=list)
    matched_rule_ids: list[str] = Field(default_factory=list)
    decision_trace: list[str] = Field(default_factory=list)
    config_fingerprint: str = ""
    final_user_visible: str = ""
    unsafe_tool_call: bool = False
    partially_allowed: bool = False
    partial_defense: bool = False
    tool_transition_type: str = ""
    replay_window: str = ""
    delayed_injection_turn: int | None = None
    structured_payload_type: str = ""
    threshold_profile: str = ""
    normalization_variant: str = ""
    vendor_declared_support: list[str] = Field(default_factory=list)


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
    source_role: SourceRole = ""
    expected_interpretation: ExpectedInterpretation = ""
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
    observed_input_text: str = ""
    normalized_input_text: str = ""
    applied_normalizers: list[str] = Field(default_factory=list)
    normalization_changed: bool = False
    normalization_diff_tags: list[str] = Field(default_factory=list)
    language_route: str = ""
    failure_stage: str = ""
    failure_reason_tags: list[str] = Field(default_factory=list)
    detector_reason_codes_pre: list[str] = Field(default_factory=list)
    detector_reason_codes_post: list[str] = Field(default_factory=list)
    response_disposition: str = ""
    tool_decision_source: str = ""
    chunk_join_required: bool = False
    chunk_join_succeeded: bool | None = None
    human_review_label: str = ""
    human_root_cause_label: str = ""
    review_confidence: float | None = None
    execution_layer: str = ""
    engine_name: str = ""
    gateway_name: str = ""
    policy_mode: str = ""
    model_name: str = ""
    policy_requested: str = ""
    policy_executed: str = ""
    raw_policy_action: Any = None
    detector_family: str = ""
    failure_cause_code: str = ""
    reason_codes: list[str] = Field(default_factory=list)
    matched_rule_ids: list[str] = Field(default_factory=list)
    decision_trace: list[str] = Field(default_factory=list)
    config_fingerprint: str = ""
    final_user_visible: str = ""
    unsafe_tool_call: bool = False
    partially_allowed: bool = False
    partial_defense: bool = False
    tool_transition_type: str = ""
    replay_turn_index: int | None = None
    delayed_trigger_fired: bool = False
    threshold_profile: str = ""
    normalization_variant: str = ""
    vendor_declared_supported: bool | None = None


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
    engine_name: str = ""
    gateway_name: str = ""
    model_name: str = ""
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
    by_source_role: dict[str, Any] = Field(default_factory=dict)
    by_expected_interpretation: dict[str, Any] = Field(default_factory=dict)
    by_detector_family: dict[str, Any] = Field(default_factory=dict)
    by_failure_cause_code: dict[str, Any] = Field(default_factory=dict)
    by_policy_request_vs_execution: dict[str, Any] = Field(default_factory=dict)
    by_raw_policy_action: dict[str, Any] = Field(default_factory=dict)
    by_reason_code: dict[str, Any] = Field(default_factory=dict)
    by_tool_transition: dict[str, Any] = Field(default_factory=dict)
    by_config_sensitivity: dict[str, Any] = Field(default_factory=dict)
    by_vendor_claim_gap: dict[str, Any] = Field(default_factory=dict)
    by_final_user_visible: dict[str, Any] = Field(default_factory=dict)
    by_analysis_axis: dict[str, Any] = Field(default_factory=dict)
    by_primary_mutation: dict[str, Any] = Field(default_factory=dict)
    by_register_level: dict[str, Any] = Field(default_factory=dict)
    by_failure_stage: dict[str, Any] = Field(default_factory=dict)
    by_language_route: dict[str, Any] = Field(default_factory=dict)
    by_primary_target_entity: dict[str, Any] = Field(default_factory=dict)
    by_execution_layer: dict[str, Any] = Field(default_factory=dict)
    by_policy_mode: dict[str, Any] = Field(default_factory=dict)
    by_contrast_group_outcome: dict[str, Any] = Field(default_factory=dict)
    by_guard_stage_alignment: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class CoverageViolation:
    key: tuple[str, ...]
    count: int
    required: int
