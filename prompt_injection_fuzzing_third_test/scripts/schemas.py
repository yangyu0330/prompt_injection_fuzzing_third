from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GuardrailVariant(str, Enum):
    EN_CLEAN = "en_clean"
    KO_CLEAN = "ko_clean"
    KO_HARD = "ko_hard"
    EN_BENIGN = "en_benign"
    KO_BENIGN = "ko_benign"


class PromptGuardMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1)
    language: Literal["en", "ko"]
    attack_or_benign: Literal["attack", "benign"]
    variant: GuardrailVariant


class PromptGuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    trusted_instruction: str = Field(min_length=1)
    user_goal: str = Field(min_length=1)
    metadata: PromptGuardMetadata


class GuardrailToggle(str, Enum):
    ON = "on"
    OFF = "off"


class EnforcementMode(str, Enum):
    ALLOW = "allow"
    ANNOTATE = "annotate"
    MASK = "mask"
    BLOCK = "block"


class PromptGuardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: bool
    label: Literal["MALICIOUS", "BENIGN"]
    malicious_score: float = Field(ge=0.0, le=1.0)
    benign_score: float = Field(ge=0.0, le=1.0)
    segment_count: int = Field(ge=1)
    max_segment_index: int = Field(ge=0)
    model_id: str = Field(min_length=1)


class GatewayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    trusted_instruction: str = Field(min_length=1)
    user_goal: str = Field(min_length=1)
    guardrail_toggle: GuardrailToggle
    enforcement_mode: EnforcementMode
    metadata: PromptGuardMetadata


class GatewayResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected_pre: bool
    detected_post: bool
    masked: bool
    blocked_effectively: bool
    effective_pass: bool
    label: Literal["MALICIOUS", "BENIGN"]
    malicious_score: float = Field(ge=0.0, le=1.0)
    benign_score: float = Field(ge=0.0, le=1.0)
    segment_count: int = Field(ge=1)
    max_segment_index: int = Field(ge=0)
    model_id: str = Field(min_length=1)
    policy_executed: EnforcementMode


class ErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    details: list[str]


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ErrorDetail


class NormalizedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: bool
    label: str
    malicious_score: float
    benign_score: float
    segment_count: int
    max_segment_index: int
    model_id: str


class IoNormalizedRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    run_id: str
    request: dict[str, Any]
    response: dict[str, Any]
    request_schema_ok: bool
    response_schema_ok: bool
    normalized_response: NormalizedResponse | None = None
    validation_errors: list[str] = Field(default_factory=list)


class CaseSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    variant: GuardrailVariant
    language: Literal["en", "ko"]
    attack_or_benign: Literal["attack", "benign"]
    detected: bool
    label: str
    malicious_score: float
    benign_score: float
    segment_count: int
    max_segment_index: int


class CompareMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_detection_rate: float
    benign_false_positive_rate: float
    malicious_score_gap: float
    label_mismatch_count: int


class BaselineParity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    en_clean_attack: CaseSummary
    ko_clean_attack: CaseSummary
    score_gap: float
    label_mismatch: bool
    critical_parity_gap: bool
    notable_parity_gap: bool


class KORobustness(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ko_clean_attack: CaseSummary
    ko_hard_attack: CaseSummary
    hard_mode_failure: bool
    hard_mode_degradation: bool
    score_drop: float


class BenignCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    en_clean_benign: CaseSummary
    ko_clean_benign: CaseSummary
    benign_false_positive: bool


class CompareReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    headline: str
    generated_at: str
    metrics: CompareMetrics
    baseline_parity: BaselineParity
    ko_robustness: KORobustness
    benign_false_positive_check: BenignCheck
    caveats: list[str]
    cases: list[CaseSummary]


def validation_error_strings(exc: Exception) -> list[str]:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        out: list[str] = []
        for item in errors():
            loc = ".".join(str(x) for x in item.get("loc", []))
            msg = str(item.get("msg", "validation error"))
            out.append(f"{loc}: {msg}".strip(": "))
        return out
    return [str(exc)]
