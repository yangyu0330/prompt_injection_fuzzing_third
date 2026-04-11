from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Any

import torch
import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from transformers import AutoModelForSequenceClassification, AutoTokenizer

try:
    from scripts.schemas import (
        ErrorDetail,
        ErrorEnvelope,
        GatewayRequest,
        GatewayResponse,
        PromptGuardRequest,
        PromptGuardResponse,
        validation_error_strings,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback
    from schemas import (  # type: ignore
        ErrorDetail,
        ErrorEnvelope,
        GatewayRequest,
        GatewayResponse,
        PromptGuardRequest,
        PromptGuardResponse,
        validation_error_strings,
    )


DEFAULT_MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"


@dataclass
class ServerSettings:
    model_id: str = DEFAULT_MODEL_ID
    threshold: float = 0.5
    window_size: int = 448
    overlap: int = 64
    host: str = "127.0.0.1"
    port: int = 8787


SETTINGS = ServerSettings(
    model_id=os.getenv("PROMPT_GUARD_MODEL_ID", DEFAULT_MODEL_ID),
    threshold=float(os.getenv("PROMPT_GUARD_THRESHOLD", "0.5")),
    window_size=int(os.getenv("PROMPT_GUARD_WINDOW_SIZE", "448")),
    overlap=int(os.getenv("PROMPT_GUARD_OVERLAP", "64")),
)


class PromptGuardScorer:
    def __init__(self, settings: ServerSettings):
        if settings.overlap >= settings.window_size:
            raise ValueError("overlap must be smaller than window_size")
        self.settings = settings
        self.tokenizer = AutoTokenizer.from_pretrained(settings.model_id)
        self.model = AutoModelForSequenceClassification.from_pretrained(settings.model_id)
        self.model.eval()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.malicious_index, self.benign_index = self._infer_label_indices()

    def _infer_label_indices(self) -> tuple[int, int]:
        id2label = getattr(self.model.config, "id2label", {}) or {}
        num_labels = int(getattr(self.model.config, "num_labels", 2))
        malicious_index = 1 if num_labels > 1 else 0
        benign_index = 0

        for idx, raw_label in id2label.items():
            label = str(raw_label).strip().lower()
            if any(token in label for token in ("malicious", "jailbreak", "inject", "unsafe")):
                malicious_index = int(idx)
            if any(token in label for token in ("benign", "safe", "clean")):
                benign_index = int(idx)
        if malicious_index == benign_index and num_labels > 1:
            benign_index = 0
            malicious_index = 1
        return malicious_index, benign_index

    def _segment_text(self, text: str) -> list[str]:
        token_ids = self.tokenizer.encode(text, add_special_tokens=False)
        if not token_ids:
            return [text]
        if len(token_ids) <= self.settings.window_size:
            return [text]

        step = max(1, self.settings.window_size - self.settings.overlap)
        out: list[str] = []
        for start in range(0, len(token_ids), step):
            chunk = token_ids[start : start + self.settings.window_size]
            if not chunk:
                break
            out.append(self.tokenizer.decode(chunk, skip_special_tokens=True))
            if start + self.settings.window_size >= len(token_ids):
                break
        return out

    def score(self, req: PromptGuardRequest) -> PromptGuardResponse:
        combined_text = "\n\n".join([req.trusted_instruction, req.user_goal, req.text])
        segments = self._segment_text(combined_text)
        malicious_scores: list[float] = []
        benign_scores: list[float] = []

        with torch.no_grad():
            for seg in segments:
                encoded = self.tokenizer(
                    seg,
                    return_tensors="pt",
                    truncation=True,
                    max_length=self.settings.window_size,
                )
                encoded = {k: v.to(self.device) for k, v in encoded.items()}
                logits = self.model(**encoded).logits[0]
                probs = torch.softmax(logits, dim=-1)
                malicious = float(probs[self.malicious_index].item())
                if self.benign_index < probs.shape[0]:
                    benign = float(probs[self.benign_index].item())
                else:
                    benign = 1.0 - malicious
                malicious_scores.append(malicious)
                benign_scores.append(benign)

        max_idx = max(range(len(malicious_scores)), key=lambda i: malicious_scores[i])
        malicious_score = float(malicious_scores[max_idx])
        benign_score = float(benign_scores[max_idx])
        detected = malicious_score >= self.settings.threshold
        label = "MALICIOUS" if detected else "BENIGN"
        return PromptGuardResponse(
            detected=detected,
            label=label,
            malicious_score=malicious_score,
            benign_score=benign_score,
            segment_count=len(segments),
            max_segment_index=max_idx,
            model_id=self.settings.model_id,
        )


app = FastAPI(title="Prompt Guard HTTP Adapter")


@app.exception_handler(RequestValidationError)
async def request_validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    body = ErrorEnvelope(
        error=ErrorDetail(
            code="INVALID_REQUEST_SCHEMA",
            message="Request body does not match schema",
            details=validation_error_strings(exc),
        )
    )
    return JSONResponse(status_code=422, content=body.model_dump())


@app.on_event("startup")
def startup_event() -> None:
    app.state.scorer = PromptGuardScorer(SETTINGS)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model_id": SETTINGS.model_id,
        "window_size": SETTINGS.window_size,
        "overlap": SETTINGS.overlap,
    }


@app.post("/detect", response_model=PromptGuardResponse)
def detect(payload: PromptGuardRequest) -> PromptGuardResponse:
    scorer: PromptGuardScorer = app.state.scorer
    return scorer.score(payload)


def _apply_enforcement(detected: bool, enforcement_mode: str) -> tuple[bool, bool, bool]:
    masked = detected and enforcement_mode == "mask"
    blocked = detected and enforcement_mode == "block"
    effective_pass = not blocked
    return masked, blocked, effective_pass


@app.post("/gateway/evaluate", response_model=GatewayResponse)
def gateway_evaluate(payload: GatewayRequest) -> GatewayResponse:
    scorer: PromptGuardScorer = app.state.scorer
    scored = scorer.score(
        PromptGuardRequest(
            text=payload.text,
            trusted_instruction=payload.trusted_instruction,
            user_goal=payload.user_goal,
            metadata=payload.metadata,
        )
    )
    detected_pre = payload.guardrail_toggle == "on" and scored.detected
    detected_post = False
    masked, blocked_effectively, effective_pass = _apply_enforcement(
        detected_pre or detected_post,
        payload.enforcement_mode.value,
    )
    enum_cls = type(payload.enforcement_mode)
    policy_executed = payload.enforcement_mode
    if blocked_effectively:
        policy_executed = enum_cls.BLOCK
    elif masked:
        policy_executed = enum_cls.MASK
    elif detected_pre or detected_post:
        policy_executed = enum_cls.ANNOTATE
    else:
        policy_executed = enum_cls.ALLOW
    return GatewayResponse(
        detected_pre=detected_pre,
        detected_post=detected_post,
        masked=masked,
        blocked_effectively=blocked_effectively,
        effective_pass=effective_pass,
        label=scored.label,
        malicious_score=scored.malicious_score,
        benign_score=scored.benign_score,
        segment_count=scored.segment_count,
        max_segment_index=scored.max_segment_index,
        model_id=scored.model_id,
        policy_executed=policy_executed,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prompt Guard HTTP adapter server")
    parser.add_argument("--host", default=SETTINGS.host)
    parser.add_argument("--port", type=int, default=SETTINGS.port)
    parser.add_argument("--model-id", default=SETTINGS.model_id)
    parser.add_argument("--threshold", type=float, default=SETTINGS.threshold)
    parser.add_argument("--window-size", type=int, default=SETTINGS.window_size)
    parser.add_argument("--overlap", type=int, default=SETTINGS.overlap)
    return parser.parse_args()


def main() -> None:
    global SETTINGS
    args = parse_args()
    SETTINGS = ServerSettings(
        model_id=args.model_id,
        threshold=args.threshold,
        window_size=args.window_size,
        overlap=args.overlap,
        host=args.host,
        port=args.port,
    )
    uvicorn.run(app, host=SETTINGS.host, port=SETTINGS.port, log_level="info")


if __name__ == "__main__":
    main()
