from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any


DEFAULT_PROMPT_GUARD_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"
DEFAULT_DETECTION_THRESHOLD = 0.5
DEFAULT_POSITIVE_HINTS = (
    "attack",
    "inject",
    "jailbreak",
    "malicious",
    "prompt",
    "unsafe",
    "violation",
    "LABEL_1",
)
DEFAULT_NEGATIVE_HINTS = ("benign", "clean", "normal", "safe", "LABEL_0")
MOCK_ATTACK_PATTERNS = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "developer message",
    "override policy",
    "tool call",
    "reveal secret",
    "prompt injection",
)


@dataclass(frozen=True)
class DetectionResult:
    detected: bool
    label: str
    score: float
    latency_ms: float
    detector_family: str = "llama_prompt_guard_2_86m"


def _normalize_label(value: str) -> str:
    return (value or "").strip()


def _contains_any_hint(text: str, hints: tuple[str, ...]) -> bool:
    normalized = text.lower()
    return any(hint.lower() in normalized for hint in hints)


def infer_detection(
    label_scores: dict[str, float],
    threshold: float = DEFAULT_DETECTION_THRESHOLD,
    positive_hints: tuple[str, ...] = DEFAULT_POSITIVE_HINTS,
    negative_hints: tuple[str, ...] = DEFAULT_NEGATIVE_HINTS,
) -> tuple[bool, str, float]:
    if not label_scores:
        return False, "unknown", 0.0

    top_label, top_score = max(label_scores.items(), key=lambda item: item[1])
    top_label = _normalize_label(top_label)
    top_score = float(top_score)

    if _contains_any_hint(top_label, negative_hints):
        return False, top_label, top_score
    if _contains_any_hint(top_label, positive_hints):
        return top_score >= threshold, top_label, top_score

    positive_candidates = [
        (label, score)
        for label, score in label_scores.items()
        if _contains_any_hint(label, positive_hints)
    ]
    if positive_candidates:
        strongest_label, strongest_score = max(positive_candidates, key=lambda item: item[1])
        return float(strongest_score) >= threshold, _normalize_label(strongest_label), float(strongest_score)

    # Last-resort fallback for unknown label maps.
    return top_score >= threshold, top_label, top_score


class PromptGuardDetector:
    def __init__(
        self,
        model_id: str = DEFAULT_PROMPT_GUARD_MODEL,
        threshold: float = DEFAULT_DETECTION_THRESHOLD,
        use_mock: bool = False,
    ) -> None:
        self.model_id = model_id
        self.threshold = threshold
        self.use_mock = use_mock
        self._tokenizer: Any = None
        self._model: Any = None
        self._torch: Any = None

    def _ensure_loaded(self) -> None:
        if self.use_mock or self._model is not None:
            return

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Prompt Guard runtime dependencies are missing. "
                "Install with: pip install -e \".[guardrail]\""
            ) from exc

        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
        self._model.eval()

    def _detect_mock(self, text: str) -> tuple[bool, str, float]:
        lowered = text.lower()
        detected = any(pattern in lowered for pattern in MOCK_ATTACK_PATTERNS)
        label = "unsafe" if detected else "safe"
        score = 0.99 if detected else 0.01
        return detected, label, score

    def _detect_model(self, text: str) -> tuple[bool, str, float]:
        self._ensure_loaded()
        assert self._tokenizer is not None
        assert self._model is not None
        assert self._torch is not None

        tokenized = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=2048,
        )
        with self._torch.no_grad():
            logits = self._model(**tokenized).logits
        probs = self._torch.softmax(logits, dim=-1).squeeze(0)

        id2label = getattr(self._model.config, "id2label", {}) or {}
        label_scores: dict[str, float] = {}
        for idx in range(probs.shape[0]):
            label = _normalize_label(str(id2label.get(int(idx), f"LABEL_{idx}")))
            label_scores[label] = float(probs[idx].item())

        return infer_detection(label_scores, threshold=self.threshold)

    def detect(self, text: str, trusted_instruction: str = "") -> DetectionResult:
        t0 = time.perf_counter()
        combined = text if not trusted_instruction else f"{trusted_instruction}\n\n{text}"

        if self.use_mock:
            detected, label, score = self._detect_mock(combined)
        else:
            detected, label, score = self._detect_model(combined)

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return DetectionResult(
            detected=bool(detected),
            label=label,
            score=float(score),
            latency_ms=float(latency_ms),
        )


def create_prompt_guard_app(detector: PromptGuardDetector):
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as exc:
        raise RuntimeError(
            "Prompt Guard server dependencies are missing. "
            "Install with: pip install -e \".[guardrail]\""
        ) from exc

    app = FastAPI(title="PI Fuzzer Prompt Guard Service", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "model_id": detector.model_id,
            "use_mock": detector.use_mock,
        }

    @app.post("/detect")
    def detect(request: dict[str, Any]) -> dict[str, Any]:
        text = request.get("text", "")
        trusted_instruction = request.get("trusted_instruction", "")
        if not isinstance(text, str):
            raise HTTPException(status_code=400, detail="`text` must be a string")
        if not isinstance(trusted_instruction, str):
            raise HTTPException(status_code=400, detail="`trusted_instruction` must be a string")
        try:
            result = detector.detect(
                text=text,
                trusted_instruction=trusted_instruction,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return {
            "result": {
                "detected": result.detected,
                "label": result.label,
                "score": result.score,
                "detector_family": result.detector_family,
            },
            "telemetry": {
                "latency_ms": result.latency_ms,
            },
        }

    return app


def run_prompt_guard_server(
    host: str = "127.0.0.1",
    port: int = 8011,
    model_id: str = DEFAULT_PROMPT_GUARD_MODEL,
    threshold: float = DEFAULT_DETECTION_THRESHOLD,
    use_mock: bool = False,
) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "uvicorn is required to run the Prompt Guard server. "
            "Install with: pip install -e \".[guardrail]\""
        ) from exc

    env_use_mock = os.getenv("PI_FUZZ_PROMPT_GUARD_MOCK", "").strip().lower() in {"1", "true", "yes"}
    detector = PromptGuardDetector(
        model_id=model_id,
        threshold=threshold,
        use_mock=use_mock or env_use_mock,
    )
    app = create_prompt_guard_app(detector)
    uvicorn.run(app, host=host, port=port)
