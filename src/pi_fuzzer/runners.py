from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .dispatch import build_request_payload, dispatch_http, map_response
from .models import CaseRecord, RunRecord, TargetConfig


def _stable_int(seed_text: str, low: int, high: int) -> int:
    digest = hashlib.sha256(seed_text.encode("utf-8")).hexdigest()
    val = int(digest[:8], 16)
    return low + (val % (high - low + 1))


def _base_run_record(
    case: CaseRecord,
    layer: str,
    target: TargetConfig,
    run_seed: int,
    repeat_index: int,
    guardrail_toggle: str,
    enforcement_mode: str,
) -> RunRecord:
    run_id = f"RUN-{layer}-{case.case_id}-{repeat_index}-{guardrail_toggle}-{enforcement_mode}"
    return RunRecord(
        run_id=run_id,
        case_id=case.case_id,
        template_id=case.template_id,
        layer=layer,  # type: ignore[arg-type]
        target_id=target.target_id,
        dispatcher_id=target.transport,
        system_config_id=f"CFG-{target.target_id}-{guardrail_toggle}-{enforcement_mode}",
        repeat_index=repeat_index,
        run_seed=run_seed,
        language=case.language,
        source_stage=case.source_stage,
        turn_mode=case.turn_mode,
        guardrail_toggle=guardrail_toggle,  # type: ignore[arg-type]
        enforcement_mode=enforcement_mode,  # type: ignore[arg-type]
    )


def _local_detection(case: CaseRecord, guardrail_toggle: str) -> bool:
    if case.attack_or_benign == "benign":
        return False
    if guardrail_toggle == "off":
        return False
    return True


def _apply_enforcement(detected: bool, enforcement_mode: str) -> tuple[bool, bool, bool]:
    masked = detected and enforcement_mode == "mask"
    blocked = detected and enforcement_mode == "block"
    effective_pass = not blocked
    return masked, blocked, effective_pass


def _variables(case: CaseRecord, guardrail_toggle: str, enforcement_mode: str) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "language": case.language,
        "source_stage": case.source_stage,
        "turn_mode": case.turn_mode,
        "entry_point": case.entry_point,
        "carrier_context": case.carrier_context,
        "guardrail_toggle": guardrail_toggle,
        "enforcement_mode": enforcement_mode,
        "trusted_instruction": case.trusted_instruction,
        "rendered_input": case.untrusted_content,
        "user_goal": case.user_goal,
    }


def _fill_perf(record: RunRecord) -> RunRecord:
    base = f"{record.run_id}|{record.case_id}|{record.enforcement_mode}"
    record.ttft_ms = float(_stable_int(base + "ttft", 120, 320))
    record.latency_ms = float(_stable_int(base + "lat", 480, 1200))
    record.throughput_rps = round(1000.0 / max(record.latency_ms, 1.0), 3)
    return record


def _write_transcript(record: RunRecord, out_dir: Path, payload: dict[str, Any], response: dict[str, Any]) -> RunRecord:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{record.run_id}.json"
    body = {"run_id": record.run_id, "payload": payload, "response": response}
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    record.request_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    record.response_hash = hashlib.sha256(json.dumps(response, sort_keys=True).encode("utf-8")).hexdigest()
    record.transcript_path = str(path.as_posix())
    return record


def run_text_only_case(
    case: CaseRecord,
    target: TargetConfig,
    out_dir: Path,
    run_seed: int,
    repeat_index: int,
    guardrail_toggle: str,
    enforcement_mode: str,
) -> RunRecord:
    record = _base_run_record(case, "L1", target, run_seed, repeat_index, guardrail_toggle, enforcement_mode)
    payload = build_request_payload(target, _variables(case, guardrail_toggle, enforcement_mode))
    response_data: dict[str, Any]

    if target.transport == "http":
        t0 = time.perf_counter()
        raw = dispatch_http(target, payload)
        record.latency_ms = (time.perf_counter() - t0) * 1000
        mapped = map_response(raw, target.response_field_map)
        response_data = raw
        record.detected_pre = bool(mapped.get("detected", False))
    else:
        response_data = {"local_detection": True}
        record.detected_pre = _local_detection(case, guardrail_toggle)

    record.detected_post = False
    record.masked, record.blocked_effectively, record.effective_pass = _apply_enforcement(
        record.detected_pre, enforcement_mode
    )
    record.benign_overblocked = case.attack_or_benign == "benign" and record.blocked_effectively
    if record.latency_ms <= 0:
        _fill_perf(record)
    else:
        record.ttft_ms = max(1.0, record.latency_ms * 0.25)
        record.throughput_rps = round(1000.0 / max(record.latency_ms, 1.0), 3)
    return _write_transcript(record, out_dir, payload, response_data)


def run_gateway_case(
    case: CaseRecord,
    target: TargetConfig,
    out_dir: Path,
    run_seed: int,
    repeat_index: int,
    guardrail_toggle: str,
    enforcement_mode: str,
) -> RunRecord:
    record = _base_run_record(case, "L2", target, run_seed, repeat_index, guardrail_toggle, enforcement_mode)
    payload = build_request_payload(target, _variables(case, guardrail_toggle, enforcement_mode))
    response_data: dict[str, Any]

    if target.transport == "http":
        t0 = time.perf_counter()
        raw = dispatch_http(target, payload)
        record.latency_ms = (time.perf_counter() - t0) * 1000
        mapped = map_response(raw, target.response_field_map)
        response_data = raw
        record.detected_pre = bool(mapped.get("detected_pre", False))
        record.detected_post = bool(mapped.get("detected_post", False))
        record.masked = bool(mapped.get("masked", False))
        record.blocked_effectively = bool(mapped.get("blocked_effectively", False))
        record.effective_pass = bool(mapped.get("effective_pass", not record.blocked_effectively))
    else:
        response_data = {"local_gateway": True}
        record.detected_pre = _local_detection(case, guardrail_toggle)
        record.detected_post = record.detected_pre and case.source_stage == "output"
        record.masked, record.blocked_effectively, record.effective_pass = _apply_enforcement(
            record.detected_pre or record.detected_post, enforcement_mode
        )

    record.benign_overblocked = case.attack_or_benign == "benign" and record.blocked_effectively
    if record.latency_ms <= 0:
        _fill_perf(record)
    else:
        record.ttft_ms = max(1.0, record.latency_ms * 0.3)
        record.throughput_rps = round(1000.0 / max(record.latency_ms, 1.0), 3)
    return _write_transcript(record, out_dir, payload, response_data)


def run_scenario_case(
    case: CaseRecord,
    target: TargetConfig,
    out_dir: Path,
    run_seed: int,
    repeat_index: int,
    guardrail_toggle: str,
    enforcement_mode: str,
) -> RunRecord:
    record = _base_run_record(case, "L3", target, run_seed, repeat_index, guardrail_toggle, enforcement_mode)
    payload = build_request_payload(target, _variables(case, guardrail_toggle, enforcement_mode))
    response_data = {"local_scenario": True}

    detected = _local_detection(case, guardrail_toggle)
    record.detected_pre = detected
    record.detected_post = detected and case.source_stage == "output"
    record.masked, record.blocked_effectively, record.effective_pass = _apply_enforcement(detected, enforcement_mode)

    scenario = case.attack_subfamily.lower()
    attack = case.attack_or_benign == "attack"
    bypass = attack and guardrail_toggle == "off"
    partial_bypass = attack and guardrail_toggle == "on" and enforcement_mode in {"allow", "annotate"}

    if "secret" in scenario:
        record.secret_exposed = bypass or partial_bypass
    if "unauthorized" in scenario or "tool" in scenario:
        record.unauthorized_tool_used = bypass or partial_bypass
    if "hijack" in scenario:
        record.task_hijacked = bypass or partial_bypass

    record.task_completed_safely = not (record.secret_exposed or record.unauthorized_tool_used or record.task_hijacked)
    record.benign_overblocked = case.attack_or_benign == "benign" and record.blocked_effectively
    _fill_perf(record)
    return _write_transcript(record, out_dir, payload, response_data)

