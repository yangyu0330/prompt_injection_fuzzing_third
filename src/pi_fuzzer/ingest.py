from __future__ import annotations

from pathlib import Path
from typing import Any

from .io_utils import read_json, read_jsonl, write_jsonl
from .models import CaseRecord, TemplateRecord
from .text_utils import stable_key


SOURCE_LICENSE = {
    "bipia": ("public benchmark", "normalized_only"),
    "llmail-inject": ("public benchmark", "normalized_only"),
    "injecagent": ("public benchmark", "normalized_only"),
    "agentdojo": ("public benchmark", "normalized_only"),
    "pint-xstest": ("public benchmark", "normalized_only"),
}


def _load_any(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        return read_jsonl(path)
    if path.suffix.lower() == ".json":
        obj = read_json(path)
        if isinstance(obj, list):
            return obj
        if isinstance(obj, dict):
            if "data" in obj and isinstance(obj["data"], list):
                return obj["data"]
            return [obj]
    raise ValueError(f"Unsupported input format: {path}")


def normalize_public_source(source: str, rows: list[dict[str, Any]]) -> tuple[list[TemplateRecord], list[CaseRecord]]:
    src = source.lower()
    license_note, redistribution_policy = SOURCE_LICENSE.get(src, ("unknown", "restricted"))
    templates: dict[str, TemplateRecord] = {}
    cases: list[CaseRecord] = []

    for idx, row in enumerate(rows, start=1):
        attack_family = str(row.get("attack_family") or _guess_attack_family(src))
        directness = str(row.get("directness") or ("indirect" if "indirect" in attack_family else "direct"))
        source_stage = str(row.get("source_stage") or "input")
        turn_mode = str(row.get("turn_mode") or "single_turn")
        lang = str(row.get("language") or row.get("lang") or "en").lower()
        template_id = str(row.get("template_id") or f"TMP-{src.upper()}-{idx:05d}")
        case_id = str(row.get("case_id") or f"CASE-{src.upper()}-{idx:05d}")
        trusted = str(row.get("trusted_instruction") or "<TRUSTED_INSTRUCTION_PLACEHOLDER>")
        untrusted = str(row.get("untrusted_content") or "<UNTRUSTED_CONTENT_PLACEHOLDER>")
        user_goal = str(row.get("user_goal") or "<USER_GOAL_PLACEHOLDER>")
        entry_point = str(row.get("entry_point") or _guess_entry_point(src))

        if template_id not in templates:
            templates[template_id] = TemplateRecord(
                template_id=template_id,
                template_kind="diagnostic_attack" if attack_family != "benign_hard_negative" else "benign_hard_negative",
                attack_or_benign="benign" if attack_family == "benign_hard_negative" else "attack",
                attack_family=attack_family,
                attack_subfamily=str(row.get("attack_subfamily") or "normalized_ingest"),
                directness=directness,
                source_stage=source_stage,
                turn_mode=turn_mode,
                supported_entry_points=[entry_point],
                supported_carriers=[str(row.get("carrier_context") or "plain_chat")],
                user_goal_skeleton="<USER_GOAL_PLACEHOLDER>",
                trusted_instruction_skeleton="<TRUSTED_INSTRUCTION_PLACEHOLDER>",
                untrusted_content_skeleton="<UNTRUSTED_CONTENT_PLACEHOLDER>",
                protected_asset=[str(row.get("protected_asset") or "policy_boundary")],
                forbidden_action=[str(row.get("forbidden_action") or "follow_untrusted_instruction")],
                expected_safe_behavior=str(row.get("expected_safe_behavior") or "<EXPECTED_SAFE_BEHAVIOR_PLACEHOLDER>"),
                tool_scope=str(row.get("tool_scope") or "none"),
                oracle_type=[str(row.get("oracle_type") or "task_checker")],
                severity=str(row.get("severity") or "S2"),
                recommended_layer=[str(row.get("recommended_layer") or "L1")],
                semantic_equivalence_group=str(row.get("semantic_equivalence_group") or f"SEG-{src.upper()}-{idx:05d}"),
                source_origin=f"ingest_{src}",
                license_note=license_note,
                redistribution_policy=redistribution_policy,
                notes="normalized from public benchmark",
            )

        case = CaseRecord(
            template_id=template_id,
            case_id=case_id,
            language=lang,
            paired_case_id=row.get("paired_case_id"),
            attack_or_benign="benign" if attack_family == "benign_hard_negative" else "attack",
            attack_family=attack_family,
            attack_subfamily=str(row.get("attack_subfamily") or "normalized_ingest"),
            directness=directness,  # type: ignore[arg-type]
            source_stage=source_stage,  # type: ignore[arg-type]
            turn_mode=turn_mode,  # type: ignore[arg-type]
            entry_point=entry_point,
            carrier_context=str(row.get("carrier_context") or "plain_chat"),
            mutation_family=list(row.get("mutation_family") or ["normalized_ingest"]),
            user_goal=user_goal,
            trusted_instruction=trusted,
            untrusted_content=untrusted,
            protected_asset=list(row.get("protected_asset") or ["policy_boundary"]),
            forbidden_action=list(row.get("forbidden_action") or ["follow_untrusted_instruction"]),
            expected_safe_behavior=str(row.get("expected_safe_behavior") or "<EXPECTED_SAFE_BEHAVIOR_PLACEHOLDER>"),
            tool_scope=str(row.get("tool_scope") or "none"),
            oracle_type=list(row.get("oracle_type") or ["task_checker"]),
            severity=str(row.get("severity") or "S2"),
            split=str(row.get("split") or "dev_calibration"),  # type: ignore[arg-type]
            source_origin=f"ingest_{src}",
            license_note=license_note,
            redistribution_policy=redistribution_policy,
            notes="normalized from public benchmark",
            semantic_equivalence_group=str(row.get("semantic_equivalence_group") or stable_key([template_id, entry_point])),
            mutation_recipe_id=row.get("mutation_recipe_id"),
            reproducibility_seed=row.get("reproducibility_seed"),
            exclude_from_headline=bool(row.get("exclude_from_headline", False)),
        )
        cases.append(case)

    return list(templates.values()), cases


def ingest_public(source: str, input_path: Path, out_path: Path) -> dict[str, int]:
    rows = _load_any(input_path)
    templates, cases = normalize_public_source(source, rows)
    write_jsonl(out_path.with_name(out_path.stem + "_templates.jsonl"), [t.model_dump() for t in templates])
    write_jsonl(out_path, [c.model_dump() for c in cases])
    return {"templates": len(templates), "cases": len(cases)}


def _guess_attack_family(source: str) -> str:
    if source in {"bipia"}:
        return "indirect_document_web_rag"
    if source in {"llmail-inject"}:
        return "email_agent_injection"
    if source in {"injecagent"}:
        return "tool_agent_misuse"
    if source in {"agentdojo"}:
        return "tool_agent_misuse"
    if source in {"pint-xstest"}:
        return "benign_hard_negative"
    return "direct_user_injection"


def _guess_entry_point(source: str) -> str:
    if source == "bipia":
        return "retrieved_document"
    if source == "llmail-inject":
        return "email_body"
    if source in {"injecagent", "agentdojo"}:
        return "tool_output"
    if source == "pint-xstest":
        return "user_prompt"
    return "user_prompt"

