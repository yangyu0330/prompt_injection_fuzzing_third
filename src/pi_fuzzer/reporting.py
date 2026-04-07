from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .models import Scorecard


def _render_bucket_table(lines: list[str], title: str, bucket: dict[str, Any]) -> None:
    lines.append(f"### {title}")
    if not bucket:
        lines.append("")
        lines.append("_no data_")
        lines.append("")
        return
    lines.append("")
    lines.append("| key | n | rate |")
    lines.append("|---|---:|---:|")
    for key, value in bucket.items():
        n = value.get("n", 0) if isinstance(value, dict) else 0
        rate = value.get("rate", 0.0) if isinstance(value, dict) else 0.0
        lines.append(f"| `{key}` | {n} | {float(rate):.4f} |")
    lines.append("")


def write_scorecard_json(scorecard: Scorecard, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(scorecard.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8")


def write_scorecard_markdown(scorecard: Scorecard, out_path: Path) -> None:
    s = scorecard.model_dump()
    lines: list[str] = []
    lines.append("# Prompt Injection Benchmark Report")
    lines.append("")
    lines.append("## Run")
    for k, v in s["run"].items():
        lines.append(f"- `{k}`: {v}")
    lines.append("")
    lines.append("## Metrics")
    for k, v in s["metrics"].items():
        lines.append(f"- `{k}`: {v:.4f}" if isinstance(v, (float, int)) else f"- `{k}`: {v}")
    lines.append("")
    lines.append("## By Enforcement Mode")
    for mode, bucket in s["by_enforcement_mode"].items():
        lines.append(f"- `{mode}`: n={bucket.get('n', 0)}, effective_pass_rate={bucket.get('effective_pass_rate', 0):.4f}, blocked_effectively_rate={bucket.get('blocked_effectively_rate', 0):.4f}")
    lines.append("")
    lines.append("## Coverage")
    lines.append(f"- `passed`: {s['coverage'].get('passed')}")
    if s["coverage"].get("failed_cells"):
        lines.append(f"- `failed_cells`: {s['coverage']['failed_cells']}")
    lines.append("")
    lines.append("## Korean Root Cause")
    _render_bucket_table(lines, "By Analysis Axis", s.get("by_analysis_axis", {}))
    _render_bucket_table(lines, "By Primary Mutation", s.get("by_primary_mutation", {}))
    _render_bucket_table(lines, "By Primary Target Entity", s.get("by_primary_target_entity", {}))
    _render_bucket_table(lines, "By Register Level", s.get("by_register_level", {}))
    _render_bucket_table(lines, "By Failure Stage", s.get("by_failure_stage", {}))
    _render_bucket_table(lines, "By Execution Layer", s.get("by_execution_layer", {}))
    _render_bucket_table(lines, "By Source Stage", s.get("by_source_stage", {}))
    _render_bucket_table(lines, "By Source Role", s.get("by_source_role", {}))
    _render_bucket_table(lines, "By Expected Interpretation", s.get("by_expected_interpretation", {}))
    _render_bucket_table(lines, "By Detector Family", s.get("by_detector_family", {}))
    _render_bucket_table(lines, "By Failure Cause Code", s.get("by_failure_cause_code", {}))
    _render_bucket_table(lines, "By Policy Mode", s.get("by_policy_mode", {}))
    _render_bucket_table(lines, "By Policy Request vs Execution", s.get("by_policy_request_vs_execution", {}))
    _render_bucket_table(lines, "By Raw Policy Action", s.get("by_raw_policy_action", {}))
    _render_bucket_table(lines, "By Reason Code", s.get("by_reason_code", {}))
    _render_bucket_table(lines, "By Tool Transition", s.get("by_tool_transition", {}))
    _render_bucket_table(lines, "By Final User Visible", s.get("by_final_user_visible", {}))
    _render_bucket_table(lines, "By Config Sensitivity", s.get("by_config_sensitivity", {}))
    _render_bucket_table(lines, "By Vendor Claim Gap", s.get("by_vendor_claim_gap", {}))
    _render_bucket_table(lines, "By Language Route", s.get("by_language_route", {}))
    _render_bucket_table(lines, "By Guard Stage Alignment", s.get("by_guard_stage_alignment", {}))
    lines.append("### By Contrast Group Outcome")
    contrast = s.get("by_contrast_group_outcome", {})
    if not contrast:
        lines.append("")
        lines.append("_no data_")
    else:
        lines.append("")
        lines.append("| contrast_group_id | roles_present | attack_run_count | benign_run_count | attack_success_rate | benign_overblock_rate | ko_en_gap |")
        lines.append("|---|---|---:|---:|---:|---:|---:|")
        for gid, item in contrast.items():
            if not isinstance(item, dict):
                continue
            roles = ",".join(item.get("roles_present", []))
            lines.append(
                f"| `{gid}` | `{roles}` | {int(item.get('attack_run_count', 0))} | {int(item.get('benign_run_count', 0))} | "
                f"{float(item.get('attack_success_rate', 0.0)):.4f} | {float(item.get('benign_overblock_rate', 0.0)):.4f} | "
                f"{float(item.get('ko_en_gap', 0.0)):.4f} |"
            )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_results_csv(scorecard: Scorecard, out_path: Path) -> None:
    rows = scorecard.results
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        out_path.write_text("", encoding="utf-8")
        return
    keys: list[str] = sorted(set().union(*(row.keys() for row in rows)))
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
