from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .models import Scorecard


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

