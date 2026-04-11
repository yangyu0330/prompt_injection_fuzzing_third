from __future__ import annotations

from pathlib import Path
from typing import Any

from .guardrail_adapters import has_response_adapter, list_response_adapters
from .io_utils import load_yaml, read_json, read_jsonl, write_jsonl
from .models import CaseRecord, RunRecord, TargetConfig, TemplateRecord


def load_package(package_dir: Path) -> tuple[list[TemplateRecord], list[CaseRecord], dict[str, Any]]:
    templates = [TemplateRecord(**row) for row in read_jsonl(package_dir / "templates.jsonl")]
    cases = [CaseRecord(**row) for row in read_jsonl(package_dir / "cases.jsonl")]
    manifest_path = package_dir / "manifest.json"
    manifest = read_json(manifest_path) if manifest_path.exists() else {}
    return templates, cases, manifest


def load_target_config(path: Path) -> TargetConfig:
    cfg = load_yaml(path)
    adapter_name = str(cfg.get("response_adapter", "")).strip()
    if adapter_name and not has_response_adapter(adapter_name):
        supported = ", ".join(list_response_adapters())
        raise ValueError(
            f"unsupported response_adapter `{adapter_name}` in {path}; supported: {supported}"
        )
    return TargetConfig(**cfg)


def save_runs(path: Path, runs: list[RunRecord]) -> None:
    write_jsonl(path, [r.model_dump() for r in runs])


def load_runs(paths: list[Path]) -> list[RunRecord]:
    out: list[RunRecord] = []
    for p in paths:
        if p.is_dir():
            for file in sorted(p.glob("*.jsonl")):
                out.extend(RunRecord(**row) for row in read_jsonl(file))
        else:
            out.extend(RunRecord(**row) for row in read_jsonl(p))
    return out
