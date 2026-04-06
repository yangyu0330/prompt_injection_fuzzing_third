from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from .io_utils import dump_json, load_yaml, read_jsonl, write_jsonl
from .models import CaseRecord, TemplateRecord
from .text_utils import stable_key
from .validation import (
    dedup_cases,
    enforce_min_cell_coverage,
    validate_analysis_linkage,
    validate_pair_invariants,
    validate_split_contamination,
)


def _default_template_sources(root: Path) -> list[Path]:
    return [root / "catalogs" / "sample_templates.jsonl"]


def _default_case_sources(root: Path) -> list[Path]:
    return [root / "catalogs" / "sample_cases.jsonl"]


def _load_templates(paths: list[Path]) -> list[TemplateRecord]:
    rows: list[TemplateRecord] = []
    for p in paths:
        rows.extend(TemplateRecord(**row) for row in read_jsonl(p))
    return rows


def _load_cases(paths: list[Path]) -> list[CaseRecord]:
    rows: list[CaseRecord] = []
    for p in paths:
        rows.extend(CaseRecord(**row) for row in read_jsonl(p))
    return rows


def _deterministic_split(case: CaseRecord, seed: int, targets: dict[str, float]) -> str:
    key = stable_key([case.semantic_equivalence_group or case.template_id, str(seed)])
    val = int(key[:8], 16) / 0xFFFFFFFF
    running = 0.0
    for split_name, pct in targets.items():
        running += float(pct)
        if val <= running:
            return split_name
    return list(targets.keys())[-1]


def _assign_splits(cases: list[CaseRecord], seed: int, targets: dict[str, float]) -> list[CaseRecord]:
    by_group: dict[str, str] = {}
    assigned: list[CaseRecord] = []
    for c in cases:
        key = c.semantic_equivalence_group or c.template_id
        split = by_group.get(key)
        if split is None:
            split = _deterministic_split(c, seed=seed, targets=targets)
            by_group[key] = split
        assigned.append(c.model_copy(update={"split": split}))
    return assigned


def build_package(config_path: Path, out_dir: Path, project_root: Path) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    build_cfg = cfg.get("build", {})
    split_cfg = cfg.get("split", {}).get("targets", {})
    if not split_cfg:
        split_cfg = {
            "dev_calibration": 0.2,
            "heldout_static": 0.45,
            "adaptive": 0.15,
            "benign_hard_negative": 0.2,
        }

    template_sources = [project_root / Path(p) for p in cfg.get("template_sources", [])] or _default_template_sources(project_root)
    case_sources = [project_root / Path(p) for p in cfg.get("case_sources", [])] or _default_case_sources(project_root)
    templates = _load_templates(template_sources)
    cases = _load_cases(case_sources)

    seed = int(build_cfg.get("seed", 20260403))
    cases = _assign_splits(cases, seed=seed, targets=split_cfg)

    dedup_cfg = cfg.get("dedup", {})
    dedup_mode = str(dedup_cfg.get("mode", "structured_only"))
    similarity_threshold = float(dedup_cfg.get("similarity_threshold", 0.92))

    release_mode = str(build_cfg.get("mode", "dev")).lower() == "release"
    if release_mode and dedup_mode != "hybrid_mandatory":
        raise ValueError("Release build requires dedup.mode=hybrid_mandatory")

    if release_mode:
        held_adp = [c for c in cases if c.split in {"heldout_static", "adaptive"}]
        other = [c for c in cases if c.split not in {"heldout_static", "adaptive"}]
        kept, drops = dedup_cases(held_adp, mode="hybrid_mandatory", similarity_threshold=similarity_threshold)
        cases = sorted(other + kept, key=lambda c: c.case_id)
    else:
        cases, drops = dedup_cases(cases, mode=dedup_mode, similarity_threshold=similarity_threshold)

    pair_errors = validate_pair_invariants(cases)
    split_errors = validate_split_contamination(cases)
    analysis_errors = validate_analysis_linkage(cases)
    if pair_errors or split_errors or analysis_errors:
        msgs = "\n".join(pair_errors + split_errors + analysis_errors)
        raise ValueError(f"Validation failed:\n{msgs}")

    coverage_cfg = cfg.get("coverage_gate", {})
    if coverage_cfg.get("enabled", True):
        dims = coverage_cfg.get(
            "require_cells",
            ["language", "source_stage", "directness", "attack_family"],
        )
        min_count = int(coverage_cfg.get("min_per_cell", 1))
        coverage_violations = enforce_min_cell_coverage(
            cases,
            dims=dims,
            min_count=min_count,
            splits={"heldout_static", "adaptive"} if release_mode else None,
        )
        if coverage_violations:
            sample = ", ".join([f"{v.key}:{v.count}/{v.required}" for v in coverage_violations[:8]])
            raise ValueError(f"Coverage gate failed ({len(coverage_violations)} cells): {sample}")

    out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(out_dir / "templates.jsonl", [t.model_dump() for t in sorted(templates, key=lambda x: x.template_id)])
    write_jsonl(out_dir / "cases.jsonl", [c.model_dump() for c in sorted(cases, key=lambda x: x.case_id)])
    write_jsonl(out_dir / "dedup_drops.jsonl", drops)

    manifest = {
        "package_id": build_cfg.get("package_id", "pi-benchmark-dev"),
        "package_version": build_cfg.get("package_version", "0.1.0"),
        "schema_version": build_cfg.get("schema_version", "1.0.0"),
        "taxonomy_version": build_cfg.get("taxonomy_version", "2026-04-source-truth"),
        "build_seed": seed,
        "mode": build_cfg.get("mode", "dev"),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "template_count": len(templates),
        "case_count": len(cases),
        "dedup_drop_count": len(drops),
        "template_sources": [str(p) for p in template_sources],
        "case_sources": [str(p) for p in case_sources],
        "config_path": str(config_path),
    }
    dump_json(out_dir / "manifest.json", manifest)
    return manifest


def validate_package(package_dir: Path, config_path: Path | None = None) -> dict[str, Any]:
    templates = [TemplateRecord(**row) for row in read_jsonl(package_dir / "templates.jsonl")]
    cases = [CaseRecord(**row) for row in read_jsonl(package_dir / "cases.jsonl")]
    pair_errors = validate_pair_invariants(cases)
    split_errors = validate_split_contamination(cases)
    analysis_errors = validate_analysis_linkage(cases)

    coverage = {"checked": False, "violations": []}
    if config_path and config_path.exists():
        cfg = load_yaml(config_path)
        coverage_cfg = cfg.get("coverage_gate", {})
        dims = coverage_cfg.get(
            "require_cells",
            ["language", "source_stage", "directness", "attack_family"],
        )
        min_count = int(coverage_cfg.get("min_per_cell", 1))
        violations = enforce_min_cell_coverage(cases, dims=dims, min_count=min_count, splits=None)
        coverage = {
            "checked": True,
            "dims": dims,
            "min_per_cell": min_count,
            "violations": [{"key": list(v.key), "count": v.count, "required": v.required} for v in violations],
        }
    ok = not pair_errors and not split_errors and not analysis_errors and not coverage["violations"]
    return {
        "ok": ok,
        "templates": len(templates),
        "cases": len(cases),
        "pair_errors": pair_errors,
        "split_errors": split_errors,
        "analysis_errors": analysis_errors,
        "coverage": coverage,
    }
