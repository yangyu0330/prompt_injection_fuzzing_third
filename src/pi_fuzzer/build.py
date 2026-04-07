from __future__ import annotations

import datetime as dt
from itertools import product
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


def _default_coverage_matrix_path(root: Path) -> Path:
    return root / "catalogs" / "coverage_matrix.yaml"


def _value_matches(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.strip().lower() == expected.strip().lower()
    return str(actual) == str(expected)


def _case_matches_filters(case: CaseRecord, filters: dict[str, Any]) -> bool:
    for field, expected in (filters or {}).items():
        actual = getattr(case, field, None)
        if isinstance(expected, list):
            if not any(_value_matches(actual, item) for item in expected):
                return False
        else:
            if not _value_matches(actual, expected):
                return False
    return True


def _resolve_coverage_profiles(cfg: dict[str, Any], project_root: Path) -> list[dict[str, Any]]:
    coverage_cfg = cfg.get("coverage_gate", {}) or {}
    profiles_ref = coverage_cfg.get("profiles")
    if not profiles_ref:
        return [
            {
                "name": "legacy_default",
                "required_dims": coverage_cfg.get("require_cells", ["language", "source_stage", "directness", "attack_family"]),
                "min_per_cell": int(coverage_cfg.get("min_per_cell", 1)),
                "filters": coverage_cfg.get("filters", {}) or {},
                "required_values": coverage_cfg.get("required_values", {}) or {},
            }
        ]

    matrix_rel = Path(str(coverage_cfg.get("matrix_path", "catalogs/coverage_matrix.yaml")))
    matrix_path = project_root / matrix_rel
    if not matrix_path.exists():
        matrix_path = _default_coverage_matrix_path(project_root)
    matrix_cfg = load_yaml(matrix_path) if matrix_path.exists() else {}

    resolved: list[dict[str, Any]] = []
    for item in profiles_ref:
        profile: dict[str, Any]
        if isinstance(item, str):
            profile = dict(matrix_cfg.get(item) or {})
            if not profile:
                raise ValueError(f"coverage_gate.profiles references unknown profile: {item}")
            profile["name"] = item
        elif isinstance(item, dict):
            profile = dict(item)
            profile.setdefault("name", "inline_profile")
        else:
            raise ValueError("coverage_gate.profiles entries must be profile names or dict objects")
        profile.setdefault("required_dims", [])
        profile.setdefault("min_per_cell", 1)
        profile.setdefault("filters", {})
        profile.setdefault("required_values", {})
        resolved.append(profile)
    return resolved


def _coverage_profile_violations(
    cases: list[CaseRecord],
    profile: dict[str, Any],
    splits: set[str] | None,
) -> list[dict[str, Any]]:
    profile_name = str(profile.get("name", "unnamed_profile"))
    filtered = [
        c
        for c in cases
        if (splits is None or c.split in splits) and _case_matches_filters(c, profile.get("filters", {}) or {})
    ]
    min_count = int(profile.get("min_per_cell", 1))
    violations: list[dict[str, Any]] = []

    dims = list(profile.get("required_dims", []) or [])
    if dims:
        for v in enforce_min_cell_coverage(filtered, dims=dims, min_count=min_count, splits=None):
            violations.append(
                {
                    "profile": profile_name,
                    "kind": "cell",
                    "key": list(v.key),
                    "count": v.count,
                    "required": v.required,
                }
            )

    required_values = profile.get("required_values", {}) or {}
    required_value_lists: dict[str, list[Any]] = {}
    for field, spec in required_values.items():
        if isinstance(spec, dict):
            values = spec.get("values", []) or []
            required = int(spec.get("min_per_value", min_count))
        elif isinstance(spec, list):
            values = spec
            required = min_count
        else:
            values = [spec]
            required = min_count
        required_value_lists[field] = list(values)
        for required_value in values:
            count = sum(1 for c in filtered if _value_matches(getattr(c, field, None), required_value))
            if count < required:
                violations.append(
                    {
                        "profile": profile_name,
                        "kind": "required_value",
                        "key": [str(field), str(required_value)],
                        "count": count,
                        "required": required,
                    }
                )

    if bool(profile.get("enforce_cartesian", False)):
        missing_dims = [d for d in dims if d not in required_value_lists]
        if missing_dims:
            raise ValueError(
                f"coverage profile '{profile_name}' requires required_values for all required_dims when enforce_cartesian=true; missing: {missing_dims}"
            )
        cartesian_counts: dict[tuple[str, ...], int] = {}
        if dims:
            for c in filtered:
                key = tuple(str(getattr(c, d)) for d in dims)
                cartesian_counts[key] = cartesian_counts.get(key, 0) + 1
        expected_lists = [required_value_lists[d] for d in dims]
        for combo in product(*expected_lists):
            combo_key = tuple(str(v) for v in combo)
            count = int(cartesian_counts.get(combo_key, 0))
            if count < min_count:
                violations.append(
                    {
                        "profile": profile_name,
                        "kind": "cartesian_cell",
                        "key": list(combo_key),
                        "count": count,
                        "required": min_count,
                    }
                )

    required_combinations = profile.get("required_combinations", []) or []
    for combo in required_combinations:
        if not isinstance(combo, dict):
            continue
        combo_min_count = int(combo.get("min_count", min_count))
        values = {k: v for k, v in combo.items() if k != "min_count"}
        count = sum(
            1
            for c in filtered
            if all(_value_matches(getattr(c, field, None), expected) for field, expected in values.items())
        )
        if count < combo_min_count:
            violations.append(
                {
                    "profile": profile_name,
                    "kind": "required_combination",
                    "key": [f"{k}={v}" for k, v in values.items()],
                    "count": count,
                    "required": combo_min_count,
                }
            )
    return violations


def _run_coverage_gate(
    cases: list[CaseRecord],
    profiles: list[dict[str, Any]],
    splits: set[str] | None,
) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for profile in profiles:
        violations.extend(_coverage_profile_violations(cases, profile, splits=splits))
    return violations


def _coverage_split_scope_for_mode(mode: str) -> set[str] | None:
    if str(mode).lower() == "release":
        return {"heldout_static", "adaptive"}
    return None


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
        profiles = _resolve_coverage_profiles(cfg, project_root)
        split_scope = _coverage_split_scope_for_mode(build_cfg.get("mode", "dev"))
        coverage_violations = _run_coverage_gate(
            cases,
            splits=split_scope,
            profiles=profiles,
        )
        if coverage_violations:
            sample = ", ".join(
                [
                    f"{v['profile']}:{v['kind']}:{tuple(v['key'])}:{v['count']}/{v['required']}"
                    for v in coverage_violations[:8]
                ]
            )
            raise ValueError(f"Coverage gate failed ({len(coverage_violations)} violations): {sample}")

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
        build_cfg = cfg.get("build", {}) or {}
        resolved_cfg = config_path.resolve()
        project_root = resolved_cfg.parents[1] if len(resolved_cfg.parents) > 1 else Path.cwd()
        profiles = _resolve_coverage_profiles(cfg, project_root)
        split_scope = _coverage_split_scope_for_mode(build_cfg.get("mode", "dev"))
        violations = _run_coverage_gate(cases, profiles=profiles, splits=split_scope)
        coverage = {
            "checked": True,
            "split_scope": sorted(split_scope) if split_scope else "all_splits",
            "profiles": [
                {
                    "name": str(p.get("name", "unnamed_profile")),
                    "required_dims": list(p.get("required_dims", []) or []),
                    "min_per_cell": int(p.get("min_per_cell", 1)),
                    "filters": dict(p.get("filters", {}) or {}),
                    "required_values": dict(p.get("required_values", {}) or {}),
                    "enforce_cartesian": bool(p.get("enforce_cartesian", False)),
                    "required_combinations": list(p.get("required_combinations", []) or []),
                }
                for p in profiles
            ],
            "violations": violations,
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
