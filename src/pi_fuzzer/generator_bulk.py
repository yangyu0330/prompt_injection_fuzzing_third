from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
import copy
import datetime as dt
import re

from .generator_bulk_index import BulkDedupIndex, IndexEntry, exact_payload_hash, write_index_files
from .generator_bulk_report import (
    build_pass_report,
    build_summary,
    choose_refill_families,
    classify_deficits,
    compute_family_shortfall,
    resolve_run_status,
)
from .generator_common import (
    as_list,
    build_case,
    build_equivalent_preflight,
    capability_and_placeholder_self_check,
    choose_benign_template_id,
    default_expected_interpretations,
    default_source_roles,
    deterministic_case_id,
    family_contrast_policy,
    fingerprint_build_context,
    intersect,
    load_templates,
    pair_key,
    project_root_from,
    recipe_map,
    resolve_build_paths_for_fingerprint,
    unique,
)
from .io_utils import dump_json, load_yaml, read_json, read_jsonl, write_jsonl
from .models import CaseRecord, TemplateRecord
from .text_utils import stable_key
from .validation import structural_fingerprint, validate_analysis_linkage


_INDEX_VERSION = "bulk-index-v1"
_SHARD_RE = re.compile(r"^family=(?P<family>[^/]+)/part-(?P<num>\d{4})\.jsonl$")


@dataclass(frozen=True)
class BundlePlan:
    bundle_key: str
    template_id: str
    family: str
    entry_point: str
    carrier_context: str
    source_role: str
    expected_interpretation: str
    primary_mutation: str
    policy_requested: str
    tool_transition_type: str
    replay_window: str
    delayed_injection_turn: int | None
    structured_payload_type: str
    threshold_profile: str
    normalization_variant: str
    languages: tuple[str, ...]
    mutation_sensitive_seg: bool
    planner_kind: str = "cartesian"
    planner_note: str = ""


@dataclass
class BulkContext:
    root: Path
    config_path: Path
    generator_cfg: dict[str, Any]
    out_dir: Path
    export_jsonl: Path
    shards_dir: Path
    pass_reports_dir: Path
    indexes_dir: Path
    manifest_path: Path
    summary_path: Path


def _as_posix_rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _atomic_dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    dump_json(tmp, payload)
    tmp.replace(path)


def _atomic_write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    write_jsonl(tmp, rows)
    tmp.replace(path)


def _build_context(
    *,
    template_sources: list[Path],
    config_path: Path,
    out_override: Path | None,
    project_root: Path | None,
) -> BulkContext:
    root = project_root_from(config_path, project_root)
    raw_cfg = load_yaml(config_path)
    generator_cfg = copy.deepcopy(raw_cfg.get("generator", {}) or {})

    output_cfg = generator_cfg.get("output", {}) or {}
    out_dir_rel = Path(str(output_cfg.get("out_dir", "catalogs/generated_bulk")))
    out_dir = root / out_dir_rel

    if out_override is not None:
        export_jsonl = (root / out_override) if not out_override.is_absolute() else out_override
    else:
        export_rel = Path(str(output_cfg.get("export_jsonl", "catalogs/generated_cases.jsonl")))
        export_jsonl = root / export_rel

    effective_output = dict(output_cfg)
    effective_output["out_dir"] = _as_posix_rel(root, out_dir)
    effective_output["export_jsonl"] = _as_posix_rel(root, export_jsonl)
    generator_cfg["output"] = effective_output

    dedup_cfg = generator_cfg.get("dedup_index", {}) or {}
    dedup_path = Path(str(dedup_cfg.get("path", str((out_dir / "indexes").as_posix()))))
    indexes_dir = (root / dedup_path) if not dedup_path.is_absolute() else dedup_path

    return BulkContext(
        root=root,
        config_path=config_path,
        generator_cfg=generator_cfg,
        out_dir=out_dir,
        export_jsonl=export_jsonl,
        shards_dir=out_dir / "shards",
        pass_reports_dir=out_dir / "pass_reports",
        indexes_dir=indexes_dir,
        manifest_path=out_dir / "manifest.json",
        summary_path=out_dir / "summary.json",
    )


def _has_existing_state(ctx: BulkContext) -> bool:
    if ctx.manifest_path.exists():
        return True
    if ctx.summary_path.exists():
        return True
    if ctx.shards_dir.exists() and any(ctx.shards_dir.rglob("*.jsonl")):
        return True
    if ctx.pass_reports_dir.exists() and any(ctx.pass_reports_dir.rglob("*.json")):
        return True
    if ctx.indexes_dir.exists() and any(ctx.indexes_dir.rglob("*.jsonl")):
        return True
    return False


def _scan_shards(ctx: BulkContext) -> list[str]:
    if not ctx.shards_dir.exists():
        return []
    rels = [str(path.relative_to(ctx.shards_dir).as_posix()) for path in ctx.shards_dir.rglob("*.jsonl")]
    return sorted(rels)


def _load_rows_from_shards(ctx: BulkContext, shard_relpaths: list[str]) -> list[CaseRecord]:
    rows: list[CaseRecord] = []
    for rel in shard_relpaths:
        shard_path = ctx.shards_dir / rel
        if not shard_path.exists():
            continue
        rows.extend(CaseRecord(**item) for item in read_jsonl(shard_path))
    return sorted(rows, key=lambda c: c.case_id)


def _extract_bundle_key(note: str) -> str:
    for token in (note or "").split(";"):
        token = token.strip()
        if token.startswith("bulk_bundle="):
            return token.split("=", 1)[1].strip()
    return ""


def _rebuild_export(ctx: BulkContext, shard_relpaths: list[str]) -> list[CaseRecord]:
    rows = _load_rows_from_shards(ctx, shard_relpaths)
    _atomic_write_jsonl(ctx.export_jsonl, [row.model_dump() for row in rows])
    return rows


def _load_index_entry_rows(indexes_dir: Path) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    bundle_path = indexes_dir / "bundle_index.jsonl"
    exact_path = indexes_dir / "exact_hash_index.jsonl"
    structural_path = indexes_dir / "structural_fingerprint_index.jsonl"
    bundle_rows = read_jsonl(bundle_path) if bundle_path.exists() else []
    exact_rows = read_jsonl(exact_path) if exact_path.exists() else []
    structural_rows = read_jsonl(structural_path) if structural_path.exists() else []
    return (bundle_rows, exact_rows, structural_rows)


def _index_needs_rebuild(index: BulkDedupIndex, rows: list[CaseRecord]) -> bool:
    for row in rows:
        if exact_payload_hash(row) not in index.exact_hashes:
            return True
        if structural_fingerprint(row) not in index.structural_fingerprints:
            return True
        bundle_key = _extract_bundle_key(row.notes)
        if bundle_key and bundle_key not in index.bundle_keys:
            return True
    return False


def _rebuild_index_from_rows(
    *,
    ctx: BulkContext,
    rows: list[CaseRecord],
    shard_relpaths: list[str],
) -> tuple[BulkDedupIndex, list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    by_case_id_to_shard: dict[str, str] = {}
    for rel in shard_relpaths:
        shard_path = ctx.shards_dir / rel
        if not shard_path.exists():
            continue
        for item in read_jsonl(shard_path):
            case_id = str(item.get("case_id", "")).strip()
            if case_id:
                by_case_id_to_shard[case_id] = rel

    index = BulkDedupIndex()
    bundle_entries: list[IndexEntry] = []
    exact_entries: list[IndexEntry] = []
    structural_entries: list[IndexEntry] = []

    for row in rows:
        shard = by_case_id_to_shard.get(row.case_id, "")
        bundle_key = _extract_bundle_key(row.notes)
        if bundle_key:
            index.add_bundle(bundle_key)
            bundle_entries.append(
                IndexEntry(
                    key=bundle_key,
                    case_id=row.case_id,
                    shard=shard,
                    family=row.attack_family,
                    template_id=row.template_id,
                )
            )

        exact = exact_payload_hash(row)
        structural = structural_fingerprint(row)
        index.exact_hashes.add(exact)
        index.structural_fingerprints.add(structural)
        exact_entries.append(
            IndexEntry(key=exact, case_id=row.case_id, shard=shard, family=row.attack_family, template_id=row.template_id)
        )
        structural_entries.append(
            IndexEntry(key=structural, case_id=row.case_id, shard=shard, family=row.attack_family, template_id=row.template_id)
        )

    bundle_rows, exact_rows, structural_rows = index.snapshot_rows(
        bundle_entries=bundle_entries,
        exact_entries=exact_entries,
        structural_entries=structural_entries,
    )
    write_index_files(
        index_dir=ctx.indexes_dir,
        bundle_entries=bundle_rows,
        exact_entries=exact_rows,
        structural_entries=structural_rows,
    )
    return index, bundle_rows, exact_rows, structural_rows


def _prepare_manifest(
    *,
    ctx: BulkContext,
    template_sources: list[Path],
    resume: bool,
) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    build_config_path, curated_case_sources, coverage_matrix_path = resolve_build_paths_for_fingerprint(
        generator_cfg=ctx.generator_cfg,
        project_root=ctx.root,
        export_jsonl=ctx.export_jsonl,
    )

    seed = int(ctx.generator_cfg.get("seed", 20260409))
    fingerprints = fingerprint_build_context(
        generator_cfg=ctx.generator_cfg,
        build_config_path=build_config_path,
        template_sources=[(ctx.root / p) if not p.is_absolute() else p for p in template_sources],
        curated_case_sources=curated_case_sources,
        coverage_matrix_path=coverage_matrix_path,
        seed=seed,
    )

    if resume:
        if not ctx.manifest_path.exists():
            raise ValueError("--resume requires an existing bulk manifest")
        manifest = read_json(ctx.manifest_path)
        raw_shards = manifest.get("shards")
        if raw_shards is None:
            committed_shards = _scan_shards(ctx)
        elif isinstance(raw_shards, list):
            committed_shards = [str(item).strip() for item in raw_shards if str(item).strip()]
        else:
            raise ValueError("bulk manifest malformed: 'shards' must be a list")
        prev_fps = dict(manifest.get("fingerprints", {}) or {})
        if prev_fps != fingerprints:
            return (
                {
                    "schema_version": "bulk-manifest-v1",
                    "status": "failed_config_mismatch",
                    "reason": "fingerprint_mismatch",
                    "fingerprints": fingerprints,
                    "previous_fingerprints": prev_fps,
                    "completed_passes": list(manifest.get("completed_passes", []) or []),
                    "shards": committed_shards,
                    "seed": seed,
                    "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                },
                committed_shards,
                fingerprints,
            )
        shard_relpaths = committed_shards
        return (manifest, shard_relpaths, fingerprints)

    if _has_existing_state(ctx):
        raise ValueError(
            "bulk out_dir already has state. clear it or rerun with --resume to continue the same run"
        )

    manifest = {
        "schema_version": "bulk-manifest-v1",
        "status": "running",
        "reason": "initialized",
        "seed": seed,
        "fingerprints": fingerprints,
        "completed_passes": [],
        "shards": [],
        "index": {
            "version": _INDEX_VERSION,
            "path": _as_posix_rel(ctx.root, ctx.indexes_dir),
        },
        "output": {
            "out_dir": _as_posix_rel(ctx.root, ctx.out_dir),
            "export_jsonl": _as_posix_rel(ctx.root, ctx.export_jsonl),
        },
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    return (manifest, [], fingerprints)


def _family_sort_key(family: str, family_cfg: dict[str, dict[str, Any]]) -> tuple[int, str]:
    cfg = family_cfg.get(family, {}) or {}
    return (-int(cfg.get("priority", 0) or 0), family)


def _collect_axes_for_template(template: TemplateRecord, family_rule: dict[str, Any]) -> dict[str, Any] | None:
    languages = unique([str(v) for v in as_list(family_rule.get("languages")) if str(v).strip()]) or ["ko", "en"]
    entry_points = intersect([str(v) for v in as_list(family_rule.get("entry_points"))], list(template.supported_entry_points))
    carriers = intersect([str(v) for v in as_list(family_rule.get("carriers"))], list(template.supported_carriers))

    source_roles_pref = [str(v) for v in as_list(family_rule.get("source_roles"))]
    if template.supported_source_roles:
        source_roles = intersect(source_roles_pref, list(template.supported_source_roles))
    else:
        source_roles = unique(source_roles_pref)
    if not source_roles:
        source_roles = list(template.supported_source_roles) or default_source_roles(template)

    expected_pref = [str(v) for v in as_list(family_rule.get("expected_interpretations"))]
    if template.supported_expected_interpretations:
        expected_interpretations = intersect(expected_pref, list(template.supported_expected_interpretations))
    else:
        expected_interpretations = unique(expected_pref)
    if not expected_interpretations:
        if template.supported_expected_interpretations:
            expected_interpretations = list(template.supported_expected_interpretations)
        else:
            values: list[str] = []
            for role in source_roles:
                values.extend(default_expected_interpretations(role))
            expected_interpretations = unique(values) or [""]

    mutations_pref = [str(v) for v in as_list(family_rule.get("mutations"))]
    if template.allowed_mutation_families:
        mutations = intersect(mutations_pref, list(template.allowed_mutation_families))
    else:
        mutations = unique(mutations_pref)
    if not mutations:
        mutations = list(template.allowed_mutation_families)

    policy_requested_values = [str(v) for v in as_list(family_rule.get("policy_requested"))] or [""]
    tool_transition_values = [str(v) for v in as_list(family_rule.get("tool_transition_types"))] or [template.tool_transition_type or ""]
    replay_windows = [str(v) for v in as_list(family_rule.get("replay_windows"))] or [""]
    delayed_turn_raw = as_list(family_rule.get("delayed_injection_turns"))
    delayed_turn_values = [int(v) if v is not None and str(v) != "" else None for v in delayed_turn_raw] or [None]
    structured_payload_types = [str(v) for v in as_list(family_rule.get("structured_payload_types"))] or [""]
    threshold_profiles = [str(v) for v in as_list(family_rule.get("threshold_profiles"))] or [""]
    normalization_variants = [str(v) for v in as_list(family_rule.get("normalization_variants"))] or [""]
    mutation_sensitive_seg = bool(family_rule.get("seg_mutation_sensitive", False))

    if not entry_points or not carriers or not source_roles or not expected_interpretations or not mutations:
        return None

    return {
        "languages": languages,
        "entry_points": entry_points,
        "carriers": carriers,
        "source_roles": source_roles,
        "expected_interpretations": expected_interpretations,
        "mutations": mutations,
        "policy_requested_values": policy_requested_values,
        "tool_transition_values": tool_transition_values,
        "replay_windows": replay_windows,
        "delayed_turn_values": delayed_turn_values,
        "structured_payload_types": structured_payload_types,
        "threshold_profiles": threshold_profiles,
        "normalization_variants": normalization_variants,
        "mutation_sensitive_seg": mutation_sensitive_seg,
    }


def _bundle_key(parts: list[str]) -> str:
    return f"BND-{stable_key(parts)[:14].upper()}"


def _dedup_plans(plans: list[BundlePlan]) -> list[BundlePlan]:
    unique_by_key: dict[str, BundlePlan] = {}
    for plan in plans:
        unique_by_key.setdefault(plan.bundle_key, plan)
    return [unique_by_key[k] for k in sorted(unique_by_key.keys())]


def _plan_bundles_cartesian(template: TemplateRecord, family_rule: dict[str, Any]) -> list[BundlePlan]:
    axes = _collect_axes_for_template(template, family_rule)
    if axes is None:
        return []

    languages = list(axes["languages"])
    entry_points = list(axes["entry_points"])
    carriers = list(axes["carriers"])
    source_roles = list(axes["source_roles"])
    expected_interpretations = list(axes["expected_interpretations"])
    mutations = list(axes["mutations"])
    policy_requested_values = list(axes["policy_requested_values"])
    tool_transition_values = list(axes["tool_transition_values"])
    replay_windows = list(axes["replay_windows"])
    delayed_turn_values = list(axes["delayed_turn_values"])
    structured_payload_types = list(axes["structured_payload_types"])
    threshold_profiles = list(axes["threshold_profiles"])
    normalization_variants = list(axes["normalization_variants"])
    mutation_sensitive_seg = bool(axes["mutation_sensitive_seg"])

    plans: list[BundlePlan] = []
    for entry_point in entry_points:
        for carrier in carriers:
            for source_role in source_roles:
                for expected_interpretation in expected_interpretations:
                    for mutation in mutations:
                        for policy_requested in policy_requested_values:
                            for tool_transition_type in tool_transition_values:
                                for replay_window in replay_windows:
                                    for delayed_turn in delayed_turn_values:
                                        for structured_payload_type in structured_payload_types:
                                            for threshold_profile in threshold_profiles:
                                                for normalization_variant in normalization_variants:
                                                    key_parts = [
                                                        template.template_id,
                                                        template.attack_family,
                                                        entry_point,
                                                        carrier,
                                                        source_role,
                                                        expected_interpretation,
                                                        mutation,
                                                        policy_requested,
                                                        tool_transition_type,
                                                        replay_window,
                                                        str(delayed_turn) if delayed_turn is not None else "",
                                                        structured_payload_type,
                                                        threshold_profile,
                                                        normalization_variant,
                                                    ]
                                                    bundle_key = _bundle_key(key_parts)
                                                    plans.append(
                                                        BundlePlan(
                                                            bundle_key=bundle_key,
                                                            template_id=template.template_id,
                                                            family=template.attack_family,
                                                            entry_point=entry_point,
                                                            carrier_context=carrier,
                                                            source_role=source_role,
                                                            expected_interpretation=expected_interpretation,
                                                            primary_mutation=mutation,
                                                            policy_requested=policy_requested,
                                                            tool_transition_type=tool_transition_type,
                                                            replay_window=replay_window,
                                                            delayed_injection_turn=delayed_turn,
                                                            structured_payload_type=structured_payload_type,
                                                            threshold_profile=threshold_profile,
                                                            normalization_variant=normalization_variant,
                                                            languages=tuple(languages),
                                                            mutation_sensitive_seg=mutation_sensitive_seg,
                                                            planner_kind="cartesian",
                                                        )
                                                    )
    return _dedup_plans(plans)


def _first_matching(preferred: str, allowed: list[str]) -> str:
    if preferred and preferred in allowed:
        return preferred
    return allowed[0]


def _plan_bundles_adaptive(
    template: TemplateRecord,
    family_rule: dict[str, Any],
    *,
    existing_rows: list[CaseRecord],
) -> list[BundlePlan]:
    axes = _collect_axes_for_template(template, family_rule)
    if axes is None:
        return []

    seed_families = unique([str(v) for v in as_list(family_rule.get("seed_families")) if str(v).strip()]) or [
        "tool_agent_misuse",
        "replay_trajectory_injection",
        "structured_payload_misuse",
    ]
    operator_chain = unique([str(v) for v in as_list(family_rule.get("operator_chain")) if str(v).strip()]) or list(
        axes["mutations"]
    )
    allowed_mutations = set(str(v) for v in axes["mutations"])
    operator_chain = [op for op in operator_chain if op in allowed_mutations] or list(axes["mutations"])

    max_variants_per_seed = max(1, int(family_rule.get("max_variants_per_seed", 2) or 2))
    seed_selection_limit = max(1, int(family_rule.get("seed_selection_limit", 16) or 16))
    seed_rows = [
        row
        for row in sorted(existing_rows, key=lambda r: r.case_id)
        if row.attack_or_benign == "attack" and row.attack_family in seed_families
    ][:seed_selection_limit]

    plans: list[BundlePlan] = []
    for seed_idx, seed_row in enumerate(seed_rows):
        entry_point = _first_matching(str(seed_row.entry_point), list(axes["entry_points"]))
        carrier = _first_matching(str(seed_row.carrier_context), list(axes["carriers"]))
        source_role = _first_matching(str(seed_row.source_role), list(axes["source_roles"]))
        expected_interpretation = _first_matching(
            str(seed_row.expected_interpretation),
            list(axes["expected_interpretations"]),
        )
        policy_requested = _first_matching(str(seed_row.policy_requested), list(axes["policy_requested_values"]))
        tool_transition_type = _first_matching(str(seed_row.tool_transition_type), list(axes["tool_transition_values"]))
        replay_window = _first_matching(str(seed_row.replay_window), list(axes["replay_windows"]))
        delayed_turn = seed_row.delayed_injection_turn
        if delayed_turn not in axes["delayed_turn_values"]:
            delayed_turn = list(axes["delayed_turn_values"])[0]
        structured_payload_type = _first_matching(
            str(seed_row.structured_payload_type),
            list(axes["structured_payload_types"]),
        )
        threshold_profile = _first_matching(str(seed_row.threshold_profile), list(axes["threshold_profiles"]))
        normalization_variant = _first_matching(
            str(seed_row.normalization_variant),
            list(axes["normalization_variants"]),
        )

        if str(seed_row.language) in axes["languages"]:
            languages = (str(seed_row.language),)
        else:
            languages = tuple(str(v) for v in axes["languages"])

        variant_count = min(max_variants_per_seed, len(operator_chain))
        for variant_idx in range(variant_count):
            mutation = operator_chain[(seed_idx + variant_idx) % len(operator_chain)]
            key_parts = [
                template.template_id,
                template.attack_family,
                "adaptive_seed",
                seed_row.case_id,
                mutation,
                entry_point,
                carrier,
                source_role,
                expected_interpretation,
                policy_requested,
                tool_transition_type,
                replay_window,
                str(delayed_turn) if delayed_turn is not None else "",
                structured_payload_type,
                threshold_profile,
                normalization_variant,
            ]
            plans.append(
                BundlePlan(
                    bundle_key=_bundle_key(key_parts),
                    template_id=template.template_id,
                    family=template.attack_family,
                    entry_point=entry_point,
                    carrier_context=carrier,
                    source_role=source_role,
                    expected_interpretation=expected_interpretation,
                    primary_mutation=mutation,
                    policy_requested=policy_requested,
                    tool_transition_type=tool_transition_type,
                    replay_window=replay_window,
                    delayed_injection_turn=delayed_turn,
                    structured_payload_type=structured_payload_type,
                    threshold_profile=threshold_profile,
                    normalization_variant=normalization_variant,
                    languages=languages,
                    mutation_sensitive_seg=bool(axes["mutation_sensitive_seg"]),
                    planner_kind="adaptive_seed",
                    planner_note=(
                        "planner=adaptive_seed;"
                        f"seed_case_id={seed_row.case_id};"
                        f"seed_family={seed_row.attack_family};"
                        f"operator={mutation}"
                    ),
                )
            )

    if plans:
        return _dedup_plans(plans)

    fallback = _plan_bundles_cartesian(template, family_rule)
    if not fallback:
        return []
    fallback_limit = max(1, min(len(fallback), max_variants_per_seed))
    return _dedup_plans(
        [
            replace(
                plan,
                planner_kind="adaptive_fallback",
                planner_note="planner=adaptive_fallback;seed_source=template_catalog",
            )
            for plan in fallback[:fallback_limit]
        ]
    )


def _baseline_and_variant(values: list[str]) -> tuple[str, str]:
    baseline = next((v for v in values if v.strip().lower() == "baseline"), values[0])
    variant = next((v for v in values if v != baseline), baseline)
    return (baseline, variant)


def _probe_pair_variants(
    *,
    pair_name: str,
    threshold_profiles: list[str],
    normalization_variants: list[str],
) -> list[tuple[str, str, str]]:
    base_threshold, variant_threshold = _baseline_and_variant(threshold_profiles)
    base_norm, variant_norm = _baseline_and_variant(normalization_variants)
    if pair_name == "threshold_only":
        rows = [
            (base_threshold, base_norm, "base"),
            (variant_threshold, base_norm, "threshold_variant"),
        ]
    elif pair_name == "normalization_only":
        rows = [
            (base_threshold, base_norm, "base"),
            (base_threshold, variant_norm, "normalization_variant"),
        ]
    elif pair_name == "combined":
        rows = [
            (base_threshold, base_norm, "base"),
            (variant_threshold, variant_norm, "combined_variant"),
        ]
    else:
        rows = [(base_threshold, base_norm, "base")]

    dedup: dict[tuple[str, str], tuple[str, str, str]] = {}
    for threshold_profile, normalization_variant, variant_name in rows:
        dedup.setdefault((threshold_profile, normalization_variant), (threshold_profile, normalization_variant, variant_name))
    return list(dedup.values())


def _plan_bundles_config_probe(template: TemplateRecord, family_rule: dict[str, Any]) -> list[BundlePlan]:
    axes = _collect_axes_for_template(template, family_rule)
    if axes is None:
        return []

    probe_pairs = unique([str(v) for v in as_list(family_rule.get("probe_pairs")) if str(v).strip()]) or [
        "threshold_only",
        "normalization_only",
        "combined",
    ]

    plans: list[BundlePlan] = []
    for entry_point in list(axes["entry_points"]):
        for carrier in list(axes["carriers"]):
            for source_role in list(axes["source_roles"]):
                for expected_interpretation in list(axes["expected_interpretations"]):
                    for mutation in list(axes["mutations"]):
                        for policy_requested in list(axes["policy_requested_values"]):
                            for tool_transition_type in list(axes["tool_transition_values"]):
                                for replay_window in list(axes["replay_windows"]):
                                    for delayed_turn in list(axes["delayed_turn_values"]):
                                        for structured_payload_type in list(axes["structured_payload_types"]):
                                            for pair_name in probe_pairs:
                                                for threshold_profile, normalization_variant, variant_name in _probe_pair_variants(
                                                    pair_name=pair_name,
                                                    threshold_profiles=list(axes["threshold_profiles"]),
                                                    normalization_variants=list(axes["normalization_variants"]),
                                                ):
                                                    key_parts = [
                                                        template.template_id,
                                                        template.attack_family,
                                                        "config_probe",
                                                        pair_name,
                                                        variant_name,
                                                        entry_point,
                                                        carrier,
                                                        source_role,
                                                        expected_interpretation,
                                                        mutation,
                                                        policy_requested,
                                                        tool_transition_type,
                                                        replay_window,
                                                        str(delayed_turn) if delayed_turn is not None else "",
                                                        structured_payload_type,
                                                        threshold_profile,
                                                        normalization_variant,
                                                    ]
                                                    plans.append(
                                                        BundlePlan(
                                                            bundle_key=_bundle_key(key_parts),
                                                            template_id=template.template_id,
                                                            family=template.attack_family,
                                                            entry_point=entry_point,
                                                            carrier_context=carrier,
                                                            source_role=source_role,
                                                            expected_interpretation=expected_interpretation,
                                                            primary_mutation=mutation,
                                                            policy_requested=policy_requested,
                                                            tool_transition_type=tool_transition_type,
                                                            replay_window=replay_window,
                                                            delayed_injection_turn=delayed_turn,
                                                            structured_payload_type=structured_payload_type,
                                                            threshold_profile=threshold_profile,
                                                            normalization_variant=normalization_variant,
                                                            languages=tuple(str(v) for v in axes["languages"]),
                                                            mutation_sensitive_seg=bool(axes["mutation_sensitive_seg"]),
                                                            planner_kind="config_probe_pair",
                                                            planner_note=(
                                                                "planner=config_probe_pair;"
                                                                f"probe_pair={pair_name};"
                                                                f"probe_variant={variant_name}"
                                                            ),
                                                        )
                                                    )
    return _dedup_plans(plans)


def _plan_bundles_for_template(
    template: TemplateRecord,
    family_rule: dict[str, Any],
    *,
    existing_rows: list[CaseRecord] | None = None,
) -> list[BundlePlan]:
    family = str(template.attack_family)
    if family == "adaptive_fuzzing":
        return _plan_bundles_adaptive(
            template,
            family_rule,
            existing_rows=list(existing_rows or []),
        )
    if family == "config_sensitivity_probe":
        return _plan_bundles_config_probe(template, family_rule)
    return _plan_bundles_cartesian(template, family_rule)


def _build_bundle_rows(
    *,
    plan: BundlePlan,
    template: TemplateRecord,
    seed: int,
    recipe_by_family: dict[str, str],
    contrast_cfg: dict[str, Any],
    templates_by_id: dict[str, TemplateRecord],
    pass_no: int,
) -> list[CaseRecord]:
    planner_note_suffix = f"bulk_bundle={plan.bundle_key};bulk_pass={pass_no};bulk_planner={plan.planner_kind}"
    if plan.planner_note:
        planner_note_suffix = f"{planner_note_suffix};{plan.planner_note}"

    rows: list[CaseRecord] = []
    for language in sorted(plan.languages):
        row = build_case(
            template=template,
            seed=seed,
            language=language,
            entry_point=plan.entry_point,
            carrier=plan.carrier_context,
            source_role=plan.source_role,
            expected_interpretation=plan.expected_interpretation,
            primary_mutation=plan.primary_mutation,
            mutation_recipe_id=recipe_by_family.get(plan.primary_mutation),
            policy_requested=plan.policy_requested,
            tool_transition_type=plan.tool_transition_type,
            replay_window=plan.replay_window,
            delayed_injection_turn=plan.delayed_injection_turn,
            structured_payload_type=plan.structured_payload_type,
            threshold_profile=plan.threshold_profile,
            normalization_variant=plan.normalization_variant,
            mutation_sensitive_seg=plan.mutation_sensitive_seg,
        )
        row = row.model_copy(
            update={
                "notes": f"{row.notes};{planner_note_suffix}",
                "paired_case_role": "attack",
            }
        )
        rows.append(row)

    policy = family_contrast_policy(plan.family, contrast_cfg)
    if policy.bilingual_pairing:
        ko_rows = [r for r in rows if r.language.lower().startswith("ko")]
        en_rows = [r for r in rows if r.language.lower().startswith("en")]
        if ko_rows and en_rows:
            ko = sorted(ko_rows, key=lambda r: r.case_id)[0]
            en = sorted(en_rows, key=lambda r: r.case_id)[0]
            pair_id = f"KRP-{stable_key([pair_key(ko)])[:10].upper()}"
            rows = [
                r.model_copy(
                    update={
                        "paired_case_id": en.case_id if r.case_id == ko.case_id else (ko.case_id if r.case_id == en.case_id else r.paired_case_id),
                        "kr_en_pair_id": pair_id if r.case_id in {ko.case_id, en.case_id} else r.kr_en_pair_id,
                        "paired_case_role": "ko_variant" if r.case_id == ko.case_id else ("en_control" if r.case_id == en.case_id else r.paired_case_role),
                    }
                )
                for r in rows
            ]

    if policy.require_benign:
        example = rows[0]
        benign_template_id = choose_benign_template_id(
            policy=policy,
            example_case=example,
            templates_by_id=templates_by_id,
        )
        if not benign_template_id:
            raise ValueError(
                f"contrast_policy for family={plan.family} requires benign_template_id or benign_template_pool match"
            )
        benign_template = templates_by_id.get(benign_template_id)
        if benign_template is None:
            raise ValueError(
                f"contrast_policy family={plan.family} references unknown benign_template_id={benign_template_id}"
            )

        entry_point = (
            example.entry_point
            if example.entry_point in benign_template.supported_entry_points
            else benign_template.supported_entry_points[0]
        )
        carrier = (
            example.carrier_context
            if example.carrier_context in benign_template.supported_carriers
            else benign_template.supported_carriers[0]
        )
        source_role = example.source_role
        if benign_template.supported_source_roles:
            source_role = (
                source_role if source_role in benign_template.supported_source_roles else benign_template.supported_source_roles[0]
            )
        expected_interpretation = example.expected_interpretation
        if benign_template.supported_expected_interpretations:
            expected_interpretation = (
                expected_interpretation
                if expected_interpretation in benign_template.supported_expected_interpretations
                else benign_template.supported_expected_interpretations[0]
            )
        benign_mutation = (benign_template.allowed_mutation_families or ["quote_wrapper"])[0]

        benign = build_case(
            template=benign_template,
            seed=seed,
            language=example.language,
            entry_point=entry_point,
            carrier=carrier,
            source_role=source_role,
            expected_interpretation=expected_interpretation,
            primary_mutation=benign_mutation,
            mutation_recipe_id=recipe_by_family.get(benign_mutation),
            policy_requested=plan.policy_requested,
            tool_transition_type=plan.tool_transition_type,
            replay_window=plan.replay_window,
            delayed_injection_turn=plan.delayed_injection_turn,
            structured_payload_type=plan.structured_payload_type,
            threshold_profile=plan.threshold_profile,
            normalization_variant=plan.normalization_variant,
            mutation_sensitive_seg=False,
        ).model_copy(
            update={
                "contrast_group_id": example.contrast_group_id,
                "paired_case_role": "benign_control",
                "notes": f"generated;{planner_note_suffix}",
            }
        )
        benign = benign.model_copy(update={"case_id": deterministic_case_id(benign, uniqueness_salt=plan.bundle_key)})

        rows = [r.model_copy(update={"benign_sibling_id": benign.case_id}) for r in rows]
        rows.append(benign)

    return sorted(rows, key=lambda r: r.case_id)


def _next_part_numbers(shard_relpaths: list[str]) -> dict[str, int]:
    max_by_family: dict[str, int] = defaultdict(int)
    for rel in shard_relpaths:
        m = _SHARD_RE.match(rel)
        if not m:
            continue
        family = m.group("family")
        part = int(m.group("num"))
        max_by_family[family] = max(max_by_family[family], part)
    return {family: part + 1 for family, part in max_by_family.items()}


def _build_exact_envelope_index(rows: list[CaseRecord]) -> dict[str, set[str]]:
    exact_to_structurals: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        exact_to_structurals[exact_payload_hash(row)].add(structural_fingerprint(row))
    return exact_to_structurals


def generate_cases_bulk(
    *,
    template_sources: list[Path],
    config_path: Path,
    out_path: Path | None,
    project_root: Path | None,
    resume: bool,
) -> dict[str, Any]:
    ctx = _build_context(
        template_sources=template_sources,
        config_path=config_path,
        out_override=out_path,
        project_root=project_root,
    )

    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    ctx.shards_dir.mkdir(parents=True, exist_ok=True)
    ctx.pass_reports_dir.mkdir(parents=True, exist_ok=True)
    ctx.indexes_dir.mkdir(parents=True, exist_ok=True)

    manifest, shard_relpaths, fingerprints = _prepare_manifest(
        ctx=ctx,
        template_sources=template_sources,
        resume=resume,
    )
    if manifest.get("status") == "failed_config_mismatch":
        summary = {
            "status": "failed_config_mismatch",
            "reason": "fingerprint_mismatch",
            "completed_passes": list(manifest.get("completed_passes", []) or []),
            "input_rows": 0,
            "survivors": 0,
            "driving_deficit_count": 0,
            "report_only_deficit_count": 0,
            "family_shortfall": {},
            "driving_deficits": [],
            "report_only_deficits": [],
        }
        _atomic_dump_json(ctx.summary_path, summary)
        _atomic_dump_json(ctx.manifest_path, manifest)
        return summary

    _atomic_dump_json(ctx.manifest_path, manifest)

    existing_rows = _rebuild_export(ctx, shard_relpaths)

    index = BulkDedupIndex.load(ctx.indexes_dir)
    bundle_entry_rows, exact_entry_rows, structural_entry_rows = _load_index_entry_rows(ctx.indexes_dir)
    if existing_rows and (_index_needs_rebuild(index, existing_rows) or not exact_entry_rows or not structural_entry_rows):
        index, bundle_entry_rows, exact_entry_rows, structural_entry_rows = _rebuild_index_from_rows(
            ctx=ctx,
            rows=existing_rows,
            shard_relpaths=shard_relpaths,
        )

    template_paths = [(ctx.root / p) if not p.is_absolute() else p for p in template_sources]
    templates = load_templates(template_paths)
    templates_by_id = {t.template_id: t for t in templates}

    seed = int(ctx.generator_cfg.get("seed", 20260409))
    mutation_recipe_path = ctx.root / Path(str(ctx.generator_cfg.get("mutation_recipe_path", "catalogs/mutation_recipes.yaml")))
    recipe_by_family = recipe_map(mutation_recipe_path)

    families_cfg = dict(ctx.generator_cfg.get("families", {}) or {})
    contrast_cfg = dict(ctx.generator_cfg.get("contrast_policy", {}) or {})
    refill_cfg = dict(ctx.generator_cfg.get("refill", {}) or {})
    preflight_cfg = dict(ctx.generator_cfg.get("preflight", {}) or {})

    max_passes = int(ctx.generator_cfg.get("max_passes", 1) or 1)
    survivor_target = int(ctx.generator_cfg.get("survivor_target", 0) or 0)
    min_new_survivors_per_pass = int(refill_cfg.get("min_new_survivors_per_pass", 0) or 0)
    fail_on_survivor_shortfall = bool(preflight_cfg.get("fail_on_survivor_shortfall", True))

    output_cfg = ctx.generator_cfg.get("output", {}) or {}
    max_rows_per_shard = int(output_cfg.get("max_rows_per_shard", 1000) or 1000)

    selected_families = sorted(families_cfg.keys(), key=lambda f: _family_sort_key(f, families_cfg))

    prev_survivors = 0
    final_driving: list[dict[str, Any]] = []
    final_report_only: list[dict[str, Any]] = []
    final_shortfall: dict[str, int] = {}
    reason = "max_passes_reached"

    existing_case_ids = {row.case_id for row in existing_rows}
    bundle_count_by_family = Counter()
    for row in existing_rows:
        key = _extract_bundle_key(row.notes)
        if key:
            bundle_count_by_family[row.attack_family] += 1

    try:
        if existing_rows:
            baseline_preflight = build_equivalent_preflight(
                existing_rows,
                generator_cfg=ctx.generator_cfg,
                project_root=ctx.root,
                generated_out_path=ctx.export_jsonl,
                enforce_export_contract=True,
            )
            driving_profiles = set(str(p) for p in as_list(refill_cfg.get("driving_profiles")) if str(p).strip())
            violation_family_hints = {
                str(k): [str(vv) for vv in as_list(v)]
                for k, v in dict(refill_cfg.get("violation_family_hints", {}) or {}).items()
            }
            final_driving, final_report_only = classify_deficits(
                list(baseline_preflight.get("coverage_violations", []) or []),
                driving_profiles=driving_profiles,
                family_hints=violation_family_hints,
            )
            family_survivor_counts = {
                str(k): int(v)
                for k, v in dict(baseline_preflight.get("family_survivor_counts", {}) or {}).items()
            }
            final_shortfall = compute_family_shortfall(family_survivor_counts, families_cfg)
            prev_survivors = int(baseline_preflight.get("generated_survivors_after_build_semantics", 0))
            if resume:
                selected_families = choose_refill_families(
                    family_shortfall=final_shortfall,
                    driving_deficits=final_driving,
                    family_cfg=families_cfg,
                ) or selected_families
            if prev_survivors >= survivor_target and not final_driving:
                selected_families = []
                reason = "target_met"

        for pass_no in range(len(manifest.get("completed_passes", []) or []) + 1, max_passes + 1):
            if not selected_families:
                if reason != "target_met":
                    reason = "no_refill_candidates"
                break

            seen_exact_envelopes = _build_exact_envelope_index(existing_rows)
            seen_structural_to_case = {
                structural_fingerprint(row): row.case_id
                for row in existing_rows
            }
            seen_bundle = set(index.bundle_keys)
            seen_case_id = set(existing_case_ids)

            new_rows_by_family: dict[str, list[CaseRecord]] = defaultdict(list)
            new_bundle_entries: list[IndexEntry] = []
            new_exact_entries: list[IndexEntry] = []
            new_structural_entries: list[IndexEntry] = []

            for family in selected_families:
                family_rule = families_cfg.get(family, {}) or {}
                if not family_rule:
                    continue

                family_templates = [
                    t
                    for t in templates
                    if t.attack_family == family and t.attack_or_benign == "attack"
                ]
                family_templates = sorted(family_templates, key=lambda t: t.template_id)
                if not family_templates:
                    continue

                max_raw_rows = int(family_rule.get("max_raw_rows", 0) or 0)
                max_bundles = int(family_rule.get("max_bundles", 0) or 0)

                family_current_rows = sum(1 for row in existing_rows if row.attack_family == family)
                family_new_rows = 0
                family_current_bundles = int(bundle_count_by_family.get(family, 0))

                for template in family_templates:
                    # Adaptive planners can derive seeds from rows emitted earlier in the same pass.
                    pass_seed_rows = list(existing_rows) + [
                        row
                        for rows_for_family in new_rows_by_family.values()
                        for row in rows_for_family
                    ]
                    plans = _plan_bundles_for_template(template, family_rule, existing_rows=pass_seed_rows)
                    for plan in plans:
                        if max_bundles > 0 and family_current_bundles >= max_bundles:
                            break
                        if max_raw_rows > 0 and (family_current_rows + family_new_rows) >= max_raw_rows:
                            break
                        if plan.bundle_key in seen_bundle:
                            continue

                        bundle_rows = _build_bundle_rows(
                            plan=plan,
                            template=template,
                            seed=seed,
                            recipe_by_family=recipe_by_family,
                            contrast_cfg=contrast_cfg,
                            templates_by_id=templates_by_id,
                            pass_no=pass_no,
                        )

                        accepted_rows: list[tuple[CaseRecord, str, str]] = []
                        benign_case_remap: dict[str, str] = {}
                        # Process benign rows first so sibling remap is available for attacks.
                        ordered_bundle_rows = sorted(
                            bundle_rows,
                            key=lambda row: 0 if row.attack_or_benign == "benign" else 1,
                        )
                        for row in ordered_bundle_rows:
                            if row.attack_or_benign == "attack" and row.benign_sibling_id in benign_case_remap:
                                row = row.model_copy(update={"benign_sibling_id": benign_case_remap[row.benign_sibling_id]})
                            if row.case_id in seen_case_id:
                                continue
                            exact_key = exact_payload_hash(row)
                            structural_key = structural_fingerprint(row)
                            seen_for_exact = seen_exact_envelopes.get(exact_key)
                            if seen_for_exact is not None and structural_key in seen_for_exact:
                                if row.attack_or_benign == "benign":
                                    existing_case = seen_structural_to_case.get(structural_key)
                                    if existing_case:
                                        benign_case_remap[row.case_id] = existing_case
                                continue
                            if structural_key in seen_structural_to_case:
                                if row.attack_or_benign == "benign":
                                    benign_case_remap[row.case_id] = seen_structural_to_case[structural_key]
                                continue
                            accepted_rows.append((row, exact_key, structural_key))

                        if not accepted_rows:
                            continue

                        seen_bundle.add(plan.bundle_key)
                        family_current_bundles += 1
                        new_bundle_entries.append(
                            IndexEntry(
                                key=plan.bundle_key,
                                case_id=accepted_rows[0][0].case_id,
                                shard="",
                                family=family,
                                template_id=template.template_id,
                            )
                        )

                        for row, exact_key, structural_key in accepted_rows:
                            seen_case_id.add(row.case_id)
                            seen_exact_envelopes.setdefault(exact_key, set()).add(structural_key)
                            seen_structural_to_case[structural_key] = row.case_id
                            new_rows_by_family[family].append(row)
                            family_new_rows += 1
                            new_exact_entries.append(
                                IndexEntry(key=exact_key, case_id=row.case_id, shard="", family=family, template_id=row.template_id)
                            )
                            new_structural_entries.append(
                                IndexEntry(
                                    key=structural_key,
                                    case_id=row.case_id,
                                    shard="",
                                    family=family,
                                    template_id=row.template_id,
                                )
                            )

                    if max_bundles > 0 and family_current_bundles >= max_bundles:
                        break
                    if max_raw_rows > 0 and (family_current_rows + family_new_rows) >= max_raw_rows:
                        break

                bundle_count_by_family[family] = family_current_bundles

            emitted_rows = sorted([row for rows in new_rows_by_family.values() for row in rows], key=lambda c: c.case_id)

            self_check_errors = capability_and_placeholder_self_check(emitted_rows, templates_by_id)
            if self_check_errors:
                sample = "\n".join(self_check_errors[:20])
                raise ValueError(f"Bulk generator self-check failed ({len(self_check_errors)}):\n{sample}")
            analysis_errors = validate_analysis_linkage(emitted_rows)
            if analysis_errors:
                sample = "\n".join(analysis_errors[:20])
                raise ValueError(f"Bulk generator analysis-link check failed ({len(analysis_errors)}):\n{sample}")

            next_parts = _next_part_numbers(shard_relpaths)
            case_to_shard: dict[str, str] = {}
            new_shards: list[str] = []

            for family in sorted(new_rows_by_family.keys()):
                family_rows = sorted(new_rows_by_family[family], key=lambda r: r.case_id)
                if not family_rows:
                    continue
                start_no = int(next_parts.get(family, 1))
                for idx in range(0, len(family_rows), max_rows_per_shard):
                    chunk = family_rows[idx : idx + max_rows_per_shard]
                    part_no = start_no + (idx // max_rows_per_shard)
                    rel = f"family={family}/part-{part_no:04d}.jsonl"
                    final_path = ctx.shards_dir / rel
                    _atomic_write_jsonl(final_path, [row.model_dump() for row in chunk])
                    new_shards.append(rel)
                    for row in chunk:
                        case_to_shard[row.case_id] = rel

            shard_relpaths = sorted(set(shard_relpaths + new_shards))
            all_generated_rows = _rebuild_export(ctx, shard_relpaths)

            preflight = build_equivalent_preflight(
                all_generated_rows,
                generator_cfg=ctx.generator_cfg,
                project_root=ctx.root,
                generated_out_path=ctx.export_jsonl,
                enforce_export_contract=True,
            )

            driving_profiles = set(str(p) for p in as_list(refill_cfg.get("driving_profiles")) if str(p).strip())
            violation_family_hints = {
                str(k): [str(vv) for vv in as_list(v)]
                for k, v in dict(refill_cfg.get("violation_family_hints", {}) or {}).items()
            }

            driving_deficits, report_only_deficits = classify_deficits(
                list(preflight.get("coverage_violations", []) or []),
                driving_profiles=driving_profiles,
                family_hints=violation_family_hints,
            )
            family_survivor_counts = {
                str(k): int(v)
                for k, v in dict(preflight.get("family_survivor_counts", {}) or {}).items()
            }
            family_shortfall = compute_family_shortfall(family_survivor_counts, families_cfg)

            pass_report = build_pass_report(
                pass_no=pass_no,
                emitted_rows=[row.model_dump() for row in emitted_rows],
                preflight=preflight,
                driving_deficits=driving_deficits,
                report_only_deficits=report_only_deficits,
                family_shortfall=family_shortfall,
            )
            pass_report_path = ctx.pass_reports_dir / f"pass-{pass_no:04d}.json"
            _atomic_dump_json(pass_report_path, pass_report)

            for entry in new_bundle_entries:
                if entry.case_id:
                    entry.shard = case_to_shard.get(entry.case_id, "")
            for entry in new_exact_entries:
                entry.shard = case_to_shard.get(entry.case_id, "")
            for entry in new_structural_entries:
                entry.shard = case_to_shard.get(entry.case_id, "")

            if new_bundle_entries:
                b_rows, _, _ = BulkDedupIndex().snapshot_rows(bundle_entries=new_bundle_entries, exact_entries=[], structural_entries=[])
                bundle_entry_rows.extend(b_rows)
            if new_exact_entries:
                _, e_rows, _ = BulkDedupIndex().snapshot_rows(bundle_entries=[], exact_entries=new_exact_entries, structural_entries=[])
                exact_entry_rows.extend(e_rows)
            if new_structural_entries:
                _, _, s_rows = BulkDedupIndex().snapshot_rows(bundle_entries=[], exact_entries=[], structural_entries=new_structural_entries)
                structural_entry_rows.extend(s_rows)

            write_index_files(
                index_dir=ctx.indexes_dir,
                bundle_entries=bundle_entry_rows,
                exact_entries=exact_entry_rows,
                structural_entries=structural_entry_rows,
            )

            index.bundle_keys = set(row.get("key", "") for row in bundle_entry_rows if str(row.get("key", "")).strip())
            index.exact_hashes = set(row.get("key", "") for row in exact_entry_rows if str(row.get("key", "")).strip())
            index.structural_fingerprints = set(
                row.get("key", "") for row in structural_entry_rows if str(row.get("key", "")).strip()
            )

            existing_rows = all_generated_rows
            existing_case_ids = {row.case_id for row in existing_rows}

            manifest["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            manifest["status"] = "running"
            manifest["reason"] = f"pass_{pass_no}_committed"
            manifest["completed_passes"] = sorted(set(list(manifest.get("completed_passes", []) or []) + [pass_no]))
            manifest["shards"] = shard_relpaths
            manifest["fingerprints"] = fingerprints
            manifest["index"] = {
                "version": _INDEX_VERSION,
                "path": _as_posix_rel(ctx.root, ctx.indexes_dir),
                "bundle_count": len(index.bundle_keys),
                "exact_hash_count": len(index.exact_hashes),
                "structural_fingerprint_count": len(index.structural_fingerprints),
            }
            _atomic_dump_json(ctx.manifest_path, manifest)

            total_survivors = int(preflight.get("generated_survivors_after_build_semantics", 0))
            shortfall_total = max(0, survivor_target - total_survivors)
            new_survivors = total_survivors - prev_survivors
            prev_survivors = total_survivors

            final_driving = driving_deficits
            final_report_only = report_only_deficits
            final_shortfall = family_shortfall

            if shortfall_total <= 0 and not driving_deficits:
                reason = "target_met"
                break
            if pass_no >= max_passes:
                reason = "max_passes_reached"
                break
            if (shortfall_total > 0 or driving_deficits) and min_new_survivors_per_pass > 0 and new_survivors < min_new_survivors_per_pass:
                reason = "min_new_survivors_threshold"
                break

            selected_families = choose_refill_families(
                family_shortfall=family_shortfall,
                driving_deficits=driving_deficits,
                family_cfg=families_cfg,
            )
            if not selected_families:
                reason = "no_refill_candidates"
                break

        shortfall_total = max(0, survivor_target - prev_survivors)
        status = resolve_run_status(
            shortfall_total=shortfall_total,
            report_only_count=len(final_report_only),
            fail_on_survivor_shortfall=fail_on_survivor_shortfall,
        )

        summary = build_summary(
            status=status,
            total_emitted_rows=len(existing_rows),
            total_survivors=prev_survivors,
            driving_deficits=final_driving,
            report_only_deficits=final_report_only,
            family_shortfall=final_shortfall,
            completed_passes=list(manifest.get("completed_passes", []) or []),
            reason=reason,
        )
        _atomic_dump_json(ctx.summary_path, summary)

        manifest["status"] = status
        manifest["reason"] = reason
        manifest["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        _atomic_dump_json(ctx.manifest_path, manifest)

        return summary
    except Exception as exc:
        fail_reason = f"exception:{type(exc).__name__}"
        summary = build_summary(
            status="failed_runtime",
            total_emitted_rows=len(existing_rows),
            total_survivors=prev_survivors,
            driving_deficits=final_driving,
            report_only_deficits=final_report_only,
            family_shortfall=final_shortfall,
            completed_passes=list(manifest.get("completed_passes", []) or []),
            reason=fail_reason,
        )
        summary["error"] = str(exc)
        _atomic_dump_json(ctx.summary_path, summary)

        manifest["status"] = "failed_runtime"
        manifest["reason"] = fail_reason
        manifest["error"] = str(exc)
        manifest["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        _atomic_dump_json(ctx.manifest_path, manifest)
        raise
