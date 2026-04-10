from __future__ import annotations

from collections import Counter
from typing import Any


def _family_from_violation(violation: dict[str, Any]) -> str | None:
    dims = list(violation.get("dims", []) or [])
    key = list(violation.get("key", []) or [])

    if violation.get("kind") == "required_value" and len(key) >= 2 and str(key[0]) == "attack_family":
        fam = str(key[1]).strip()
        if fam:
            return fam

    if "attack_family" in dims and len(dims) == len(key):
        idx = dims.index("attack_family")
        if idx < len(key):
            fam = str(key[idx]).strip()
            if fam.startswith("attack_family="):
                fam = fam.split("=", 1)[1].strip()
            if fam:
                return fam

    if violation.get("kind") == "required_combination":
        for token in key:
            text = str(token)
            if text.startswith("attack_family="):
                fam = text.split("=", 1)[1].strip()
                if fam:
                    return fam

    return None


def classify_deficits(
    coverage_violations: list[dict[str, Any]],
    *,
    driving_profiles: set[str],
    family_hints: dict[str, list[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    driving: list[dict[str, Any]] = []
    report_only: list[dict[str, Any]] = []

    for violation in coverage_violations:
        profile = str(violation.get("profile", ""))
        key = tuple(str(v) for v in (violation.get("key") or []))
        hint_families = list(family_hints.get("|".join(key), []))
        family = _family_from_violation(violation)

        item = {
            "profile": profile,
            "kind": str(violation.get("kind", "")),
            "key": list(violation.get("key", []) or []),
            "dims": list(violation.get("dims", []) or []),
            "count": int(violation.get("count", 0)),
            "required": int(violation.get("required", 0)),
            "suggested_families": [family] if family else hint_families,
        }

        invertible = bool(item["suggested_families"])
        if profile in driving_profiles and invertible:
            driving.append(item)
        else:
            report_only.append(item)

    return driving, report_only


def generated_family_stats(rows: list[dict[str, Any]], survivor_case_ids: set[str]) -> dict[str, dict[str, int]]:
    by_family_input = Counter(str(r.get("attack_family", "")) for r in rows)
    by_family_survivor = Counter(
        str(r.get("attack_family", "")) for r in rows if str(r.get("case_id", "")) in survivor_case_ids
    )

    families = sorted(set(by_family_input) | set(by_family_survivor))
    stats: dict[str, dict[str, int]] = {}
    for family in families:
        input_count = int(by_family_input.get(family, 0))
        survivor_count = int(by_family_survivor.get(family, 0))
        stats[family] = {
            "input": input_count,
            "survivor": survivor_count,
            "drop": max(0, input_count - survivor_count),
        }
    return stats


def compute_family_shortfall(
    family_survivor_counts: dict[str, int],
    family_targets: dict[str, dict[str, Any]],
) -> dict[str, int]:
    shortfall: dict[str, int] = {}
    for family, cfg in family_targets.items():
        target = int(cfg.get("target_survivors", 0) or 0)
        if target <= 0:
            continue
        observed = int(family_survivor_counts.get(family, 0))
        gap = max(0, target - observed)
        if gap > 0:
            shortfall[family] = gap
    return shortfall


def choose_refill_families(
    *,
    family_shortfall: dict[str, int],
    driving_deficits: list[dict[str, Any]],
    family_cfg: dict[str, dict[str, Any]],
) -> list[str]:
    hinted: set[str] = set()
    for deficit in driving_deficits:
        for fam in deficit.get("suggested_families", []) or []:
            if fam:
                hinted.add(str(fam))

    candidates = set(family_shortfall.keys()) | hinted

    def _priority(family: str) -> tuple[float, int, int, str]:
        cfg = family_cfg.get(family, {}) or {}
        priority = int(cfg.get("priority", 0) or 0)
        gap = int(family_shortfall.get(family, 0) or 0)
        target = int(cfg.get("target_survivors", 0) or 0)
        ratio = (float(gap) / float(target)) if target > 0 else 0.0
        return (-ratio, -priority, -gap, family)

    return sorted(candidates, key=_priority)


def resolve_run_status(
    *,
    shortfall_total: int,
    report_only_count: int,
    fail_on_survivor_shortfall: bool,
) -> str:
    if shortfall_total > 0:
        if fail_on_survivor_shortfall:
            return "failed_survivor_shortfall"
        return "success_with_survivor_shortfall"
    if report_only_count > 0:
        return "success_with_report_only_deficits"
    return "success"


def status_exit_code(status: str) -> int:
    if status.startswith("failed_"):
        return 2
    return 0


def build_pass_report(
    *,
    pass_no: int,
    emitted_rows: list[dict[str, Any]],
    preflight: dict[str, Any],
    driving_deficits: list[dict[str, Any]],
    report_only_deficits: list[dict[str, Any]],
    family_shortfall: dict[str, int],
) -> dict[str, Any]:
    survivor_ids = set(preflight.get("survivor_case_ids", []) or [])
    family_stats = generated_family_stats(emitted_rows, survivor_ids)
    return {
        "pass": pass_no,
        "input_rows": len(emitted_rows),
        "survivors": int(preflight.get("generated_survivors_after_build_semantics", 0)),
        "coverage_violation_count": int(preflight.get("coverage_violation_count", 0)),
        "driving_deficit_count": len(driving_deficits),
        "report_only_deficit_count": len(report_only_deficits),
        "family_stats": family_stats,
        "family_shortfall": dict(sorted(family_shortfall.items())),
        "driving_deficits": driving_deficits,
        "report_only_deficits": report_only_deficits,
    }


def build_summary(
    *,
    status: str,
    total_emitted_rows: int,
    total_survivors: int,
    driving_deficits: list[dict[str, Any]],
    report_only_deficits: list[dict[str, Any]],
    family_shortfall: dict[str, int],
    completed_passes: list[int],
    reason: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "completed_passes": completed_passes,
        "input_rows": total_emitted_rows,
        "survivors": total_survivors,
        "driving_deficit_count": len(driving_deficits),
        "report_only_deficit_count": len(report_only_deficits),
        "family_shortfall": dict(sorted(family_shortfall.items())),
        "driving_deficits": driving_deficits,
        "report_only_deficits": report_only_deficits,
    }
