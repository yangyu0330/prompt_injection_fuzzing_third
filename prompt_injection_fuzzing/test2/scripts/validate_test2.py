from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
SAMPLES = ROOT / "samples"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no} invalid JSON: {exc}") from exc
    return rows


def build_schema_store() -> tuple[dict[str, Any], dict[str, Any], str]:
    schemas: dict[str, Any] = {}
    store: dict[str, Any] = {}
    base_uri = SPEC.as_uri() + "/"
    for schema_path in SPEC.glob("*.schema.json"):
        schema = load_json(schema_path)
        schemas[schema_path.name] = schema
        schema_id = schema.get("$id")
        if schema_id:
            store[schema_id] = schema
        store[(SPEC / schema_path.name).as_uri()] = schema
    return schemas, store, base_uri


def iter_errors(validator: jsonschema.Draft202012Validator, instance: Any) -> Iterable[str]:
    for err in validator.iter_errors(instance):
        loc = ".".join(str(p) for p in err.path)
        if loc:
            yield f"{loc}: {err.message}"
        else:
            yield err.message


def validate_schema_instance(
    schema_name: str,
    instance: Any,
    schemas: dict[str, Any],
    store: dict[str, Any],
    base_uri: str,
) -> None:
    schema = schemas[schema_name]
    resolver = jsonschema.RefResolver(base_uri=base_uri, referrer=schema, store=store)
    validator = jsonschema.Draft202012Validator(schema, resolver=resolver)
    errors = list(iter_errors(validator, instance))
    if errors:
        raise AssertionError(f"{schema_name} validation failed:\n- " + "\n- ".join(errors))


def check_split_hygiene(canonical: list[dict[str, Any]]) -> None:
    fam_to_splits: dict[str, set[str]] = defaultdict(set)
    for row in canonical:
        fam_to_splits[row["family_id"]].add(row["split"])
    bad = {fam: splits for fam, splits in fam_to_splits.items() if len(splits) > 1}
    if bad:
        raise AssertionError(f"family_id split hygiene failed: {bad}")


def check_pair_consistency(canonical: list[dict[str, Any]]) -> None:
    pair_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in canonical:
        if row["pair_id"].startswith("PAIR-"):
            pair_rows[row["pair_id"]].append(row)

    for pair_id, rows in pair_rows.items():
        langs = {r["lang"] for r in rows}
        families = {r["family_id"] for r in rows}
        splits = {r["split"] for r in rows}
        if langs != {"EN", "KO"}:
            raise AssertionError(f"{pair_id} must contain exactly EN and KO entries, got {langs}")
        if len(families) != 1:
            raise AssertionError(f"{pair_id} must share one family_id, got {families}")
        if len(splits) != 1:
            raise AssertionError(f"{pair_id} must share one split, got {splits}")


def check_ko_native(canonical: list[dict[str, Any]]) -> None:
    ko_native = [r for r in canonical if r["pair_id"].startswith("KO-NATIVE-")]
    if not ko_native:
        raise AssertionError("No KO-native samples found.")
    for row in ko_native:
        if row["lang"] != "KO":
            raise AssertionError(f"KO-native row must use KO lang: {row['seed_id']}")
    for row in canonical:
        if row["pair_id"].startswith("PAIR-") and row["family_id"].startswith("FAM-KONAT-"):
            raise AssertionError(f"PAIRED row cannot use KO-native family: {row['seed_id']}")


def check_hard_negative_ratio(canonical: list[dict[str, Any]], minimum: float = 0.20) -> None:
    ratio = sum(1 for r in canonical if r["is_hard_negative"]) / max(len(canonical), 1)
    if ratio < minimum:
        raise AssertionError(f"Hard negative ratio too low: {ratio:.3f} < {minimum:.3f}")


def check_layer_coverage(layer_data: dict[str, Any]) -> None:
    required_layers = [
        "pi_layer1_input",
        "pi_layer1_output",
        "pi_layer2_gateway",
        "pi_layer3_llm",
        "pi_layer4_rag_docs",
        "pi_layer4_rag_queries",
    ]
    required_surfaces = {
        "direct_user",
        "indirect_document",
        "indirect_email",
        "indirect_repo",
        "multi_turn_memory",
    }

    for layer_name in required_layers:
        rows = layer_data[layer_name]
        surfaces = {r["meta"]["attack_surface"] for r in rows}
        goals = {r["meta"]["goal"] for r in rows}
        has_hn = any(r["meta"]["is_hard_negative"] for r in rows)

        missing = required_surfaces - surfaces
        if missing:
            raise AssertionError(f"{layer_name} missing required surfaces: {sorted(missing)}")
        if "tool_redirection" not in goals:
            raise AssertionError(f"{layer_name} missing tool_redirection coverage")
        if not has_hn:
            raise AssertionError(f"{layer_name} missing hard-negative coverage")


def check_report_keys(layer_data: dict[str, Any]) -> None:
    required = {
        "by_level",
        "by_mutation",
        "by_type",
        "by_tier",
        "by_lang",
        "by_surface",
        "by_carrier",
        "by_goal",
        "by_source_side",
        "by_layer_target",
        "by_hard_negative",
    }
    stats_keys = set(layer_data["pi_stats"].keys())
    missing = required - stats_keys
    if missing:
        raise AssertionError(f"pi_stats missing keys: {sorted(missing)}")


def main() -> None:
    schemas, store, base_uri = build_schema_store()

    canonical = load_jsonl(SAMPLES / "canonical_cases.sample.jsonl")
    rendered = load_jsonl(SAMPLES / "rendered_cases.sample.jsonl")
    judge_events = load_jsonl(SAMPLES / "judge_events.sample.jsonl")
    run_results = load_jsonl(SAMPLES / "run_results.sample.jsonl")
    layer_exports = load_json(SAMPLES / "layer_exports.sample.json")

    for row in canonical:
        validate_schema_instance("canonical_case.schema.json", row, schemas, store, base_uri)
    for row in rendered:
        validate_schema_instance("rendered_case.schema.json", row, schemas, store, base_uri)
    for row in judge_events:
        validate_schema_instance("judge_event.schema.json", row, schemas, store, base_uri)
    for row in run_results:
        validate_schema_instance("run_result.schema.json", row, schemas, store, base_uri)
    validate_schema_instance("layer_exports.schema.json", layer_exports, schemas, store, base_uri)

    check_split_hygiene(canonical)
    check_pair_consistency(canonical)
    check_ko_native(canonical)
    check_hard_negative_ratio(canonical, minimum=0.20)
    check_layer_coverage(layer_exports)
    check_report_keys(layer_exports)

    print("OK: test2 package validation passed.")


if __name__ == "__main__":
    main()
