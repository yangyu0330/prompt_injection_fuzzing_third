from __future__ import annotations

import argparse
from pathlib import Path

from .adapters import CommandAdapter, HttpAdapter, MockAdapter
from .builder import build_cases
from .io_utils import load_cases, read_jsonl, save_cases, save_results, write_json
from .metrics import summarize_results
from .runner import RunConfig, run_cases
from .sample_data import make_benign_cases, make_seed_cases
from .schema import validate_cases


def _csv(values: str | None) -> list[str]:
    if not values:
        return []
    return [v.strip() for v in values.split(",") if v.strip()]


def _print_validation(errs: dict[str, list[str]], max_lines: int = 20) -> None:
    lines = []
    for case_id, e in errs.items():
        for item in e:
            lines.append(f"- {case_id}: {item}")
    if not lines:
        return
    print("Validation errors:")
    for line in lines[:max_lines]:
        print(line)
    if len(lines) > max_lines:
        print(f"... and {len(lines) - max_lines} more")


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.output_root).expanduser().resolve()
    suites = root / "data" / "suites"
    generated = root / "data" / "generated"
    reports = root / "reports"
    suites.mkdir(parents=True, exist_ok=True)
    generated.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)

    seeds = make_seed_cases(target_count=args.seed_count)
    benign = make_benign_cases(target_count=args.benign_count)
    all_cases = seeds + benign

    errs = validate_cases(all_cases)
    if errs:
        _print_validation(errs)
        return 2

    out_path = suites / "base_seed.jsonl"
    save_cases(out_path, all_cases)
    write_json(
        root / "fuzzer_config.json",
        {
            "base_seed_path": str(out_path),
            "default_generated_path": str(generated / "cases.jsonl"),
            "default_result_path": str(reports / "run_results.jsonl"),
            "default_summary_path": str(reports / "summary.json"),
        },
    )

    print(f"Initialized fuzzer workspace under: {root}")
    print(f"Base seeds written: {out_path} ({len(all_cases)} cases)")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    cases = load_cases(args.input)
    errs = validate_cases(cases)
    if errs:
        _print_validation(errs, max_lines=100)
        print(f"Validation failed: {len(errs)} invalid cases")
        return 2
    print(f"Validation passed: {len(cases)} cases")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    base_cases = load_cases(args.input)
    mutators = _csv(args.mutators)
    packers = _csv(args.packers)
    languages = set(_csv(args.languages)) or None
    splits = set(_csv(args.splits)) or None

    cases = build_cases(
        base_cases=base_cases,
        mutator_names=mutators,
        packer_names=packers,
        mutation_depth=args.mutation_depth,
        max_variants_per_seed=args.max_variants_per_seed,
        languages=languages,
        splits=splits,
    )

    errs = validate_cases(cases)
    if errs:
        _print_validation(errs, max_lines=100)
        if args.strict:
            return 2
        print("Continuing because --strict=false")

    save_cases(args.output, cases)
    print(f"Built cases: {len(cases)}")
    print(f"Output: {Path(args.output).expanduser().resolve()}")
    return 0


def _build_adapter(args: argparse.Namespace):
    if args.adapter == "mock":
        return MockAdapter(refusal_bias=args.mock_refusal_bias)
    if args.adapter == "http":
        if not args.http_url:
            raise ValueError("--http-url is required for adapter=http")
        return HttpAdapter(
            url=args.http_url,
            timeout_sec=args.timeout_sec,
            auth_bearer=args.http_bearer,
        )
    if args.adapter == "command":
        if not args.command:
            raise ValueError("--command is required for adapter=command")
        return CommandAdapter(command=args.command, timeout_sec=args.timeout_sec)
    raise ValueError(f"Unsupported adapter: {args.adapter}")


def _progress(done: int, total: int, case_id: str) -> None:
    if done % 25 == 0 or done == total:
        print(f"[{done}/{total}] {case_id}")


def _load_results(path: str) -> list:
    return [r for r in read_jsonl(path)]


def cmd_run(args: argparse.Namespace) -> int:
    cases = load_cases(args.cases)
    if args.splits:
        wanted = set(_csv(args.splits))
        cases = [c for c in cases if c.split in wanted]
    if args.limit > 0:
        cases = cases[: args.limit]
    if not cases:
        print("No cases to run after filtering.")
        return 1

    adapter = _build_adapter(args)
    config = RunConfig(workers=args.workers, fail_on_error=args.fail_on_error)
    results = run_cases(cases, adapter, config=config, progress=_progress)
    save_results(args.output, results)

    case_index = {c.case_id: c for c in cases}
    summary = summarize_results(results, case_index)
    summary["adapter"] = adapter.name
    summary["input_cases"] = str(Path(args.cases).expanduser().resolve())
    write_json(args.summary, summary)

    print(f"Run complete: {len(results)} cases")
    print(f"Results: {Path(args.output).expanduser().resolve()}")
    print(f"Summary: {Path(args.summary).expanduser().resolve()}")
    print("Key metrics:")
    for k, v in summary["metrics"].items():
        print(f"- {k}: {v:.4f}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    cases = load_cases(args.cases)
    case_index = {c.case_id: c for c in cases}

    raw = _load_results(args.results)
    # Parse run results through the stable fields.
    from .models import RunResult

    results = []
    for row in raw:
        results.append(
            RunResult(
                case_id=row["case_id"],
                adapter=row.get("adapter", "unknown"),
                expected_oracle=row.get("expected_oracle", "NONE"),
                expected_oracle_hit=bool(row.get("expected_oracle_hit", False)),
                oracle_hits=dict(row.get("oracle_hits", {})),
                benign_hard_negative=bool(row.get("benign_hard_negative", False)),
                response=dict(row.get("response", {})),
                started_at=row.get("started_at", ""),
                ended_at=row.get("ended_at", ""),
                error=row.get("error"),
            )
        )

    summary = summarize_results(results, case_index)
    write_json(args.output, summary)
    print(f"Summary written: {Path(args.output).expanduser().resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pifuzz", description="Prompt injection fuzzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create folders and write seed dataset")
    p_init.add_argument("--output-root", default=".")
    p_init.add_argument("--seed-count", type=int, default=240)
    p_init.add_argument("--benign-count", type=int, default=60)
    p_init.set_defaults(func=cmd_init)

    p_validate = sub.add_parser("validate", help="Validate JSONL cases")
    p_validate.add_argument("--input", required=True)
    p_validate.set_defaults(func=cmd_validate)

    p_build = sub.add_parser("build", help="Build expanded fuzz cases from seed bank")
    p_build.add_argument("--input", required=True)
    p_build.add_argument("--output", required=True)
    p_build.add_argument(
        "--mutators",
        default="none,jamo,spacing,code_switch,digit_words,homoglyph,split_payload",
    )
    p_build.add_argument(
        "--packers",
        default="plain,email,meeting_note,rag_chunk,repo_issue,html,json_blob",
    )
    p_build.add_argument("--mutation-depth", type=int, default=1)
    p_build.add_argument("--max-variants-per-seed", type=int, default=10)
    p_build.add_argument("--languages", default="")
    p_build.add_argument("--splits", default="")
    p_build.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True)
    p_build.set_defaults(func=cmd_build)

    p_run = sub.add_parser("run", help="Run fuzz cases against target adapter")
    p_run.add_argument("--cases", required=True)
    p_run.add_argument("--output", required=True)
    p_run.add_argument("--summary", required=True)
    p_run.add_argument("--adapter", choices=["mock", "http", "command"], default="mock")
    p_run.add_argument("--http-url", default="")
    p_run.add_argument("--http-bearer", default="")
    p_run.add_argument("--command", default="")
    p_run.add_argument("--timeout-sec", type=float, default=30.0)
    p_run.add_argument("--mock-refusal-bias", type=float, default=0.15)
    p_run.add_argument("--workers", type=int, default=4)
    p_run.add_argument("--splits", default="")
    p_run.add_argument("--limit", type=int, default=0)
    p_run.add_argument("--fail-on-error", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_report = sub.add_parser("report", help="Build summary report from prior run")
    p_report.add_argument("--cases", required=True)
    p_report.add_argument("--results", required=True)
    p_report.add_argument("--output", required=True)
    p_report.set_defaults(func=cmd_report)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    code = args.func(args)
    raise SystemExit(code)


if __name__ == "__main__":
    main()

