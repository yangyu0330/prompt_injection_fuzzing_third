from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated
from typing import Any

import typer

from .build import build_package, validate_package
from .dispatch import build_request_payload, dispatch_http, map_response
from .engine import load_package, load_runs, load_target_config, save_runs
from .generator import generate_cases
from .guardrail_adapters import apply_response_adapter
from .ingest import ingest_public
from .io_utils import dump_json, read_json
from .reporting import write_results_csv, write_scorecard_json, write_scorecard_markdown
from .runtime_render import render_runtime_trusted_instruction, render_runtime_untrusted_input
from .runners import run_gateway_case, run_scenario_case, run_text_only_case
from .scoring import build_scorecard

app = typer.Typer(help="Prompt injection benchmark builder/runner/scorer/reporter")


def _project_root() -> Path:
    return Path.cwd()


def _split_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _resolve_score_coverage_summary(package: Path, config: Path | None) -> dict[str, Any]:
    if config is None:
        return {
            "checked": False,
            "passed": None,
            "note": "coverage_not_evaluated_in_score",
        }
    if not config.exists():
        raise typer.BadParameter(f"config not found: {config}")

    validation = validate_package(package_dir=package, config_path=config)
    coverage = dict(validation.get("coverage", {}))
    coverage["passed"] = not bool(coverage.get("violations"))
    coverage["validation_ok"] = bool(validation.get("ok", False))
    return coverage


@app.command("build")
def cmd_build(
    config: Annotated[Path, typer.Option("--config")],
    out: Annotated[Path, typer.Option("--out")] = Path("packages/dev_release"),
) -> None:
    manifest = build_package(config_path=config, out_dir=out, project_root=_project_root())
    typer.echo(json.dumps(manifest, ensure_ascii=False, indent=2))


@app.command("validate")
def cmd_validate(
    package: Annotated[Path, typer.Option("--package")],
    config: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    result = validate_package(package_dir=package, config_path=config)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["ok"]:
        raise typer.Exit(code=2)


@app.command("ingest-public")
def cmd_ingest_public(
    source: Annotated[str, typer.Option("--source")],
    input_path: Annotated[Path, typer.Option("--input")],
    out: Annotated[Path, typer.Option("--out")],
) -> None:
    result = ingest_public(source=source, input_path=input_path, out_path=out)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))


@app.command("generate-cases")
def cmd_generate_cases(
    templates: Annotated[list[Path], typer.Option("--templates")],
    config: Annotated[Path, typer.Option("--config")] = Path("configs/generator_mvp.yaml"),
    out: Annotated[Path, typer.Option("--out")] = Path("catalogs/generated_cases.jsonl"),
    resume: Annotated[bool, typer.Option("--resume")] = False,
) -> None:
    if not templates:
        raise typer.BadParameter("at least one --templates path is required")
    summary = generate_cases(
        template_sources=templates,
        config_path=config,
        out_path=out,
        project_root=_project_root(),
        resume=resume,
    )
    typer.echo(json.dumps(summary, ensure_ascii=False, indent=2))
    status = str(summary.get("status", ""))
    if status.startswith("failed_"):
        raise typer.Exit(code=2)


@app.command("run")
def cmd_run(
    layer: Annotated[str, typer.Option("--layer")],
    package: Annotated[Path, typer.Option("--package")],
    target: Annotated[Path, typer.Option("--target")],
    out: Annotated[Path, typer.Option("--out")] = Path("runs"),
    repeats: Annotated[int, typer.Option("--repeats")] = 1,
    guardrail_toggle: Annotated[str, typer.Option("--guardrail-toggle")] = "on,off",
    enforcement_modes: Annotated[str, typer.Option("--enforcement-modes")] = "allow,annotate,mask,block",
    run_seed: Annotated[int, typer.Option("--run-seed")] = 20260403,
) -> None:
    templates, cases, _manifest = load_package(package)
    template_kind_by_id = {t.template_id: t.template_kind for t in templates}
    target_cfg = load_target_config(target)

    layer = layer.upper()
    if layer not in {"L1", "L2", "L3"}:
        raise typer.BadParameter("layer must be one of L1, L2, L3")

    selected = cases
    if layer == "L3":
        selected = [c for c in cases if template_kind_by_id.get(c.template_id) == "outcome_scenario"]
    if layer in {"L1", "L2"}:
        selected = [c for c in cases if template_kind_by_id.get(c.template_id) != "outcome_scenario"]

    toggles = _split_csv(guardrail_toggle)
    modes = _split_csv(enforcement_modes)
    run_rows = []
    transcript_dir = out / "transcripts" / layer.lower()
    for c in selected:
        for tgl in toggles:
            for mode in modes:
                for rep in range(1, repeats + 1):
                    if layer == "L1":
                        rr = run_text_only_case(c, target_cfg, transcript_dir, run_seed, rep, tgl, mode)
                    elif layer == "L2":
                        rr = run_gateway_case(c, target_cfg, transcript_dir, run_seed, rep, tgl, mode)
                    else:
                        rr = run_scenario_case(c, target_cfg, transcript_dir, run_seed, rep, tgl, mode)
                    run_rows.append(rr)

    out.mkdir(parents=True, exist_ok=True)
    run_file = out / f"runs_{layer.lower()}.jsonl"
    save_runs(run_file, run_rows)
    typer.echo(f"wrote {len(run_rows)} runs -> {run_file}")


@app.command("score")
def cmd_score(
    runs: Annotated[list[Path], typer.Option("--runs")],
    package: Annotated[Path, typer.Option("--package")],
    config: Annotated[Path | None, typer.Option("--config")] = None,
    out: Annotated[Path, typer.Option("--out")] = Path("reports/scorecard.json"),
) -> None:
    _templates, cases, manifest = load_package(package)
    run_rows = load_runs(runs)
    coverage_summary = _resolve_score_coverage_summary(package, config)
    scorecard = build_scorecard(run_rows, cases, coverage_summary=coverage_summary, package_meta=manifest)
    write_scorecard_json(scorecard, out)
    typer.echo(f"scorecard -> {out}")


@app.command("report")
def cmd_report(
    score: Annotated[Path, typer.Option("--score")],
    md: Annotated[Path, typer.Option("--md")] = Path("reports/report.md"),
    csv: Annotated[Path, typer.Option("--csv")] = Path("reports/results.csv"),
) -> None:
    raw = read_json(score)
    from .models import Scorecard

    scorecard = Scorecard(**raw)
    write_scorecard_markdown(scorecard, md)
    write_results_csv(scorecard, csv)
    typer.echo(f"report -> {md}")
    typer.echo(f"csv -> {csv}")


@app.command("dispatch-http")
def cmd_dispatch_http(
    target: Annotated[Path, typer.Option("--target")],
    package: Annotated[Path, typer.Option("--package")],
    case_id: Annotated[str, typer.Option("--case-id")],
    guardrail_toggle: Annotated[str, typer.Option("--guardrail-toggle")] = "on",
    enforcement_mode: Annotated[str, typer.Option("--enforcement-mode")] = "annotate",
) -> None:
    _templates, cases, _manifest = load_package(package)
    target_cfg = load_target_config(target)
    case = next((c for c in cases if c.case_id == case_id), None)
    if case is None:
        raise typer.BadParameter(f"case_id not found: {case_id}")
    rendered_trusted = render_runtime_trusted_instruction(case)
    rendered_untrusted = render_runtime_untrusted_input(case)
    payload = build_request_payload(
        target_cfg,
        {
            "case_id": case.case_id,
            "language": case.language,
            "source_stage": case.source_stage,
            "turn_mode": case.turn_mode,
            "entry_point": case.entry_point,
            "trusted_instruction": rendered_trusted,
            "rendered_input": rendered_untrusted,
            "guardrail_toggle": guardrail_toggle,
            "enforcement_mode": enforcement_mode,
        },
    )
    raw = dispatch_http(target_cfg, payload)
    mapped = map_response(raw, target_cfg.response_field_map)
    mapped = apply_response_adapter(
        target_cfg.response_adapter,
        raw_response=raw,
        mapped_response=mapped,
        adapter_config=target_cfg.adapter_config,
    )
    typer.echo(json.dumps({"payload": payload, "mapped": mapped}, ensure_ascii=False, indent=2))


@app.command("serve-prompt-guard")
def cmd_serve_prompt_guard(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8011,
    model_id: Annotated[str, typer.Option("--model-id")] = "meta-llama/Llama-Prompt-Guard-2-86M",
    threshold: Annotated[float, typer.Option("--threshold")] = 0.5,
    use_mock: Annotated[bool, typer.Option("--use-mock")] = False,
) -> None:
    from .prompt_guard_runtime import run_prompt_guard_server

    run_prompt_guard_server(
        host=host,
        port=port,
        model_id=model_id,
        threshold=threshold,
        use_mock=use_mock,
    )


@app.command("serve-gateway-probe")
def cmd_serve_gateway_probe(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8012,
    litellm_base_url: Annotated[str, typer.Option("--litellm-base-url")] = "http://127.0.0.1:4000",
    model_alias: Annotated[str, typer.Option("--model-alias")] = "pi-fuzz-smoke-model",
    guardrail_name: Annotated[str, typer.Option("--guardrail-name")] = "prompt-guard-pre",
    api_key: Annotated[str, typer.Option("--api-key")] = "",
    timeout_sec: Annotated[float, typer.Option("--timeout-sec")] = 20.0,
) -> None:
    from .gateway_probe_runtime import run_gateway_probe_server

    resolved_api_key = api_key or os.getenv("PI_FUZZ_LITELLM_API_KEY", "sk-local-litellm")
    run_gateway_probe_server(
        host=host,
        port=port,
        litellm_base_url=litellm_base_url,
        model_alias=model_alias,
        guardrail_name=guardrail_name,
        api_key=resolved_api_key,
        timeout_sec=timeout_sec,
    )


if __name__ == "__main__":
    app()
