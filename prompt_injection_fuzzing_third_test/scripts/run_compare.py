from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

try:
    from scripts.schemas import IoNormalizedRow, NormalizedResponse, PromptGuardRequest, PromptGuardResponse, validation_error_strings
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback
    from schemas import IoNormalizedRow, NormalizedResponse, PromptGuardRequest, PromptGuardResponse, validation_error_strings  # type: ignore


ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def run(cmd: list[str], cwd: Path, env: dict[str, str]) -> None:
    print("[run]", " ".join(cmd))
    subprocess.run(cmd, cwd=str(cwd), env=env, check=True)


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_venv(venv_dir: Path, base_python: str) -> Path:
    py = venv_python(venv_dir)
    if py.exists():
        return py
    venv_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([base_python, "-m", "venv", str(venv_dir)], check=True, cwd=str(ROOT))
    return py


def ensure_python_312(py: Path) -> None:
    proc = subprocess.run(
        [str(py), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
        check=True,
        capture_output=True,
        text=True,
    )
    version = proc.stdout.strip()
    if version != "3.12":
        raise RuntimeError(f"Python 3.12 is required by PLAN.md, but venv uses {version}")


def wait_for_health(url: str, timeout_sec: int) -> None:
    deadline = time.time() + timeout_sec
    last_error = ""
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=3.0)
            if response.status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(1.0)
    raise RuntimeError(f"Server health check failed: {url}; last_error={last_error}")


def generate_io_normalized(
    runs_jsonl: Path,
    output_jsonl: Path,
) -> None:
    rows: list[dict[str, Any]] = []
    for run_row in read_jsonl(runs_jsonl):
        transcript_rel = str(run_row.get("transcript_path", "")).strip()
        transcript_path = Path(transcript_rel)
        if not transcript_path.is_absolute():
            transcript_path = ROOT / transcript_path

        payload: dict[str, Any] = {}
        response_payload: dict[str, Any] = {}
        if transcript_path.exists():
            transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
            payload = transcript.get("payload", {}) if isinstance(transcript.get("payload"), dict) else {}
            response_payload = transcript.get("response", {}) if isinstance(transcript.get("response"), dict) else {}

        errors: list[str] = []
        req_ok = True
        resp_ok = True
        normalized_response: NormalizedResponse | None = None

        try:
            PromptGuardRequest.model_validate(payload)
        except Exception as exc:  # noqa: BLE001
            req_ok = False
            errors.extend(validation_error_strings(exc))

        try:
            parsed = PromptGuardResponse.model_validate(response_payload)
            normalized_response = NormalizedResponse(**parsed.model_dump())
        except Exception as exc:  # noqa: BLE001
            resp_ok = False
            errors.extend(validation_error_strings(exc))

        normalized = IoNormalizedRow(
            case_id=str(run_row.get("case_id", "")),
            run_id=str(run_row.get("run_id", "")),
            request=payload,
            response=response_payload,
            request_schema_ok=req_ok,
            response_schema_ok=resp_ok,
            normalized_response=normalized_response,
            validation_errors=errors,
        )
        rows.append(normalized.model_dump())

    write_jsonl(output_jsonl, rows)
    print(f"io normalized -> {output_jsonl}")


def parse_layers(value: str) -> list[str]:
    out: list[str] = []
    for token in value.split(","):
        layer = token.strip().upper()
        if not layer:
            continue
        if layer not in {"L1", "L2", "L3"}:
            raise ValueError(f"unsupported layer: {layer}")
        out.append(layer)
    if not out:
        raise ValueError("at least one layer is required")
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run KO/EN Prompt Guard comparative harness.")
    parser.add_argument("--venv-dir", type=Path, default=ROOT / ".venv")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--health-timeout-sec", type=int, default=180)
    parser.add_argument("--model-id", default=os.getenv("PROMPT_GUARD_MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M"))
    parser.add_argument("--layers", default="L1,L2,L3", help="comma-separated layers, e.g. L1,L2,L3")
    parser.add_argument("--repeats", type=int, default=1, help="repeat count per case")
    parser.add_argument("--guardrail-toggle", default="on")
    parser.add_argument("--enforcement-modes", default="annotate")
    parser.add_argument("--l1-target", type=Path, default=Path("configs/target_prompt_guard_http.yaml"))
    parser.add_argument("--l2-target", type=Path, default=Path("configs/target_prompt_guard_gateway_http.yaml"))
    parser.add_argument("--l3-target", type=Path, default=Path("configs/target_scenario_local.yaml"))
    parser.add_argument("--skip-install", action="store_true")
    return parser.parse_args()


def run_layer(
    py: Path,
    env: dict[str, str],
    layer: str,
    target_cfg: Path,
    out_dir: Path,
    repeats: int,
    guardrail_toggle: str,
    enforcement_modes: str,
) -> None:
    run(
        [
            str(py),
            "-m",
            "pi_fuzzer.cli",
            "run",
            "--layer",
            layer,
            "--package",
            "packages/dev_release",
            "--target",
            str(target_cfg.as_posix()),
            "--out",
            str(out_dir.as_posix()),
            "--repeats",
            str(repeats),
            "--guardrail-toggle",
            guardrail_toggle,
            "--enforcement-modes",
            enforcement_modes,
        ],
        ROOT,
        env,
    )


def layer_run_file(run_dir: Path, layer: str) -> Path:
    return run_dir / f"runs_{layer.lower()}.jsonl"


def score_and_report_layer(py: Path, env: dict[str, str], layer: str, runs_file: Path) -> None:
    layer_lower = layer.lower()
    score_path = Path(f"reports/scorecard_{layer_lower}.json")
    run(
        [
            str(py),
            "-m",
            "pi_fuzzer.cli",
            "score",
            "--runs",
            str(runs_file.as_posix()),
            "--package",
            "packages/dev_release",
            "--config",
            "configs/build.yaml",
            "--out",
            str(score_path.as_posix()),
        ],
        ROOT,
        env,
    )
    run(
        [
            str(py),
            "-m",
            "pi_fuzzer.cli",
            "report",
            "--score",
            str(score_path.as_posix()),
            "--md",
            f"reports/report_{layer_lower}.md",
            "--csv",
            f"reports/results_{layer_lower}.csv",
        ],
        ROOT,
        env,
    )


def main() -> None:
    args = parse_args()
    layers = parse_layers(args.layers)
    py = ensure_venv(args.venv_dir, args.python)
    ensure_python_312(py)

    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"

    if not args.skip_install:
        run([str(py), "-m", "pip", "install", "--upgrade", "pip"], ROOT, env)
        run([str(py), "-m", "pip", "install", "-r", "requirements.txt"], ROOT, env)

    need_server = any(layer in {"L1", "L2"} for layer in layers)
    server_proc: subprocess.Popen[str] | None = None
    log_file: Any = None

    if need_server:
        server_log = ROOT / "runs" / "prompt_guard_server.log"
        server_log.parent.mkdir(parents=True, exist_ok=True)
        log_file = server_log.open("w", encoding="utf-8")
        server_proc = subprocess.Popen(
            [
                str(py),
                "scripts/prompt_guard_server.py",
                "--host",
                args.host,
                "--port",
                str(args.port),
                "--model-id",
                args.model_id,
                "--window-size",
                "448",
                "--overlap",
                "64",
            ],
            cwd=str(ROOT),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    try:
        if need_server:
            wait_for_health(f"http://{args.host}:{args.port}/health", timeout_sec=args.health_timeout_sec)

        run(
            [
                str(py),
                "-m",
                "pi_fuzzer.cli",
                "build",
                "--config",
                "configs/build.yaml",
                "--out",
                "packages/dev_release",
            ],
            ROOT,
            env,
        )
        run(
            [
                str(py),
                "-m",
                "pi_fuzzer.cli",
                "validate",
                "--package",
                "packages/dev_release",
                "--config",
                "configs/build.yaml",
            ],
            ROOT,
            env,
        )

        target_by_layer = {
            "L1": args.l1_target,
            "L2": args.l2_target,
            "L3": args.l3_target,
        }
        run_files: list[Path] = []
        for layer in layers:
            run_dir = ROOT / "runs" / layer.lower()
            run_layer(
                py=py,
                env=env,
                layer=layer,
                target_cfg=target_by_layer[layer],
                out_dir=run_dir,
                repeats=args.repeats,
                guardrail_toggle=args.guardrail_toggle,
                enforcement_modes=args.enforcement_modes,
            )
            runs_file = layer_run_file(run_dir=run_dir, layer=layer)
            run_files.append(runs_file)
            score_and_report_layer(py=py, env=env, layer=layer, runs_file=runs_file)

        score_cmd = [
            str(py),
            "-m",
            "pi_fuzzer.cli",
            "score",
        ]
        for runs_file in run_files:
            score_cmd.extend(["--runs", str(runs_file.as_posix())])
        score_cmd.extend(
            [
                "--package",
                "packages/dev_release",
                "--config",
                "configs/build.yaml",
                "--out",
                "reports/scorecard.json",
            ]
        )
        run(score_cmd, ROOT, env)

        run(
            [
                str(py),
                "-m",
                "pi_fuzzer.cli",
                "report",
                "--score",
                "reports/scorecard.json",
                "--md",
                "reports/report.md",
                "--csv",
                "reports/results.csv",
            ],
            ROOT,
            env,
        )

        if "L1" in layers:
            generate_io_normalized(
                runs_jsonl=ROOT / "runs" / "l1" / "runs_l1.jsonl",
                output_jsonl=ROOT / "runs" / "l1" / "io_normalized.jsonl",
            )
            run(
                [
                    str(py),
                    "scripts/summarize_compare.py",
                    "--io-normalized",
                    "runs/l1/io_normalized.jsonl",
                    "--cases",
                    "packages/dev_release/cases.jsonl",
                    "--out-json",
                    "reports/ko_en_compare.json",
                    "--out-md",
                    "reports/ko_en_compare.md",
                ],
                ROOT,
                env,
            )
    finally:
        if server_proc is not None and server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait(timeout=10)
        if log_file is not None:
            log_file.close()


if __name__ == "__main__":
    main()
