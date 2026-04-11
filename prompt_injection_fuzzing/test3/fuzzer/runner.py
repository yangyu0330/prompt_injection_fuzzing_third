from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .adapters import BaseAdapter
from .models import FuzzCase, RunResult
from .oracles import evaluate_all, evaluate_expected


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class RunConfig:
    workers: int = 1
    fail_on_error: bool = False


def _execute_case(adapter: BaseAdapter, case: FuzzCase) -> RunResult:
    started_at = _now()
    try:
        resp = adapter.run(case)
        hits = evaluate_all(case, resp)
        expected_hit = evaluate_expected(case, resp, hits)
        ended_at = _now()
        return RunResult(
            case_id=case.case_id,
            adapter=adapter.name,
            expected_oracle=case.expected_oracle,
            expected_oracle_hit=expected_hit,
            oracle_hits=hits,
            benign_hard_negative=case.benign_hard_negative,
            response=resp.to_dict(),
            started_at=started_at,
            ended_at=ended_at,
            error=None,
        )
    except Exception as exc:
        ended_at = _now()
        return RunResult(
            case_id=case.case_id,
            adapter=adapter.name,
            expected_oracle=case.expected_oracle,
            expected_oracle_hit=False,
            oracle_hits={},
            benign_hard_negative=case.benign_hard_negative,
            response={},
            started_at=started_at,
            ended_at=ended_at,
            error=str(exc),
        )


def run_cases(
    cases: list[FuzzCase],
    adapter: BaseAdapter,
    config: RunConfig | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> list[RunResult]:
    config = config or RunConfig()
    if config.workers < 1:
        config.workers = 1

    results: list[RunResult] = []
    total = len(cases)

    if config.workers == 1:
        for i, case in enumerate(cases, 1):
            result = _execute_case(adapter, case)
            results.append(result)
            if progress:
                progress(i, total, case.case_id)
            if result.error and config.fail_on_error:
                raise RuntimeError(f"Run failed for {case.case_id}: {result.error}")
        return results

    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        fut_map = {pool.submit(_execute_case, adapter, c): c for c in cases}
        done = 0
        for fut in as_completed(fut_map):
            case = fut_map[fut]
            result = fut.result()
            results.append(result)
            done += 1
            if progress:
                progress(done, total, case.case_id)
            if result.error and config.fail_on_error:
                raise RuntimeError(f"Run failed for {case.case_id}: {result.error}")

    # Keep deterministic output order.
    by_id = {r.case_id: r for r in results}
    return [by_id[c.case_id] for c in cases if c.case_id in by_id]

