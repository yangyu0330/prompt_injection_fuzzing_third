from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator, TypeVar

from .models import FuzzCase, RunResult

T = TypeVar("T")


def ensure_parent(path: str | Path) -> None:
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def read_jsonl(path: str | Path) -> Iterator[dict]:
    p = Path(path).expanduser().resolve()
    with p.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {p}:{line_no}: {exc}") from exc


def write_jsonl(path: str | Path, rows: Iterable[dict]) -> None:
    ensure_parent(path)
    p = Path(path).expanduser().resolve()
    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_cases(path: str | Path) -> list[FuzzCase]:
    return [FuzzCase.from_dict(row) for row in read_jsonl(path)]


def save_cases(path: str | Path, cases: Iterable[FuzzCase]) -> None:
    write_jsonl(path, (c.to_dict() for c in cases))


def save_results(path: str | Path, results: Iterable[RunResult]) -> None:
    write_jsonl(path, (r.to_dict() for r in results))


def write_json(path: str | Path, obj: dict) -> None:
    ensure_parent(path)
    p = Path(path).expanduser().resolve()
    with p.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")

