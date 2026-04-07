import json
from pathlib import Path


NON_INPUT_ENTRY_POINTS = {
    "retrieved_document",
    "quoted_reply",
    "email_body",
    "webpage_body",
    "html_comment_or_metadata",
    "file_text",
    "tool_output",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def test_sample_cases_do_not_keep_input_stage_for_non_input_entry_points() -> None:
    rows = _read_jsonl(_repo_root() / "catalogs" / "sample_cases.jsonl")
    violations = [
        (r.get("case_id", ""), r.get("source_stage", ""), r.get("entry_point", ""))
        for r in rows
        if (r.get("source_stage") or "").strip().lower() == "input"
        and (r.get("entry_point") or "").strip().lower() in NON_INPUT_ENTRY_POINTS
    ]
    assert violations == []


def test_sample_templates_do_not_keep_input_stage_for_non_input_entry_points() -> None:
    rows = _read_jsonl(_repo_root() / "catalogs" / "sample_templates.jsonl")
    violations = []
    for row in rows:
        stage = (row.get("source_stage") or "").strip().lower()
        entry_points = [(ep or "").strip().lower() for ep in (row.get("supported_entry_points") or [])]
        if stage == "input" and any(ep in NON_INPUT_ENTRY_POINTS for ep in entry_points):
            violations.append((row.get("template_id", ""), row.get("source_stage", ""), entry_points))
    assert violations == []
