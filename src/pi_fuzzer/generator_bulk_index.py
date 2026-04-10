from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .io_utils import read_jsonl, write_jsonl
from .models import CaseRecord
from .text_utils import normalize_text, sha256_text
from .validation import render_payload_text, structural_fingerprint


@dataclass
class IndexEntry:
    key: str
    case_id: str
    shard: str
    family: str
    template_id: str


class BulkDedupIndex:
    def __init__(self) -> None:
        self.bundle_keys: set[str] = set()
        self.exact_hashes: set[str] = set()
        self.structural_fingerprints: set[str] = set()

    @classmethod
    def load(cls, index_dir: Path) -> BulkDedupIndex:
        index = cls()
        if not index_dir.exists():
            return index

        bundle_path = index_dir / "bundle_index.jsonl"
        exact_path = index_dir / "exact_hash_index.jsonl"
        structural_path = index_dir / "structural_fingerprint_index.jsonl"

        if bundle_path.exists():
            for row in read_jsonl(bundle_path):
                key = str(row.get("key", "")).strip()
                if key:
                    index.bundle_keys.add(key)

        if exact_path.exists():
            for row in read_jsonl(exact_path):
                key = str(row.get("key", "")).strip()
                if key:
                    index.exact_hashes.add(key)

        if structural_path.exists():
            for row in read_jsonl(structural_path):
                key = str(row.get("key", "")).strip()
                if key:
                    index.structural_fingerprints.add(key)

        return index

    def seen_bundle(self, key: str) -> bool:
        return key in self.bundle_keys

    def seen_exact(self, key: str) -> bool:
        return key in self.exact_hashes

    def seen_structural(self, key: str) -> bool:
        return key in self.structural_fingerprints

    def add_bundle(self, key: str) -> None:
        if key:
            self.bundle_keys.add(key)

    def add_row(self, row: CaseRecord) -> tuple[str, str]:
        exact = exact_payload_hash(row)
        structural = structural_fingerprint(row)
        self.exact_hashes.add(exact)
        self.structural_fingerprints.add(structural)
        return exact, structural

    def snapshot_rows(
        self,
        *,
        bundle_entries: Iterable[IndexEntry],
        exact_entries: Iterable[IndexEntry],
        structural_entries: Iterable[IndexEntry],
    ) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
        bundle_rows = [
            {
                "key": e.key,
                "case_id": e.case_id,
                "shard": e.shard,
                "family": e.family,
                "template_id": e.template_id,
            }
            for e in bundle_entries
        ]
        exact_rows = [
            {
                "key": e.key,
                "case_id": e.case_id,
                "shard": e.shard,
                "family": e.family,
                "template_id": e.template_id,
            }
            for e in exact_entries
        ]
        structural_rows = [
            {
                "key": e.key,
                "case_id": e.case_id,
                "shard": e.shard,
                "family": e.family,
                "template_id": e.template_id,
            }
            for e in structural_entries
        ]
        return bundle_rows, exact_rows, structural_rows



def exact_payload_hash(case: CaseRecord) -> str:
    return sha256_text(normalize_text(render_payload_text(case)))


def rebuild_index_from_rows(rows: list[CaseRecord]) -> BulkDedupIndex:
    index = BulkDedupIndex()
    for row in rows:
        index.exact_hashes.add(exact_payload_hash(row))
        index.structural_fingerprints.add(structural_fingerprint(row))
    return index


def write_index_files(
    *,
    index_dir: Path,
    bundle_entries: list[dict[str, str]],
    exact_entries: list[dict[str, str]],
    structural_entries: list[dict[str, str]],
) -> None:
    index_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(index_dir / "bundle_index.jsonl", bundle_entries)
    write_jsonl(index_dir / "exact_hash_index.jsonl", exact_entries)
    write_jsonl(index_dir / "structural_fingerprint_index.jsonl", structural_entries)
