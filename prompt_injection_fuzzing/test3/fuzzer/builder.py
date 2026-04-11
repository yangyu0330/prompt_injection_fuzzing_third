from __future__ import annotations

from dataclasses import replace

from .models import FuzzCase
from .mutators import MUTATORS
from .packers import PACKERS
from .schema import compose_plain_input, normalize_case


def _base_case(case: FuzzCase) -> FuzzCase:
    c = normalize_case(case)
    if not c.input_text.strip():
        c = replace(c, input_text=compose_plain_input(c.user_task, c.attack_text))
    return c


def expand_mutations(
    case: FuzzCase,
    mutator_names: list[str],
    mutation_depth: int = 1,
    max_variants: int = 12,
) -> list[FuzzCase]:
    mutator_names = [m for m in mutator_names if m in MUTATORS and m != "none"]
    if mutation_depth < 1 or not mutator_names:
        return [_base_case(case)]

    variants: list[FuzzCase] = [_base_case(case)]
    frontier: list[FuzzCase] = [variants[0]]
    for _ in range(mutation_depth):
        next_frontier: list[FuzzCase] = []
        for node in frontier:
            for name in mutator_names:
                mutated = MUTATORS[name](node)
                next_frontier.append(mutated)
                variants.append(mutated)
                if len(variants) >= max_variants:
                    return variants[:max_variants]
        frontier = next_frontier
        if not frontier:
            break
    return variants[:max_variants]


def apply_packers(case: FuzzCase, packer_names: list[str]) -> list[FuzzCase]:
    out: list[FuzzCase] = []
    for name in packer_names:
        fn = PACKERS.get(name)
        if not fn:
            continue
        out.append(fn(case))
    return out or [case]


def build_cases(
    base_cases: list[FuzzCase],
    mutator_names: list[str],
    packer_names: list[str],
    mutation_depth: int,
    max_variants_per_seed: int,
    languages: set[str] | None = None,
    splits: set[str] | None = None,
) -> list[FuzzCase]:
    out: list[FuzzCase] = []
    seen: set[str] = set()

    for seed in base_cases:
        if languages and seed.language not in languages:
            continue
        if splits and seed.split not in splits:
            continue

        mutated = expand_mutations(
            seed,
            mutator_names=mutator_names,
            mutation_depth=mutation_depth,
            max_variants=max_variants_per_seed,
        )
        for m in mutated:
            packed = apply_packers(m, packer_names)
            for p in packed:
                if p.case_id in seen:
                    continue
                seen.add(p.case_id)
                out.append(normalize_case(p))

    return out

