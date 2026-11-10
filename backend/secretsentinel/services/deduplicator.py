"""Deduplicate findings within a scan.

Two passes, both using only safe identity fields:

1. Exact occurrence: same rule, path, line and commit -> one finding
   (merging ``sources`` when ``both`` mode sees it in dir and git scans).
   A ``dir`` finding (no commit) and a ``git`` finding for the same rule,
   path and line are treated as the same occurrence and merged, keeping the
   commit reference.
2. Overlap: different rules on the same path/line/commit (e.g. a Web3 rule
   and Gitleaks' generic-api-key on ``PRIVATE_KEY=0x...``) -> keep the most
   severe/specific finding and record the others in ``also_matched``.
"""

from __future__ import annotations

from .types import CONFIDENCE_ORDER, SEVERITY_ORDER, SafeFinding


def _rank(f: SafeFinding) -> tuple:
    specific = 0 if f.rule_id.startswith("generic") else 1
    return (SEVERITY_ORDER.get(f.severity, 0), specific, CONFIDENCE_ORDER.get(f.confidence, 0), f.rule_id)


def _merge_sources(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(a) | set(b)))


def deduplicate(findings: list[SafeFinding]) -> list[SafeFinding]:
    # Pass 1: exact occurrences (commit-insensitive between dir and git).
    by_occurrence: dict[tuple, SafeFinding] = {}
    for f in findings:
        key = (f.rule_id, f.relative_path, f.start_line)
        existing = by_occurrence.get(key)
        if existing is None:
            by_occurrence[key] = f
            continue
        if existing.commit_sha and f.commit_sha and existing.commit_sha != f.commit_sha:
            # Same text added in two different commits: genuinely distinct occurrences.
            by_occurrence[key + (f.commit_sha,)] = f
            continue
        existing.sources = _merge_sources(existing.sources, f.sources)
        existing.commit_sha = existing.commit_sha or f.commit_sha
        existing.tags = tuple(dict.fromkeys(existing.tags + f.tags))

    # Pass 2: overlapping rules at the same location.
    by_location: dict[tuple, list[SafeFinding]] = {}
    for f in by_occurrence.values():
        by_location.setdefault((f.relative_path, f.start_line, f.commit_sha), []).append(f)
    result: list[SafeFinding] = []
    for group in by_location.values():
        if len(group) == 1:
            result.append(group[0])
            continue
        group.sort(key=_rank, reverse=True)
        best = group[0]
        others = [g.rule_id for g in group[1:]]
        best.also_matched = tuple(sorted(set(best.also_matched) | set(others)))
        for g in group[1:]:
            best.sources = _merge_sources(best.sources, g.sources)
        result.append(best)
    result.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.relative_path, f.start_line, f.rule_id))
    return result
