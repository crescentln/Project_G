#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


class GateError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[gates] {message}")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GateError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"invalid json: {path}: {exc}") from exc


def parse_rule_counts(payload: dict[str, Any], source_path: pathlib.Path) -> dict[str, int]:
    categories = payload.get("categories")
    if not isinstance(categories, list):
        raise GateError(f"{source_path}: 'categories' must be an array")

    out: dict[str, int] = {}
    for idx, row in enumerate(categories):
        if not isinstance(row, dict):
            raise GateError(f"{source_path}: categories[{idx}] must be an object")
        category_id = str(row.get("id", "")).strip()
        if not category_id:
            continue
        try:
            count = int(row.get("rule_count", 0))
        except (TypeError, ValueError) as exc:
            raise GateError(f"{source_path}: invalid rule_count for '{category_id}'") from exc
        out[category_id] = count
    return out


def compute_count_drift(
    baseline_counts: dict[str, int],
    current_counts: dict[str, int],
    max_change_pct: float,
    min_abs_delta: int,
    min_baseline_rules: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    changes: list[dict[str, Any]] = []
    violations: list[str] = []

    common_ids = sorted(set(baseline_counts) & set(current_counts))
    for category_id in common_ids:
        before = baseline_counts[category_id]
        after = current_counts[category_id]
        delta = after - before
        abs_delta = abs(delta)
        pct = (abs_delta * 100.0 / before) if before > 0 else (100.0 if after > 0 else 0.0)

        changes.append(
            {
                "id": category_id,
                "before": before,
                "after": after,
                "delta": delta,
                "delta_pct": pct,
            }
        )

        if before < min_baseline_rules:
            continue
        if abs_delta < min_abs_delta:
            continue
        if pct > max_change_pct:
            violations.append(
                f"rule count drift too large: {category_id} before={before} after={after} "
                f"delta={delta:+d} ({pct:.2f}%)"
            )

    removed_ids = sorted(set(baseline_counts) - set(current_counts))
    for category_id in removed_ids:
        before = baseline_counts[category_id]
        if before >= min_baseline_rules:
            violations.append(f"category removed from current output: {category_id} (baseline={before})")

    return changes, violations


def resolve_conflict_counts(payload: dict[str, Any]) -> tuple[int, int]:
    try:
        cross_action_conflicts = int(payload.get("cross_action_conflict_count", 0))
    except (TypeError, ValueError):
        cross_action_conflicts = 0
    try:
        high_severity_conflicts = int(payload.get("high_severity_conflict_count", 0))
    except (TypeError, ValueError):
        high_severity_conflicts = 0

    if cross_action_conflicts or high_severity_conflicts:
        return cross_action_conflicts, high_severity_conflicts

    raw_conflicts = payload.get("conflicts", [])
    if not isinstance(raw_conflicts, list):
        return 0, 0

    cross_action_conflicts = 0
    high_severity_conflicts = 0
    for item in raw_conflicts:
        if not isinstance(item, dict):
            continue
        conflict_type = str(item.get("type", "")).strip()
        severity = str(item.get("severity", "")).strip().lower()
        if conflict_type and conflict_type != "same_action_overlap":
            cross_action_conflicts += 1
        if severity == "high":
            high_severity_conflicts += 1
    return cross_action_conflicts, high_severity_conflicts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Quality gates for ruleset pipeline outputs.")
    parser.add_argument(
        "--current",
        type=pathlib.Path,
        required=True,
        help="Current policy reference JSON path (usually ruleset/dist/policy_reference.json).",
    )
    parser.add_argument(
        "--baseline",
        type=pathlib.Path,
        default=None,
        help="Previous policy reference JSON path for drift comparison.",
    )
    parser.add_argument(
        "--fetch-report",
        type=pathlib.Path,
        required=True,
        help="Fetch report JSON path (ruleset/dist/fetch_report.json).",
    )
    parser.add_argument(
        "--conflicts",
        type=pathlib.Path,
        required=True,
        help="Conflicts report JSON path (ruleset/dist/conflicts.json).",
    )
    parser.add_argument(
        "--max-change-pct",
        type=float,
        default=20.0,
        help="Maximum allowed percentage change per category (default: 20).",
    )
    parser.add_argument(
        "--min-abs-delta",
        type=int,
        default=50,
        help="Minimum absolute delta before applying pct gate (default: 50).",
    )
    parser.add_argument(
        "--min-baseline-rules",
        type=int,
        default=100,
        help="Minimum baseline size before applying pct gate (default: 100).",
    )
    parser.add_argument(
        "--max-fetch-fallbacks",
        type=int,
        default=0,
        help="Maximum allowed fallback_cache_count in fetch report (default: 0).",
    )
    parser.add_argument(
        "--max-cross-action-conflicts",
        type=int,
        default=0,
        help="Maximum allowed cross-action conflicts (default: 0).",
    )
    parser.add_argument(
        "--max-high-severity-conflicts",
        type=int,
        default=0,
        help="Maximum allowed high severity conflicts (default: 0).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    violations: list[str] = []

    current_payload = read_json(args.current)
    current_counts = parse_rule_counts(current_payload, args.current)
    log(f"current categories: {len(current_counts)}")

    if args.baseline is None:
        log("baseline not provided, skip rule-count drift gate")
    elif not args.baseline.exists():
        log(f"baseline file not found, skip rule-count drift gate: {args.baseline}")
    else:
        baseline_payload = read_json(args.baseline)
        baseline_counts = parse_rule_counts(baseline_payload, args.baseline)
        changes, drift_violations = compute_count_drift(
            baseline_counts=baseline_counts,
            current_counts=current_counts,
            max_change_pct=args.max_change_pct,
            min_abs_delta=args.min_abs_delta,
            min_baseline_rules=args.min_baseline_rules,
        )
        top_changes = sorted(changes, key=lambda x: abs(int(x["delta"])), reverse=True)[:8]
        for item in top_changes:
            log(
                "drift "
                f"{item['id']}: {item['before']} -> {item['after']} "
                f"({item['delta']:+d}, {item['delta_pct']:.2f}%)"
            )
        violations.extend(drift_violations)

    fetch_payload = read_json(args.fetch_report)
    try:
        fallback_cache_count = int(fetch_payload.get("fallback_cache_count", 0))
    except (TypeError, ValueError) as exc:
        raise GateError(f"{args.fetch_report}: invalid fallback_cache_count") from exc
    log(
        "fetch report "
        f"network={fetch_payload.get('network_success_count', 0)} "
        f"offline_cache={fetch_payload.get('offline_cache_count', 0)} "
        f"fallback_cache={fallback_cache_count}"
    )
    if fallback_cache_count > args.max_fetch_fallbacks:
        violations.append(
            f"fetch fallback exceeded: fallback_cache_count={fallback_cache_count}, "
            f"limit={args.max_fetch_fallbacks}"
        )

    conflict_payload = read_json(args.conflicts)
    cross_action_conflicts, high_severity_conflicts = resolve_conflict_counts(conflict_payload)
    log(
        "conflicts report "
        f"cross_action={cross_action_conflicts} high_severity={high_severity_conflicts}"
    )
    if cross_action_conflicts > args.max_cross_action_conflicts:
        violations.append(
            f"cross-action conflicts exceeded: {cross_action_conflicts} > {args.max_cross_action_conflicts}"
        )
    if high_severity_conflicts > args.max_high_severity_conflicts:
        violations.append(
            f"high-severity conflicts exceeded: {high_severity_conflicts} > {args.max_high_severity_conflicts}"
        )

    if violations:
        log(f"FAILED with {len(violations)} violation(s):")
        for item in violations:
            log(f"- {item}")
        return 2

    log("all quality gates passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        log(f"error: {exc}")
        raise SystemExit(1) from exc
