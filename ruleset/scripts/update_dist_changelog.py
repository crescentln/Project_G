#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
from typing import Any


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_counts(payload: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    rows = payload.get("categories", [])
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        category_id = str(row.get("id", "")).strip()
        if not category_id:
            continue
        try:
            count = int(row.get("rule_count", 0))
        except (TypeError, ValueError):
            continue
        out[category_id] = count
    return out


def diff_counts(before: dict[str, int], after: dict[str, int]) -> list[str]:
    changes: list[tuple[str, int, int, int]] = []
    for category_id in sorted(set(before) | set(after)):
        old = int(before.get(category_id, 0))
        new = int(after.get(category_id, 0))
        if old == new:
            continue
        delta = new - old
        changes.append((category_id, old, new, delta))
    changes.sort(key=lambda item: abs(item[3]), reverse=True)
    lines = [f"- `{cid}`: {old} -> {new} ({delta:+d})" for cid, old, new, delta in changes]
    return lines


def normalize_existing_body(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        return ""

    if lines[0].startswith("# Ruleset Dist Changelog"):
        body_lines = lines[3:] if len(lines) >= 3 else []
        return "\n".join(body_lines).strip()
    return text.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update ruleset dist changelog.")
    parser.add_argument(
        "--current-policy",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/policy_reference.json"),
        help="Current policy reference JSON",
    )
    parser.add_argument(
        "--baseline-policy",
        type=pathlib.Path,
        default=None,
        help="Baseline policy reference JSON for diff",
    )
    parser.add_argument(
        "--conflicts",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/conflicts.json"),
        help="Conflicts report JSON",
    )
    parser.add_argument(
        "--fetch-report",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/fetch_report.json"),
        help="Fetch report JSON",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/CHANGELOG.md"),
        help="Changelog output path",
    )
    parser.add_argument(
        "--max-change-lines",
        type=int,
        default=20,
        help="Maximum changed categories to include",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    now_utc = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    current_policy = read_json(args.current_policy)
    current_counts = parse_counts(current_policy)
    current_category_count = len(current_counts)

    conflict_payload = read_json(args.conflicts)
    fetch_payload = read_json(args.fetch_report)

    entry_lines = [f"## {now_utc}", ""]
    entry_lines.append(f"- Category Count: {current_category_count}")
    entry_lines.append(
        "- Conflict Summary: "
        f"total={int(conflict_payload.get('conflict_count', 0))}, "
        f"cross_action={int(conflict_payload.get('cross_action_conflict_count', 0))}, "
        f"high={int(conflict_payload.get('high_severity_conflict_count', 0))}"
    )
    entry_lines.append(
        "- Fetch Summary: "
        f"network={int(fetch_payload.get('network_success_count', 0))}, "
        f"offline_cache={int(fetch_payload.get('offline_cache_count', 0))}, "
        f"fallback_cache={int(fetch_payload.get('fallback_cache_count', 0))}"
    )

    change_lines: list[str] = []
    if args.baseline_policy and args.baseline_policy.exists():
        baseline_policy = read_json(args.baseline_policy)
        baseline_counts = parse_counts(baseline_policy)
        change_lines = diff_counts(baseline_counts, current_counts)

    if change_lines:
        entry_lines.append("- Top Rule Count Changes:")
        entry_lines.extend(change_lines[: max(args.max_change_lines, 1)])
    else:
        entry_lines.append("- Top Rule Count Changes: none")

    entry_lines.extend(["", ""])
    new_entry = "\n".join(entry_lines)

    existing_body = normalize_existing_body(args.output)
    output_lines = [
        "# Ruleset Dist Changelog",
        "",
        "Auto-generated summary for `ruleset/dist` updates.",
        "",
        new_entry.rstrip(),
    ]
    if existing_body:
        output_lines.extend(["", existing_body])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(output_lines).rstrip() + "\n", encoding="utf-8")
    print(f"[changelog] updated {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
