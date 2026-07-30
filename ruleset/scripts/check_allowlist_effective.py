#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

from build_rulesets import parse_explicit_rule, parse_local_domain_text


def log(msg: str) -> None:
    print(f"[allowcheck] {msg}")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_allow_rules(path: pathlib.Path) -> set[str]:
    if not path.exists():
        return set()
    return parse_local_domain_text(path.read_text(encoding="utf-8"))


def parse_dist_rules(path: pathlib.Path) -> set[str]:
    rules: set[str] = set()
    if not path.exists():
        return rules

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = parse_explicit_rule(line)
        if parsed:
            rules.add(parsed)
    return rules


def parse_openclash_rules(path: pathlib.Path) -> set[str]:
    rules: set[str] = set()
    if not path.exists():
        return rules

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line == "payload:" or line.startswith("#"):
            continue
        if line == "payload: []" or not line.startswith("- "):
            continue
        value = line[2:].strip()
        if value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1].replace("''", "'")
        parsed = parse_explicit_rule(value)
        if parsed:
            rules.add(parsed)
    return rules


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ensure allowlists are effective in built outputs.")
    parser.add_argument(
        "--sources",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/config/sources.json"),
        help="sources.json path",
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path("ruleset"),
        help="ruleset root path",
    )
    parser.add_argument(
        "--surge-dir",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/surge"),
        help="surge dist directory",
    )
    parser.add_argument(
        "--stash-dir",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/stash"),
        help="stash dist directory",
    )
    parser.add_argument(
        "--openclash-dir",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/openclash"),
        help="openclash dist directory",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = read_json(args.sources)
    categories = payload.get("categories", [])
    if not isinstance(categories, list):
        raise SystemExit("[allowcheck] invalid sources config: categories must be array")

    violations: list[str] = []
    checked = 0

    for row in categories:
        if not isinstance(row, dict):
            continue
        category_id = str(row.get("id", "")).strip()
        allow_rel = row.get("allow_rules_path")
        if not category_id or not allow_rel:
            continue

        allow_file = args.root / str(allow_rel)
        if not allow_file.is_file():
            violations.append(
                f"{category_id}: declared allowlist file is missing -> {allow_file}"
            )
            continue
        allow_rules = parse_allow_rules(allow_file)
        if not allow_rules:
            continue

        outputs = (
            ("surge", args.surge_dir / f"{category_id}.list", parse_dist_rules),
            ("stash", args.stash_dir / f"{category_id}.list", parse_dist_rules),
            ("openclash", args.openclash_dir / f"{category_id}.yaml", parse_openclash_rules),
        )
        for output_name, dist_file, parser_fn in outputs:
            if not dist_file.exists():
                violations.append(f"{category_id}/{output_name}: missing output -> {dist_file}")
                continue

            checked += 1
            leftovers = sorted(allow_rules & parser_fn(dist_file))
            if leftovers:
                for item in leftovers[:20]:
                    violations.append(
                        f"{category_id}/{output_name}: allowlisted rule still exists -> {item}"
                    )
                if len(leftovers) > 20:
                    violations.append(
                        f"{category_id}/{output_name}: ... and {len(leftovers) - 20} more allowlist leftovers"
                    )

    if violations:
        log(f"FAILED with {len(violations)} violation(s)")
        for msg in violations:
            log(f"- {msg}")
        return 1

    log(f"passed: checked_categories={checked}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
