#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

EXPLICIT_PREFIXES = (
    "DOMAIN,",
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "DOMAIN-REGEX,",
    "IP-CIDR,",
    "IP-CIDR6,",
)


def log(msg: str) -> None:
    print(f"[allowcheck] {msg}")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_domain_token(token: str) -> str:
    value = token.strip().lower()
    if value.startswith("+."):
        value = value[2:]
    elif value.startswith("."):
        value = value[1:]
    elif value.startswith("||"):
        value = value[2:]
    value = value.strip(".")
    return value


def parse_allow_rules(path: pathlib.Path) -> set[str]:
    rules: set[str] = set()
    if not path.exists():
        return rules

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        line = re.split(r"\s[#;]", line, maxsplit=1)[0].strip()
        if not line:
            continue

        upper = line.upper()
        if upper.startswith(EXPLICIT_PREFIXES):
            rules.add(line)
            continue

        domain = normalize_domain_token(line)
        if domain:
            rules.add(f"DOMAIN-SUFFIX,{domain}")

    return rules


def parse_dist_rules(path: pathlib.Path) -> set[str]:
    rules: set[str] = set()
    if not path.exists():
        return rules

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rules.add(line)
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
        allow_rules = parse_allow_rules(allow_file)
        if not allow_rules:
            continue

        dist_file = args.surge_dir / f"{category_id}.list"
        dist_rules = parse_dist_rules(dist_file)
        checked += 1

        leftovers = sorted(allow_rules & dist_rules)
        if leftovers:
            for item in leftovers[:20]:
                violations.append(f"{category_id}: allowlisted rule still exists -> {item}")
            if len(leftovers) > 20:
                violations.append(
                    f"{category_id}: ... and {len(leftovers) - 20} more allowlist leftovers"
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
