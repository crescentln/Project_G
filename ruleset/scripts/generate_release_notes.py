#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def latest_changelog_entry(path: pathlib.Path) -> tuple[str, list[str]]:
    if not path.exists():
        return "", []

    lines = path.read_text(encoding="utf-8").splitlines()
    header = ""
    body: list[str] = []
    in_entry = False

    for line in lines:
        if line.startswith("## "):
            if in_entry:
                break
            header = line[3:].strip()
            in_entry = True
            continue
        if in_entry:
            body.append(line)

    return header, body


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate markdown notes for weekly ruleset release.")
    parser.add_argument("--repo", required=True, help="GitHub repository, e.g. owner/repo")
    parser.add_argument("--tag", required=True, help="Release tag")
    parser.add_argument(
        "--changelog",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/CHANGELOG.md"),
        help="Changelog markdown",
    )
    parser.add_argument(
        "--index",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/index.json"),
        help="Index json",
    )
    parser.add_argument(
        "--conflicts",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/conflicts.json"),
        help="Conflicts json",
    )
    parser.add_argument(
        "--fetch-report",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/fetch_report.json"),
        help="Fetch report json",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        required=True,
        help="Output markdown file",
    )
    parser.add_argument(
        "--candidate-manifest",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/candidate_manifest.json"),
    )
    parser.add_argument(
        "--client-parity",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/client_parity.json"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    index_payload = read_json(args.index)
    conflicts_payload = read_json(args.conflicts)
    fetch_payload = read_json(args.fetch_report)
    candidate_payload = (
        read_json(args.candidate_manifest)
        if args.candidate_manifest.is_file()
        else {}
    )
    client_payload = (
        read_json(args.client_parity)
        if args.client_parity.is_file()
        else {}
    )
    entry_time, entry_lines = latest_changelog_entry(args.changelog)

    category_count = int(index_payload.get("category_count", 0))
    conflict_count = int(conflicts_payload.get("conflict_count", 0))
    cross_action = int(conflicts_payload.get("cross_action_conflict_count", 0))
    informational_cross_action = int(
        conflicts_payload.get("informational_cross_action_conflict_count", 0)
    )
    high_severity = int(conflicts_payload.get("high_severity_conflict_count", 0))

    network = int(fetch_payload.get("network_success_count", 0))
    offline_cache = int(fetch_payload.get("offline_cache_count", 0))
    fallback_cache = int(fetch_payload.get("fallback_cache_count", 0))

    raw_base = f"https://raw.githubusercontent.com/{args.repo}/{args.tag}/ruleset/dist"

    out: list[str] = []
    out.append(f"# Ruleset Snapshot `{args.tag}`")
    out.append("")
    if entry_time:
        out.append(f"- Build Time (UTC): `{entry_time}`")
    out.append(f"- Category Count: `{category_count}`")
    out.append(
        "- Conflict Summary: "
        f"`total={conflict_count}, gated_cross_action={cross_action}, "
        f"informational_cross_action={informational_cross_action}, high={high_severity}`"
    )
    out.append(
        "- Fetch Summary: "
        f"`network={network}, offline_cache={offline_cache}, fallback_cache={fallback_cache}`"
    )
    if candidate_payload:
        out.append(
            "- Candidate Decision: "
            f"`risk={candidate_payload.get('risk_level', 'unknown')}, "
            f"semantic_digest={candidate_payload.get('semantic_digest', 'unknown')}, "
            "automated_elevated_evidence="
            f"{bool(candidate_payload.get('requires_review', False))}`"
        )
        budget_exceeded = [
            str(item) for item in candidate_payload.get("budget_exceeded", [])
        ]
        out.append(
            "- Budget Exceeded: "
            + (
                "; ".join(f"`{item}`" for item in budget_exceeded)
                if budget_exceeded
                else "none"
            )
        )
    if client_payload:
        clients = client_payload.get("clients", {})
        out.append(
            "- Client Parity: "
            f"`openclash={clients.get('openclash_effective_rules', 0)}, "
            f"surge={clients.get('surge_effective_rules', 0)}, "
            f"surge_lost={clients.get('surge_lost_rules', 0)}, "
            f"stash={clients.get('stash_effective_rules', 0)}`"
        )
    out.append("")
    out.append("## Artifacts")
    out.append("")
    out.append(f"- Index JSON: `{raw_base}/index.json`")
    out.append(f"- Policy Reference JSON: `{raw_base}/policy_reference.json`")
    out.append(f"- Immutable Source Lock: `{raw_base}/sources.lock.json`")
    out.append(f"- Source Provenance: `{raw_base}/source_provenance.json`")
    out.append(f"- Source Health: `{raw_base}/source_health.json`")
    out.append(f"- Rule Delta and Risk: `{raw_base}/rule_delta.json`")
    out.append(f"- Client Parity: `{raw_base}/client_parity.json`")
    out.append(f"- Candidate Radar: `{raw_base}/candidate_sources.json`")
    out.append(f"- Recommended OpenClash: `{raw_base}/recommended_openclash.yaml`")
    out.append(f"- Recommended Surge: `{raw_base}/recommended_surge.conf`")
    out.append(f"- Recommended Stash (classical): `{raw_base}/recommended_stash.yaml`")
    out.append(f"- Recommended Stash Native: `{raw_base}/recommended_stash_native.yaml`")

    change_lines = [line for line in entry_lines if line.startswith("- `")]
    if change_lines:
        out.append("")
        out.append("## Top Rule Count Changes")
        out.append("")
        out.extend(change_lines[:20])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    print(f"[release-notes] wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
