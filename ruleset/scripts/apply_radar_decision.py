#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


class RadarDecisionError(RuntimeError):
    pass


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RadarDecisionError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RadarDecisionError(f"JSON root must be an object: {path}")
    return payload


def apply_decision(
    manifest: dict[str, Any],
    radar: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if radar.get("candidate_only") is not True:
        raise RadarDecisionError("source radar must remain candidate-only")
    try:
        quorum = int(radar.get("high_impact_quorum", 0))
    except (TypeError, ValueError) as exc:
        raise RadarDecisionError("source radar high_impact_quorum is invalid") from exc
    if quorum < 2:
        raise RadarDecisionError("source radar high_impact_quorum must be at least 2")

    repositories = radar.get("repositories", [])
    if not isinstance(repositories, list) or not repositories:
        raise RadarDecisionError("source radar repositories must be a non-empty array")
    advanced_repositories: list[str] = []
    independent_changes: list[str] = []
    for raw in repositories:
        if not isinstance(raw, dict):
            raise RadarDecisionError("source radar repository rows must be objects")
        repository = str(raw.get("repository", "")).strip()
        role = str(raw.get("role", "")).strip()
        if role == "active-locked-source":
            locked_revision = str(raw.get("locked_revision", "")).strip()
            resolved_revision = str(raw.get("resolved_revision", "")).strip()
            if not locked_revision:
                raise RadarDecisionError(
                    f"active source is missing locked_revision: {repository}"
                )
            if resolved_revision != locked_revision:
                advanced_repositories.append(repository)
        else:
            if raw.get("candidate_only") is not True:
                raise RadarDecisionError(
                    f"independent radar source is not candidate-only: {repository}"
                )
            if bool(raw.get("changed", False)):
                independent_changes.append(repository)

    tree = radar.get("v2fly_tree", {})
    if not isinstance(tree, dict):
        raise RadarDecisionError("source radar v2fly_tree must be an object")
    head_vs_lock = tree.get("head_vs_lock", {})
    if not isinstance(head_vs_lock, dict):
        raise RadarDecisionError("source radar head_vs_lock must be an object")
    tree_advanced = bool(head_vs_lock.get("head_advanced_after_lock", False))
    if tree_advanced and "v2fly/domain-list-community" not in advanced_repositories:
        raise RadarDecisionError("source radar head/lock decision is inconsistent")

    updated = dict(manifest)
    risk_markers = {
        str(item) for item in updated.get("risk_markers", []) if str(item)
    }
    if advanced_repositories:
        risk_markers.add("source-head-advanced-after-lock")
        updated["risk_level"] = "high"
        updated["auto_promotion_eligible"] = False
        updated["requires_review"] = bool(updated.get("changed", False))
    quorum_review_required = (
        "single-community-tier" in risk_markers
        and bool(updated.get("changed", False))
    )
    updated["risk_markers"] = sorted(risk_markers)
    updated["source_head_advanced_after_lock"] = bool(advanced_repositories)
    updated["source_radar"] = {
        "candidate_only": True,
        "high_impact_quorum": quorum,
        "advanced_active_repositories": sorted(advanced_repositories),
        "independent_changed_repositories": sorted(independent_changes),
        "unbuilt_head_file_count": len(tree.get("unbuilt_head_files", [])),
        "quorum_review_required": quorum_review_required,
    }
    decision = {
        "candidate_only": True,
        "promotion_blocked": bool(advanced_repositories),
        "auto_promotion_blocked": bool(advanced_repositories)
        or quorum_review_required,
        "advanced_active_repositories": sorted(advanced_repositories),
        "independent_changed_repositories": sorted(independent_changes),
        "unbuilt_head_files": tree.get("unbuilt_head_files", []),
        "high_impact_quorum": quorum,
        "quorum_review_required": quorum_review_required,
    }
    return updated, decision


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate source radar output and merge its decision into a candidate."
    )
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--radar", type=pathlib.Path, required=True)
    parser.add_argument("--decision-output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = read_json(args.manifest)
        radar = read_json(args.radar)
        updated, decision = apply_decision(manifest, radar)
        args.manifest.write_text(
            json.dumps(updated, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        args.decision_output.parent.mkdir(parents=True, exist_ok=True)
        args.decision_output.write_text(
            json.dumps(decision, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            "[radar-decision] "
            f"promotion_blocked={str(decision['promotion_blocked']).lower()} "
            f"independent_changes={len(decision['independent_changed_repositories'])}"
        )
        return 0
    except RadarDecisionError as exc:
        print(f"[radar-decision] error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
