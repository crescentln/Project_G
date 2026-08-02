#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DECISION_SCHEMA = "project-g-candidate-decision-v1"
AUTOMATED_REVIEW_SCHEMA = "project-g-automated-review-v2"


class CandidateIdentityError(RuntimeError):
    pass


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateIdentityError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CandidateIdentityError(f"JSON root must be an object: {path}")
    return payload


def require_bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise CandidateIdentityError(f"{key} must be a boolean")
    return value


def require_nonnegative_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateIdentityError(f"{key} must be a non-negative integer")
    return value


def sorted_strings(payload: dict[str, Any], key: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CandidateIdentityError(f"{key} must be an array of strings")
    return sorted(set(value))


def sorted_json_values(payload: dict[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise CandidateIdentityError(f"{key} must be an array")
    return sorted(
        value,
        key=lambda item: json.dumps(
            item,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def build_decision_payload(
    manifest: dict[str, Any],
    radar: dict[str, Any],
    automated_review: dict[str, Any],
) -> dict[str, Any]:
    semantic_digest = str(manifest.get("semantic_digest", "")).strip()
    source_lock_sha256 = str(manifest.get("source_lock_sha256", "")).strip()
    if not SHA256_RE.fullmatch(semantic_digest):
        raise CandidateIdentityError("semantic_digest must be a lowercase SHA-256")
    if not SHA256_RE.fullmatch(source_lock_sha256):
        raise CandidateIdentityError("source_lock_sha256 must be a lowercase SHA-256")

    risk_level = str(manifest.get("risk_level", "")).strip()
    if risk_level not in {"none", "low", "high"}:
        raise CandidateIdentityError("risk_level must be none, low, or high")
    conflict_delta = manifest.get("conflict_delta")
    if not isinstance(conflict_delta, dict):
        raise CandidateIdentityError("conflict_delta must be an object")

    review_schema = str(automated_review.get("schema", "")).strip()
    if review_schema != AUTOMATED_REVIEW_SCHEMA:
        raise CandidateIdentityError(
            f"automated review schema must be {AUTOMATED_REVIEW_SCHEMA}"
        )
    review_policy = str(automated_review.get("review_policy", "")).strip()
    if not review_policy:
        raise CandidateIdentityError("automated review policy must be non-empty")
    required_stable_cycles = require_nonnegative_int(
        automated_review, "required_stable_cycles"
    )
    if required_stable_cycles < 2:
        raise CandidateIdentityError(
            "automated review must require at least two stable cycles"
        )
    minimum_cycle_separation_seconds = require_nonnegative_int(
        automated_review, "minimum_cycle_separation_seconds"
    )
    if minimum_cycle_separation_seconds < 300:
        raise CandidateIdentityError(
            "automated review cycle separation must be at least 300 seconds"
        )
    blockers = sorted_strings(automated_review, "blockers")
    review_eligible = require_bool(automated_review, "eligible")
    if review_eligible != (len(blockers) == 0):
        raise CandidateIdentityError(
            "automated review eligibility must match its blocker set"
        )

    return {
        "schema": DECISION_SCHEMA,
        "semantic_digest": semantic_digest,
        "source_lock_sha256": source_lock_sha256,
        "changed": require_bool(manifest, "changed"),
        "risk_level": risk_level,
        "requires_review": require_bool(manifest, "requires_review"),
        "auto_promotion_eligible": require_bool(
            manifest, "auto_promotion_eligible"
        ),
        "baseline_available": require_bool(manifest, "baseline_available"),
        "source_lock_changed": require_bool(manifest, "source_lock_changed"),
        "source_head_advanced_after_lock": require_bool(
            manifest, "source_head_advanced_after_lock"
        ),
        "fallback_cache_count": require_nonnegative_int(
            manifest, "fallback_cache_count"
        ),
        "cache_blocked_source_ids": sorted_strings(
            manifest, "cache_blocked_source_ids"
        ),
        "changed_categories": sorted_strings(manifest, "changed_categories"),
        "risk_markers": sorted_strings(manifest, "risk_markers"),
        "budget_exceeded": sorted_json_values(manifest, "budget_exceeded"),
        "conflict_delta": conflict_delta,
        "automated_review": {
            "schema": review_schema,
            "eligible": review_eligible,
            "required_stable_cycles": required_stable_cycles,
            "minimum_cycle_separation_seconds": minimum_cycle_separation_seconds,
            "review_policy": review_policy,
            "report_sha256": hashlib.sha256(
                canonical_bytes(automated_review)
            ).hexdigest(),
        },
        "source_radar": {
            "candidate_only": require_bool(radar, "candidate_only"),
            "promotion_blocked": require_bool(radar, "promotion_blocked"),
            "auto_promotion_blocked": require_bool(
                radar, "auto_promotion_blocked"
            ),
            "advanced_active_repositories": sorted_strings(
                radar, "advanced_active_repositories"
            ),
            "independent_changed_repositories": sorted_strings(
                radar, "independent_changed_repositories"
            ),
            "unbuilt_head_files": sorted_strings(radar, "unbuilt_head_files"),
            "high_impact_quorum": require_nonnegative_int(
                radar, "high_impact_quorum"
            ),
            "quorum_review_required": require_bool(
                radar, "quorum_review_required"
            ),
        },
    }


def build_identity(
    manifest: dict[str, Any],
    radar: dict[str, Any],
    automated_review: dict[str, Any],
    source_sha: str,
    workflow_bytes: bytes,
) -> tuple[dict[str, Any], bytes, str]:
    source_sha = source_sha.strip()
    if not GIT_SHA_RE.fullmatch(source_sha):
        raise CandidateIdentityError("source_sha must be a lowercase 40-character Git SHA")
    decision = build_decision_payload(manifest, radar, automated_review)
    decision_bytes = canonical_bytes(decision)
    decision_fingerprint = hashlib.sha256(decision_bytes).hexdigest()
    identity = {
        "decision_fingerprint": decision_fingerprint,
        "decision_schema": DECISION_SCHEMA,
        "semantic_digest": decision["semantic_digest"],
        "source_lock_sha256": decision["source_lock_sha256"],
        "source_sha": source_sha,
        "workflow_sha256": hashlib.sha256(workflow_bytes).hexdigest(),
    }
    return identity, decision_bytes, decision_fingerprint


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build deterministic Project_G candidate decision and identity files."
    )
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--radar-decision", type=pathlib.Path, required=True)
    parser.add_argument("--automated-review", type=pathlib.Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow", type=pathlib.Path, required=True)
    parser.add_argument("--identity-output", type=pathlib.Path, required=True)
    parser.add_argument("--decision-output", type=pathlib.Path, required=True)
    parser.add_argument("--fingerprint-output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = read_json(args.manifest)
        radar = read_json(args.radar_decision)
        automated_review = read_json(args.automated_review)
        workflow_bytes = args.workflow.read_bytes()
        identity, decision_bytes, fingerprint = build_identity(
            manifest,
            radar,
            automated_review,
            args.source_sha,
            workflow_bytes,
        )
        for path in (
            args.identity_output,
            args.decision_output,
            args.fingerprint_output,
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
        args.identity_output.write_bytes(canonical_bytes(identity))
        args.decision_output.write_bytes(decision_bytes)
        args.fingerprint_output.write_text(f"{fingerprint}\n", encoding="utf-8")
        print(f"[candidate-identity] decision_fingerprint={fingerprint}")
        return 0
    except (CandidateIdentityError, OSError) as exc:
        print(f"[candidate-identity] error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
