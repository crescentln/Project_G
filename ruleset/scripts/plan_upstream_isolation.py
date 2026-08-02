#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from collections import defaultdict, deque
from typing import Any

try:
    from ruleset.scripts.check_automated_review import (
        ISOLATION_EVIDENCE_SCHEMA,
        ISOLATION_ARTIFACT_SCHEMA,
        REPORT_SCHEMA,
        canonical_bytes,
        canonical_source_bindings,
        digest_payload,
        isolation_finding,
    )
except ModuleNotFoundError:
    from check_automated_review import (  # type: ignore[no-redef]
        ISOLATION_EVIDENCE_SCHEMA,
        ISOLATION_ARTIFACT_SCHEMA,
        REPORT_SCHEMA,
        canonical_bytes,
        canonical_source_bindings,
        digest_payload,
        isolation_finding,
    )


PLAN_SCHEMA = "project-g-upstream-isolation-plan-v1"
PLANNER_POLICY = "atomic-source-binding-category-lkg-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IsolationPlannerError(RuntimeError):
    pass


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IsolationPlannerError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise IsolationPlannerError(f"JSON root must be an object: {path}")
    return payload


def verify_digest(payload: dict[str, Any], field: str, label: str) -> None:
    expected = str(payload.get(field, ""))
    without_digest = dict(payload)
    without_digest.pop(field, None)
    if expected != digest_payload(without_digest):
        raise IsolationPlannerError(f"{label} digest is invalid")


def attach_isolation_evidence(
    review: dict[str, Any], artifact: dict[str, Any]
) -> dict[str, Any]:
    if artifact.get("schema") != ISOLATION_ARTIFACT_SCHEMA:
        raise IsolationPlannerError("isolation artifact schema is invalid")
    if artifact.get("mode") != "shadow-only":
        raise IsolationPlannerError("isolation artifact is not shadow-only")
    verify_digest(artifact, "artifact_sha256", "isolation artifact")
    if artifact.get("automated_review_sha256") != digest_payload(review):
        raise IsolationPlannerError("isolation artifact review binding is invalid")
    for artifact_field, review_field in (
        ("baseline_index_sha256", "baseline_index_sha256"),
        ("candidate_index_sha256", "current_index_sha256"),
        ("source_config_sha256", "source_config_sha256"),
    ):
        if artifact.get(artifact_field) != review.get(review_field):
            raise IsolationPlannerError(
                f"isolation artifact {artifact_field} binding is invalid"
            )
    isolation = artifact.get("isolation_evidence")
    if not isinstance(isolation, dict):
        raise IsolationPlannerError("isolation artifact lacks evidence")
    attached = dict(review)
    attached["isolation_evidence"] = isolation
    return attached


def category_graph(
    source_config: dict[str, Any],
) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]]]:
    raw_categories = source_config.get("categories")
    if not isinstance(raw_categories, list):
        raise IsolationPlannerError("source config categories must be an array")
    categories: set[str] = set()
    components: dict[str, set[str]] = {}
    for raw in raw_categories:
        if not isinstance(raw, dict):
            raise IsolationPlannerError("source config category rows must be objects")
        category = str(raw.get("id", ""))
        if not category or category in categories:
            raise IsolationPlannerError(
                "source config categories must be unique and named"
            )
        categories.add(category)
        aggregate = raw.get("aggregate_of", [])
        if aggregate is None:
            aggregate = []
        if not isinstance(aggregate, list) or any(
            not isinstance(item, str) or not item for item in aggregate
        ):
            raise IsolationPlannerError(
                f"category {category} aggregate_of must be an array of names"
            )
        components[category] = set(aggregate)
    for category, direct_components in components.items():
        missing = direct_components - categories
        if missing:
            raise IsolationPlannerError(
                f"category {category} references unknown aggregates: "
                + ", ".join(sorted(missing))
            )

    dependents: dict[str, set[str]] = {category: set() for category in categories}
    for aggregate, direct_components in components.items():
        for component in direct_components:
            dependents[component].add(aggregate)

    indegree = {category: len(components[category]) for category in categories}
    queue = deque(sorted(category for category, count in indegree.items() if not count))
    visited: list[str] = []
    while queue:
        category = queue.popleft()
        visited.append(category)
        for dependent in sorted(dependents[category]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)
    if len(visited) != len(categories):
        raise IsolationPlannerError("source config aggregate graph contains a cycle")
    return categories, components, dependents


def transitive_dependents(
    seeds: set[str], dependents: dict[str, set[str]]
) -> set[str]:
    closure = set(seeds)
    queue = deque(sorted(seeds))
    while queue:
        category = queue.popleft()
        for dependent in sorted(dependents.get(category, set())):
            if dependent not in closure:
                closure.add(dependent)
                queue.append(dependent)
    return closure


def repository_category_bindings(
    source_config: dict[str, Any], provenance: dict[str, Any]
) -> dict[str, set[str]]:
    bindings = canonical_source_bindings(source_config).get("bindings")
    if not isinstance(bindings, dict):
        raise IsolationPlannerError("canonical source bindings are malformed")
    source_rows = provenance.get("sources")
    if not isinstance(source_rows, list):
        raise IsolationPlannerError("source provenance sources must be an array")
    result: dict[str, set[str]] = defaultdict(set)
    for raw in source_rows:
        if not isinstance(raw, dict):
            raise IsolationPlannerError("source provenance rows must be objects")
        source_id = str(raw.get("source_id", ""))
        binding = bindings.get(source_id)
        if not isinstance(binding, dict):
            continue
        category = str(binding.get("category", ""))
        repository = str(raw.get("repository", ""))
        if not repository:
            resolved_ref = str(raw.get("resolved_ref", ""))
            if "://" in resolved_ref:
                repository = resolved_ref.split("://", 1)[1].split("/", 1)[0]
        if category and repository:
            result[repository].add(category)
    return result


def validate_review(
    review: dict[str, Any],
    source_config: dict[str, Any],
    baseline_index: dict[str, Any],
    candidate_index: dict[str, Any],
    provenance: dict[str, Any],
) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    if review.get("schema") != REPORT_SCHEMA:
        raise IsolationPlannerError("automated review schema is invalid")
    if review.get("source_config_sha256") != digest_payload(source_config):
        raise IsolationPlannerError("automated review source config binding is invalid")
    if review.get("baseline_index_sha256") != digest_payload(baseline_index):
        raise IsolationPlannerError("automated review baseline index binding is invalid")
    if review.get("current_index_sha256") != digest_payload(candidate_index):
        raise IsolationPlannerError("automated review candidate index binding is invalid")

    changed_categories = review.get("changed_categories")
    blockers = review.get("blockers")
    isolation = review.get("isolation_evidence")
    if (
        not isinstance(changed_categories, list)
        or any(not isinstance(item, str) or not item for item in changed_categories)
        or changed_categories != sorted(set(changed_categories))
    ):
        raise IsolationPlannerError("automated review changed categories are invalid")
    if (
        not isinstance(blockers, list)
        or any(not isinstance(item, str) or not item for item in blockers)
        or blockers != sorted(set(blockers))
    ):
        raise IsolationPlannerError("automated review blockers are invalid")
    if not isinstance(isolation, dict):
        raise IsolationPlannerError("automated review lacks isolation evidence")
    if isolation.get("schema") != ISOLATION_EVIDENCE_SCHEMA:
        raise IsolationPlannerError("isolation evidence schema is invalid")
    if isolation.get("mode") != "shadow-only":
        raise IsolationPlannerError("isolation evidence is not shadow-only")
    verify_digest(isolation, "evidence_sha256", "isolation evidence")
    if isolation.get("source_provenance_sha256") != digest_payload(provenance):
        raise IsolationPlannerError(
            "isolation evidence candidate provenance binding is invalid"
        )

    findings = isolation.get("findings")
    unscoped = isolation.get("unscoped_blockers")
    derived_blocker_sha256s = isolation.get("derived_blocker_sha256s")
    if not isinstance(findings, list) or any(
        not isinstance(item, dict) for item in findings
    ):
        raise IsolationPlannerError("isolation findings are invalid")
    if (
        not isinstance(unscoped, list)
        or any(not isinstance(item, str) or not item for item in unscoped)
        or unscoped != sorted(set(unscoped))
        or any(item not in blockers for item in unscoped)
    ):
        raise IsolationPlannerError("unscoped isolation blockers are invalid")
    if (
        not isinstance(derived_blocker_sha256s, list)
        or any(
            not isinstance(item, str) or not SHA256_RE.fullmatch(item)
            for item in derived_blocker_sha256s
        )
        or derived_blocker_sha256s != sorted(set(derived_blocker_sha256s))
    ):
        raise IsolationPlannerError("derived isolation blocker digests are invalid")
    if isolation.get("complete_blocker_mapping") is not (not unscoped):
        raise IsolationPlannerError("isolation blocker completeness is inconsistent")
    if isolation.get("blocker_count") != len(blockers):
        raise IsolationPlannerError("isolation blocker count is inconsistent")
    if isolation.get("findings_sha256") != digest_payload(findings):
        raise IsolationPlannerError("isolation findings digest is invalid")

    mapped_blocker_sha256s: set[str] = set()
    for finding in findings:
        verify_digest(finding, "evidence_digest", "isolation finding")
        category = str(finding.get("category", ""))
        if category and category not in changed_categories:
            raise IsolationPlannerError(
                f"isolation finding references unchanged category {category}"
            )
        if finding.get("scope") not in {"rule", "source-binding", "category", "global"}:
            raise IsolationPlannerError("isolation finding scope is invalid")
        if not isinstance(finding.get("isolatable"), bool):
            raise IsolationPlannerError("isolation finding isolatable state is invalid")
        blocker_sha256 = finding.get("blocker_sha256")
        if not isinstance(blocker_sha256, str) or (
            blocker_sha256 and not SHA256_RE.fullmatch(blocker_sha256)
        ):
            raise IsolationPlannerError("isolation finding blocker digest is invalid")
        if blocker_sha256:
            message = str(finding.get("message", ""))
            if blocker_sha256 != hashlib.sha256(
                message.encode("utf-8")
            ).hexdigest():
                raise IsolationPlannerError(
                    "isolation finding blocker binding is invalid"
                )
            mapped_blocker_sha256s.add(blocker_sha256)
        for field in ("source_ids", "repository_bindings", "dependency_closure"):
            values = finding.get(field)
            if (
                not isinstance(values, list)
                or any(not isinstance(item, str) or not item for item in values)
                or values != sorted(set(values))
            ):
                raise IsolationPlannerError(
                    f"isolation finding {field} is invalid"
                )
    blocker_sha256s = {
        hashlib.sha256(message.encode("utf-8")).hexdigest()
        for message in blockers
    }
    unscoped_blocker_sha256s = {
        hashlib.sha256(message.encode("utf-8")).hexdigest()
        for message in unscoped
    }
    derived_blocker_sha256_set = set(derived_blocker_sha256s)
    if (
        mapped_blocker_sha256s
        | derived_blocker_sha256_set
        | unscoped_blocker_sha256s
    ) != blocker_sha256s:
        raise IsolationPlannerError(
            "isolation blocker digest coverage is not exact"
        )
    if (
        mapped_blocker_sha256s & derived_blocker_sha256_set
        or mapped_blocker_sha256s & unscoped_blocker_sha256s
        or derived_blocker_sha256_set & unscoped_blocker_sha256s
    ):
        raise IsolationPlannerError("isolation blocker digest classes overlap")
    if isolation.get("mapped_blocker_count") != len(mapped_blocker_sha256s):
        raise IsolationPlannerError("mapped isolation blocker count is inconsistent")
    if isolation.get("derived_blocker_count") != len(
        derived_blocker_sha256_set
    ):
        raise IsolationPlannerError("derived isolation blocker count is inconsistent")
    return changed_categories, findings, unscoped


def build_plan(
    review: dict[str, Any],
    source_config: dict[str, Any],
    baseline_index: dict[str, Any],
    candidate_index: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    changed_categories, findings, unscoped = validate_review(
        review, source_config, baseline_index, candidate_index, provenance
    )
    categories, components, dependents = category_graph(source_config)
    unknown_changed = set(changed_categories) - categories
    if unknown_changed:
        raise IsolationPlannerError(
            "automated review references unknown changed categories: "
            + ", ".join(sorted(unknown_changed))
        )

    repository_categories = repository_category_bindings(
        source_config, provenance
    )
    reason_codes: dict[str, set[str]] = defaultdict(set)
    quarantined: set[str] = set()
    global_hold = bool(unscoped)
    if global_hold:
        for category in changed_categories:
            reason_codes[category].add("unscoped-review-blocker")

    for finding in findings:
        category = str(finding.get("category", ""))
        code = str(finding.get("code", "invalid-finding"))
        if finding.get("isolatable") is not True or finding.get("scope") == "global":
            global_hold = True
            for changed_category in changed_categories:
                reason_codes[changed_category].add("non-isolatable-finding")
            continue
        seeds: set[str] = {category} if category else set()
        for repository in finding.get("repository_bindings", []):
            seeds.update(repository_categories.get(str(repository), set()))
        if not seeds:
            global_hold = True
            for changed_category in changed_categories:
                reason_codes[changed_category].add("unbound-isolation-finding")
            continue
        affected = transitive_dependents(seeds, dependents)
        for affected_category in affected & set(changed_categories):
            quarantined.add(affected_category)
            reason_codes[affected_category].add(code)

    if global_hold:
        quarantined = set(changed_categories)
    accepted = sorted(set(changed_categories) - quarantined)
    quarantined_categories = sorted(quarantined)

    delta_counts: dict[str, int] = {}
    category_evidence = review.get("category_evidence", [])
    if not isinstance(category_evidence, list):
        raise IsolationPlannerError("automated review category evidence is invalid")
    for raw in category_evidence:
        if not isinstance(raw, dict):
            raise IsolationPlannerError("automated review category rows are invalid")
        category = str(raw.get("category", ""))
        added = raw.get("added_count")
        removed = raw.get("removed_count")
        if (
            not category
            or isinstance(added, bool)
            or not isinstance(added, int)
            or added < 0
            or isinstance(removed, bool)
            or not isinstance(removed, int)
            or removed < 0
        ):
            raise IsolationPlannerError("automated review category counts are invalid")
        if category in delta_counts:
            raise IsolationPlannerError(
                "automated review category evidence contains duplicates"
            )
        delta_counts[category] = added + removed
    if set(delta_counts) != set(changed_categories):
        raise IsolationPlannerError(
            "automated review category evidence is not exact"
        )

    category_decisions = []
    for category in changed_categories:
        use_candidate = category in accepted
        category_decisions.append(
            {
                "category": category,
                "shadow_selection": (
                    "candidate-category"
                    if use_candidate
                    else "published-category-lkg"
                ),
                "candidate_delta_count": delta_counts[category],
                "quarantined": not use_candidate,
                "reason_codes": sorted(reason_codes.get(category, set())),
                "aggregate_components": sorted(components.get(category, set())),
            }
        )

    isolation = review["isolation_evidence"]
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "mode": "shadow-only",
        "enforcement_ready": False,
        "planner_policy": PLANNER_POLICY,
        "isolation_unit": "source-binding-with-shared-repository-closure",
        "fallback_granularity": "published-category-lkg",
        "per_source_lkg_bootstrap_required": True,
        "baseline_index_sha256": digest_payload(baseline_index),
        "candidate_index_sha256": digest_payload(candidate_index),
        "source_config_sha256": digest_payload(source_config),
        "source_provenance_sha256": digest_payload(provenance),
        "automated_review_sha256": digest_payload(
            {
                key: value
                for key, value in review.items()
                if key != "isolation_evidence"
            }
        ),
        "isolation_evidence_sha256": str(isolation["evidence_sha256"]),
        "changed_categories": changed_categories,
        "accepted_candidate_categories": accepted,
        "quarantined_categories": quarantined_categories,
        "safe_slice_changed": bool(accepted),
        "planned_safe_delta_count": sum(
            delta_counts[category] for category in accepted
        ),
        "publishable_safe_delta_count": 0,
        "composite_validation_required": True,
        "quarantine_active": bool(quarantined_categories),
        "global_hold": global_hold,
        "unscoped_blockers": unscoped,
        "category_decisions": category_decisions,
        "repository_dependency_closure": {
            repository: sorted(bound_categories)
            for repository, bound_categories in sorted(
                repository_categories.items()
            )
        },
    }
    plan["plan_fingerprint"] = digest_payload(plan)
    return plan


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic, non-authoritative upstream-isolation shadow plan."
        )
    )
    parser.add_argument("--automated-review", type=pathlib.Path, required=True)
    parser.add_argument("--isolation-evidence", type=pathlib.Path, required=True)
    parser.add_argument("--source-config", type=pathlib.Path, required=True)
    parser.add_argument("--baseline-dist", type=pathlib.Path, required=True)
    parser.add_argument("--candidate-dist", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--require-empty-safe-slice", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        review = attach_isolation_evidence(
            read_json(args.automated_review),
            read_json(args.isolation_evidence),
        )
        source_config = read_json(args.source_config)
        baseline_index = read_json(args.baseline_dist / "index.json")
        candidate_index = read_json(args.candidate_dist / "index.json")
        provenance = read_json(args.candidate_dist / "source_provenance.json")
        plan = build_plan(
            review,
            source_config,
            baseline_index,
            candidate_index,
            provenance,
        )
        if args.require_empty_safe_slice and plan["safe_slice_changed"]:
            raise IsolationPlannerError(
                "shadow plan unexpectedly contains an accepted candidate category"
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_bytes(plan))
    except (IsolationPlannerError, OSError) as exc:
        print(f"upstream isolation planning failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
