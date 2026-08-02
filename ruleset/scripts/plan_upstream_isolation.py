#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import urllib.parse
from collections import defaultdict, deque
from typing import Any

try:
    from ruleset.scripts.build_category_lkg_binding import (
        BINDING_POLICY,
        BINDING_SCHEMA,
        CATEGORY_OUTPUT_PATH_FIELDS,
        CATEGORY_OUTPUT_PATH_TEMPLATES,
        CategoryLkgBindingError,
        category_output_identities,
        directory_manifest,
        validate_source_provenance,
    )
    from ruleset.scripts.check_automated_review import (
        ISOLATION_EVIDENCE_SCHEMA,
        ISOLATION_ARTIFACT_SCHEMA,
        REPORT_SCHEMA,
        AutomatedReviewError,
        canonical_bytes,
        canonical_source_bindings,
        digest_payload,
        isolation_finding,
        source_lock_identity,
    )
except ModuleNotFoundError:
    from build_category_lkg_binding import (  # type: ignore[no-redef]
        BINDING_POLICY,
        BINDING_SCHEMA,
        CATEGORY_OUTPUT_PATH_FIELDS,
        CATEGORY_OUTPUT_PATH_TEMPLATES,
        CategoryLkgBindingError,
        category_output_identities,
        directory_manifest,
        validate_source_provenance,
    )
    from check_automated_review import (  # type: ignore[no-redef]
        ISOLATION_EVIDENCE_SCHEMA,
        ISOLATION_ARTIFACT_SCHEMA,
        REPORT_SCHEMA,
        AutomatedReviewError,
        canonical_bytes,
        canonical_source_bindings,
        digest_payload,
        isolation_finding,
        source_lock_identity,
    )


PLAN_SCHEMA = "project-g-upstream-isolation-plan-v2"
SELECTION_SCHEMA = "project-g-upstream-isolation-selection-v1"
PLANNER_POLICY = "atomic-repository-category-lkg-shadow-v2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CATEGORY_SEMANTIC_FIELDS = (
    "normalized_rules_sha256",
    "rule_count",
    "recommended_action",
    "recommended_priority",
    "contract_sha256",
)


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


def repository_identity(raw_ref: str) -> str:
    parsed = urllib.parse.urlparse(raw_ref)
    hostname = (parsed.hostname or "").lower()
    parts = [urllib.parse.unquote(item) for item in parsed.path.split("/") if item]
    if hostname == "api.github.com" and len(parts) >= 3 and parts[0] == "repos":
        return f"{parts[1]}/{parts[2]}".removesuffix(".git")
    if hostname in {
        "github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
    } and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}".removesuffix(".git")
    if hostname in {"cdn.jsdelivr.net", "testingcf.jsdelivr.net"}:
        if len(parts) >= 3 and parts[0] == "gh":
            return f"{parts[1]}/{parts[2].split('@', 1)[0]}".removesuffix(
                ".git"
            )
    return hostname


def repository_category_bindings(
    source_config: dict[str, Any],
    provenance: dict[str, Any],
    source_lock_repositories: dict[str, Any],
) -> dict[str, set[str]]:
    bindings = canonical_source_bindings(source_config).get("bindings")
    if not isinstance(bindings, dict):
        raise IsolationPlannerError("canonical source bindings are malformed")
    source_rows = provenance.get("sources")
    source_count = provenance.get("source_count")
    if (
        not isinstance(source_rows, list)
        or isinstance(source_count, bool)
        or not isinstance(source_count, int)
        or source_count != len(source_rows)
    ):
        raise IsolationPlannerError("source provenance sources must be an array")
    source_by_id: dict[str, dict[str, Any]] = {}
    for raw in source_rows:
        if not isinstance(raw, dict):
            raise IsolationPlannerError("source provenance rows must be objects")
        source_id = str(raw.get("source_id", "")).strip()
        if not source_id or source_id in source_by_id:
            raise IsolationPlannerError(
                "source provenance IDs must be unique and named"
            )
        source_by_id[source_id] = raw
    missing = sorted(set(bindings) - set(source_by_id))
    if missing:
        raise IsolationPlannerError(
            "source provenance canonical coverage is incomplete: "
            + ", ".join(missing[:5])
        )

    result: dict[str, set[str]] = defaultdict(set)
    repository_source_ids: dict[str, set[str]] = defaultdict(set)
    for source_id, binding in sorted(bindings.items()):
        if not isinstance(binding, dict):
            raise IsolationPlannerError("canonical source binding rows are malformed")
        raw = source_by_id[source_id]
        category = str(binding.get("category", ""))
        if not category:
            raise IsolationPlannerError("canonical source binding category is absent")
        configured_identities = {
            identity
            for identity in (
                repository_identity(str(item))
                for item in binding.get("requested_refs", [])
            )
            if identity
        }
        configured_repositories = {
            identity for identity in configured_identities if "/" in identity
        }
        if len(configured_repositories) > 1:
            raise IsolationPlannerError(
                f"source configuration spans multiple repositories: {source_id}"
            )
        declared_repository = str(raw.get("repository", "")).strip()
        resolved_repository = repository_identity(str(raw.get("resolved_ref", "")))
        if configured_repositories:
            repository = next(iter(configured_repositories))
            if (
                declared_repository != repository
                or resolved_repository != repository
            ):
                raise IsolationPlannerError(
                    f"source provenance repository differs from configuration: {source_id}"
                )
        else:
            if declared_repository:
                raise IsolationPlannerError(
                    f"non-repository source declares a repository: {source_id}"
                )
            if configured_identities and resolved_repository not in configured_identities:
                raise IsolationPlannerError(
                    f"source provenance endpoint differs from configuration: {source_id}"
                )
            repository = resolved_repository
        if repository:
            result[repository].add(category)
            repository_source_ids[repository].add(source_id)

    for repository, raw_lock in sorted(source_lock_repositories.items()):
        if not isinstance(raw_lock, dict):
            raise IsolationPlannerError(
                f"candidate source lock entry is malformed: {repository}"
            )
        source_ids = repository_source_ids.get(repository, set())
        binding_count = raw_lock.get("binding_count")
        if (
            not source_ids
            or isinstance(binding_count, bool)
            or not isinstance(binding_count, int)
            or binding_count != len(source_ids)
        ):
            raise IsolationPlannerError(
                f"candidate source lock binding coverage is inconsistent: {repository}"
            )
        for source_id in sorted(source_ids):
            raw = source_by_id[source_id]
            if (
                raw.get("requested_ref") != raw_lock.get("requested_ref")
                or raw.get("resolved_revision") != raw_lock.get("resolved_revision")
            ):
                raise IsolationPlannerError(
                    f"candidate source lock identity is inconsistent: {source_id}"
                )
    return result


def selected_provenance_rows(
    source_config: dict[str, Any],
    provenance: dict[str, Any],
    candidate_bound_categories: set[str],
) -> list[dict[str, Any]]:
    bindings = canonical_source_bindings(source_config).get("bindings")
    source_rows = provenance.get("sources")
    if not isinstance(bindings, dict) or not isinstance(source_rows, list):
        raise IsolationPlannerError("selected provenance inputs are malformed")
    source_by_id = {
        str(raw.get("source_id", "")): raw
        for raw in source_rows
        if isinstance(raw, dict)
    }
    rows: list[dict[str, Any]] = []
    for source_id, binding in sorted(bindings.items()):
        if (
            not isinstance(binding, dict)
            or str(binding.get("category", "")) not in candidate_bound_categories
        ):
            continue
        raw = source_by_id.get(source_id)
        if not isinstance(raw, dict):
            raise IsolationPlannerError(
                f"selected source provenance is absent: {source_id}"
            )
        identity = {
            "source_id": source_id,
            "binding_id": str(binding.get("binding_id", "")),
            "category": str(binding.get("category", "")),
            "configured_source_sha256": str(
                binding.get("configured_source_sha256", "")
            ),
            "repository": str(raw.get("repository", "")),
            "requested_ref": str(raw.get("requested_ref", "")),
            "resolved_revision": str(raw.get("resolved_revision", "")),
            "resolved_ref": str(raw.get("resolved_ref", "")),
            "content_sha256": str(raw.get("content_sha256", "")),
            "archive_sha256": str(raw.get("archive_sha256", "")),
            "root_path": str(raw.get("root_path", "")),
            "files_sha256": digest_payload(raw.get("files", [])),
            "include_graph_sha256": digest_payload(raw.get("include_graph", [])),
        }
        if (
            not identity["binding_id"]
            or not SHA256_RE.fullmatch(identity["configured_source_sha256"])
            or not SHA256_RE.fullmatch(identity["content_sha256"])
        ):
            raise IsolationPlannerError(
                f"selected source provenance identity is incomplete: {source_id}"
            )
        rows.append(identity)
    return rows


def category_repository_bindings(
    repositories: dict[str, set[str]],
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for repository, categories in repositories.items():
        for category in categories:
            result[category].add(repository)
    return result


def validate_category_lkg_binding(
    binding: dict[str, Any],
    *,
    exact_main_sha: str,
    baseline_dist: pathlib.Path,
    baseline_index: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if binding.get("schema") != BINDING_SCHEMA:
        raise IsolationPlannerError("category LKG binding schema is invalid")
    if (
        binding.get("mode") != "shadow-bootstrap-only"
        or binding.get("enforcement_ready") is not False
        or binding.get("binding_policy") != BINDING_POLICY
        or binding.get("lkg_granularity")
        != "published-category-output-bundle"
        or binding.get("per_source_lkg_available") is not False
        or binding.get("single_source_snapshot") is not False
        or binding.get("normalized_source_payloads_included") is not False
        or binding.get("licensing_assertions_added") is not False
    ):
        raise IsolationPlannerError("category LKG binding safety mode is invalid")
    verify_digest(binding, "binding_sha256", "category LKG binding")
    if binding.get("exact_main_sha") != exact_main_sha:
        raise IsolationPlannerError("category LKG binding main SHA is invalid")
    if binding.get("baseline_index_sha256") != digest_payload(baseline_index):
        raise IsolationPlannerError("category LKG binding baseline index is invalid")
    try:
        baseline_manifest = directory_manifest(baseline_dist)
    except CategoryLkgBindingError as exc:
        raise IsolationPlannerError(str(exc)) from exc
    if binding.get("dist_tree_sha256") != digest_payload(baseline_manifest):
        raise IsolationPlannerError("category LKG dist tree digest is invalid")
    baseline_candidate_manifest = read_json(
        baseline_dist / "candidate_manifest.json"
    )
    if binding.get("baseline_candidate_manifest_sha256") != digest_payload(
        baseline_candidate_manifest
    ):
        raise IsolationPlannerError(
            "category LKG candidate manifest binding is invalid"
        )
    baseline_provenance = read_json(
        baseline_dist / "source_provenance.json"
    )
    if binding.get("baseline_source_provenance_sha256") != digest_payload(
        baseline_provenance
    ):
        raise IsolationPlannerError(
            "category LKG source provenance binding is invalid"
        )

    anchor = binding.get("lkg_anchor")
    if not isinstance(anchor, dict):
        raise IsolationPlannerError("category LKG release anchor is absent")
    verify_digest(anchor, "anchor_sha256", "category LKG release anchor")
    repository = str(anchor.get("repository", ""))
    archive_asset = anchor.get("archive_asset")
    checksum_asset = anchor.get("checksum_asset")
    status = anchor.get("published_status")
    attestation = anchor.get("source_attestation")
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or not re.fullmatch(
            r"ruleset-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}",
            str(anchor.get("release_tag", "")),
        )
        or not re.fullmatch(r"[0-9a-f]{40}", str(anchor.get("release_commit_sha", "")))
        or not re.fullmatch(r"[0-9a-f]{40}", str(binding.get("main_dist_tree_oid", "")))
        or anchor.get("release_dist_tree_oid") != binding.get("main_dist_tree_oid")
        or not SHA256_RE.fullmatch(str(anchor.get("anchor_sha256", "")))
        or not isinstance(archive_asset, dict)
        or archive_asset.get("name") != "ruleset-dist.tar.gz"
        or not SHA256_RE.fullmatch(str(archive_asset.get("sha256", "")))
        or not isinstance(checksum_asset, dict)
        or checksum_asset.get("name") != "ruleset-dist.sha256"
        or not SHA256_RE.fullmatch(str(checksum_asset.get("sha256", "")))
        or not isinstance(status, dict)
        or status.get("context") != "ruleset/published"
        or status.get("state") != "success"
        or status.get("github_actions_app_id") != 15368
        or not isinstance(attestation, dict)
        or attestation.get("workflow")
        != f"{repository}/.github/workflows/source-discovery.yml"
        or not re.fullmatch(r"[0-9a-f]{40}", str(attestation.get("source_sha", "")))
        or attestation.get("source_sha")
        != baseline_candidate_manifest.get("source_commit_sha")
        or attestation.get("subject_sha256") != archive_asset.get("sha256")
    ):
        raise IsolationPlannerError("category LKG release tree binding is invalid")

    baseline_lock = read_json(baseline_dist / "sources.lock.json")
    try:
        baseline_lock_sha256, baseline_repositories = source_lock_identity(
            baseline_lock, "category LKG baseline"
        )
    except AutomatedReviewError as exc:
        raise IsolationPlannerError(str(exc)) from exc
    if (
        binding.get("baseline_source_lock_sha256") != baseline_lock_sha256
        or binding.get("baseline_source_lock_repositories")
        != sorted(baseline_repositories)
    ):
        raise IsolationPlannerError("category LKG source lock binding is invalid")
    try:
        validate_source_provenance(
            baseline_provenance,
            baseline_lock_sha256,
            baseline_repositories,
        )
    except CategoryLkgBindingError as exc:
        raise IsolationPlannerError(str(exc)) from exc

    raw_categories = binding.get("categories")
    if not isinstance(raw_categories, list) or any(
        not isinstance(item, dict) for item in raw_categories
    ):
        raise IsolationPlannerError("category LKG snapshots are invalid")
    bound_categories: dict[str, dict[str, Any]] = {}
    for raw in raw_categories:
        category = str(raw.get("category", ""))
        if not category or category in bound_categories:
            raise IsolationPlannerError(
                "category LKG snapshots must be unique and named"
            )
        verify_digest(raw, "snapshot_sha256", f"category LKG snapshot {category}")
        bound_categories[category] = raw
    if (
        binding.get("category_count") != len(bound_categories)
        or sorted(bound_categories) != sorted(
            str(item.get("id", ""))
            for item in baseline_index.get("categories", [])
            if isinstance(item, dict)
        )
    ):
        raise IsolationPlannerError("category LKG snapshot coverage is not exact")
    try:
        recomputed = category_output_identities(baseline_dist, baseline_index)
    except CategoryLkgBindingError as exc:
        raise IsolationPlannerError(str(exc)) from exc
    if bound_categories != recomputed:
        raise IsolationPlannerError(
            "category LKG snapshots do not match the verified baseline dist"
        )
    return bound_categories, anchor


def aggregate_overlay_sha256(
    category: str, raw_category: dict[str, Any], source_root: pathlib.Path
) -> str:
    overlay = str(raw_category.get("manual_overlay_path", "")).strip()
    if not overlay:
        return digest_payload([])
    relative = pathlib.PurePosixPath(overlay)
    if (
        relative.is_absolute()
        or overlay != relative.as_posix()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise IsolationPlannerError(f"aggregate {category} overlay path is unsafe")
    path = source_root.joinpath(*relative.parts)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise IsolationPlannerError(
            f"aggregate {category} overlay is unavailable: {exc}"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


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
    *,
    exact_main_sha: str,
    baseline_dist: pathlib.Path,
    candidate_dist: pathlib.Path,
    lkg_binding: dict[str, Any],
    source_root: pathlib.Path,
) -> dict[str, Any]:
    changed_categories, findings, unscoped = validate_review(
        review, source_config, baseline_index, candidate_index, provenance
    )
    if not re.fullmatch(r"[0-9a-f]{40}", exact_main_sha):
        raise IsolationPlannerError("exact main SHA is invalid")
    categories, components, dependents = category_graph(source_config)
    leaves = {category for category in categories if not components[category]}
    unknown_changed = set(changed_categories) - categories
    if unknown_changed:
        raise IsolationPlannerError(
            "automated review references unknown changed categories: "
            + ", ".join(sorted(unknown_changed))
        )

    lkg_categories, lkg_anchor = validate_category_lkg_binding(
        lkg_binding,
        exact_main_sha=exact_main_sha,
        baseline_dist=baseline_dist,
        baseline_index=baseline_index,
    )
    try:
        candidate_categories = category_output_identities(
            candidate_dist, candidate_index
        )
    except CategoryLkgBindingError as exc:
        raise IsolationPlannerError(str(exc)) from exc
    if set(lkg_categories) != categories or set(candidate_categories) != categories:
        raise IsolationPlannerError(
            "candidate and category LKG output coverage must match source config"
        )

    baseline_lock = read_json(baseline_dist / "sources.lock.json")
    candidate_lock = read_json(candidate_dist / "sources.lock.json")
    try:
        baseline_lock_sha256, baseline_lock_repositories = source_lock_identity(
            baseline_lock, "category LKG baseline"
        )
        candidate_lock_sha256, candidate_lock_repositories = source_lock_identity(
            candidate_lock, "observed candidate"
        )
    except AutomatedReviewError as exc:
        raise IsolationPlannerError(str(exc)) from exc
    if baseline_lock_sha256 != lkg_binding.get("baseline_source_lock_sha256"):
        raise IsolationPlannerError(
            "planner baseline source lock differs from category LKG binding"
        )
    if review.get("baseline_source_lock_sha256") != baseline_lock_sha256:
        raise IsolationPlannerError("review baseline source lock binding is invalid")
    if review.get("current_source_lock_sha256") != candidate_lock_sha256:
        raise IsolationPlannerError("review candidate source lock binding is invalid")

    if provenance.get("source_lock_sha256") != candidate_lock_sha256:
        raise IsolationPlannerError(
            "candidate source provenance lock binding is invalid"
        )
    repository_categories = repository_category_bindings(
        source_config, provenance, candidate_lock_repositories
    )
    category_repositories = category_repository_bindings(repository_categories)
    reason_codes: dict[str, set[str]] = defaultdict(set)
    held: set[str] = set()
    global_hold = bool(unscoped)
    if global_hold:
        for category in categories:
            reason_codes[category].add("unscoped-review-blocker")

    def hold_categories(
        seeds: set[str], reason: str, explicit_repositories: set[str] | None = None
    ) -> None:
        expanded = set(seeds)
        repositories = set(explicit_repositories or set())
        for category in list(seeds):
            repositories.update(category_repositories.get(category, set()))
        for repository in repositories:
            expanded.update(repository_categories.get(repository, set()))
        affected = transitive_dependents(expanded, dependents)
        for category in affected:
            held.add(category)
            reason_codes[category].add(reason)

    for finding in findings:
        category = str(finding.get("category", ""))
        code = str(finding.get("code", "invalid-finding"))
        if finding.get("isolatable") is not True or finding.get("scope") == "global":
            global_hold = True
            for configured_category in categories:
                reason_codes[configured_category].add("non-isolatable-finding")
            continue
        seeds: set[str] = {category} if category else set()
        repositories = {
            str(repository)
            for repository in finding.get("repository_bindings", [])
        }
        if not seeds:
            global_hold = True
            for configured_category in categories:
                reason_codes[configured_category].add(
                    "unbound-isolation-finding"
                )
            continue
        hold_categories(seeds, code, repositories)

    delta_counts: dict[str, int] = {}
    evidence_by_category: dict[str, dict[str, Any]] = {}
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
        evidence_by_category[category] = raw
    if set(delta_counts) != set(changed_categories):
        raise IsolationPlannerError(
            "automated review category evidence is not exact"
        )

    for category, evidence in evidence_by_category.items():
        if any(
            evidence.get(field) is True
            for field in (
                "category_added",
                "category_removed",
                "action_changed",
                "priority_changed",
            )
        ):
            global_hold = True
            for configured_category in categories:
                reason_codes[configured_category].add(
                    "control-plane-change"
                )
        removed_count = evidence.get("removed_count")
        if category in leaves and isinstance(removed_count, int) and removed_count > 0:
            hold_categories({category}, "removal-absence-proof-unavailable")

    for category in categories:
        lkg_identity = lkg_categories[category]
        candidate_identity = candidate_categories[category]
        for field in (
            "recommended_action",
            "recommended_priority",
            "contract_sha256",
        ):
            if lkg_identity.get(field) != candidate_identity.get(field):
                global_hold = True
                reason_codes[category].add("control-plane-identity-drift")

    changed_set = set(changed_categories)
    candidate_equivalent_categories = {
        category
        for category in categories
        if all(
            candidate_categories[category].get(field)
            == lkg_categories[category].get(field)
            for field in CATEGORY_SEMANTIC_FIELDS
        )
    }
    unreported_identity_changes = (
        categories - changed_set - candidate_equivalent_categories
    )
    if unreported_identity_changes:
        raise IsolationPlannerError(
            "candidate category identity changes are absent from review: "
            + ", ".join(sorted(unreported_identity_changes))
        )
    changed_leaf_categories = changed_set & leaves
    semantic_changed_leaf_categories = (
        changed_leaf_categories - candidate_equivalent_categories
    )
    if set(baseline_lock_repositories) != set(candidate_lock_repositories):
        raise IsolationPlannerError(
            "candidate source lock repository coverage differs from published LKG"
        )
    locked_repositories = sorted(
        set(baseline_lock_repositories) | set(candidate_lock_repositories)
    )
    changed_locked_repositories = {
        repository
        for repository in locked_repositories
        if baseline_lock_repositories.get(repository)
        != candidate_lock_repositories.get(repository)
    }
    for repository in locked_repositories:
        bound_leaves = repository_categories.get(repository, set()) & leaves
        if not bound_leaves:
            global_hold = True
            for configured_category in categories:
                reason_codes[configured_category].add(
                    "locked-repository-category-binding-missing"
                )
            continue

    while True:
        held_before = set(held)
        eligible_changed = semantic_changed_leaf_categories - held
        candidate_closure = set(eligible_changed)
        closure_changed = True
        while closure_changed and held == held_before:
            closure_changed = False
            for repository in sorted(changed_locked_repositories):
                bound_leaves = repository_categories.get(repository, set()) & leaves
                if not (bound_leaves & candidate_closure):
                    continue
                eligible_closure = eligible_changed | (
                    candidate_equivalent_categories & leaves
                )
                if bool(bound_leaves & held) or not bound_leaves <= eligible_closure:
                    hold_categories(
                        set(bound_leaves),
                        "shared-repository-atomicity-unproven",
                    )
                    break
                new_categories = bound_leaves - candidate_closure
                if new_categories:
                    candidate_closure.update(new_categories)
                    closure_changed = True
        if held == held_before:
            break

    if global_hold:
        held = set(categories)
    accepted = sorted(semantic_changed_leaf_categories - held)
    accepted_set = set(accepted)
    quarantined_categories = sorted(changed_set & held)

    candidate_repository_closure = set(accepted_set)
    closure_changed = True
    while closure_changed:
        closure_changed = False
        for repository in sorted(changed_locked_repositories):
            bound_leaves = repository_categories.get(repository, set()) & leaves
            if not (bound_leaves & candidate_repository_closure):
                continue
            if bool(bound_leaves & held) or not bound_leaves <= (
                accepted_set | (candidate_equivalent_categories & leaves)
            ):
                raise IsolationPlannerError(
                    f"candidate repository closure is inconsistent: {repository}"
                )
            new_categories = bound_leaves - candidate_repository_closure
            if new_categories:
                candidate_repository_closure.update(new_categories)
                closure_changed = True

    repository_selections: list[dict[str, Any]] = []
    for repository in locked_repositories:
        bound_leaves = repository_categories.get(repository, set()) & leaves
        baseline_entry = baseline_lock_repositories.get(repository)
        candidate_entry = candidate_lock_repositories.get(repository)
        lock_changed = baseline_entry != candidate_entry
        use_candidate = (
            lock_changed
            and bool(bound_leaves & candidate_repository_closure)
            and not bool(bound_leaves & held)
            and bound_leaves <= candidate_repository_closure
        )
        selected_entry = (
            candidate_entry
            if use_candidate
            else baseline_entry
        )
        if not isinstance(selected_entry, dict):
            raise IsolationPlannerError(
                f"selected lock entry is absent for repository {repository}"
            )
        repository_selections.append(
            {
                "repository": repository,
                "selection": (
                    "observed-candidate-lock"
                    if use_candidate
                    else "published-lkg-lock"
                ),
                "bound_leaf_categories": sorted(bound_leaves),
                "selected_entry_sha256": digest_payload(selected_entry),
            }
        )
    raw_category_rows = {
        str(raw.get("id", "")): raw
        for raw in source_config.get("categories", [])
        if isinstance(raw, dict)
    }
    selection_rows: dict[str, dict[str, Any]] = {}

    def category_selection(category: str) -> dict[str, Any]:
        if category in selection_rows:
            return selection_rows[category]
        changed = category in changed_set
        reasons = sorted(reason_codes.get(category, set()))
        if category in leaves:
            use_candidate = category in accepted_set
            use_candidate_equivalent = (
                category in candidate_repository_closure and not use_candidate
            )
            identity = (
                candidate_categories[category]
                if use_candidate or use_candidate_equivalent
                else lkg_categories[category]
            )
            row = {
                "category": category,
                "category_kind": "leaf",
                "selection": (
                    "candidate-category"
                    if use_candidate
                    else (
                        "candidate-equivalent-category"
                        if use_candidate_equivalent
                        else "published-category-lkg"
                    )
                ),
                "changed": changed,
                "quarantined": category in held,
                "reason_codes": reasons,
                "candidate_delta_count": delta_counts.get(category, 0),
                "selected_snapshot_sha256": identity["snapshot_sha256"],
                "selected_normalized_rules_sha256": identity[
                    "normalized_rules_sha256"
                ],
                "selected_rule_count": identity["rule_count"],
                "selected_output_bundle_sha256": identity[
                    "output_bundle_sha256"
                ],
                "recommended_action": identity["recommended_action"],
                "recommended_priority": identity["recommended_priority"],
                "contract_sha256": identity["contract_sha256"],
            }
        else:
            component_rows = [
                category_selection(component)
                for component in sorted(components[category])
            ]
            lkg_identity = lkg_categories[category]
            should_derive = category not in held and (
                changed
                or any(
                    item["selection"]
                    in {
                        "candidate-category",
                        "candidate-equivalent-category",
                        "derived-recompute-required",
                    }
                    for item in component_rows
                )
            )
            if should_derive:
                raw_category = raw_category_rows.get(category)
                if not isinstance(raw_category, dict):
                    raise IsolationPlannerError(
                        f"aggregate {category} configuration is absent"
                    )
                overlay_sha256 = aggregate_overlay_sha256(
                    category, raw_category, source_root
                )
                derivation = {
                    "category": category,
                    "components": [
                        {
                            "category": item["category"],
                            "selected_snapshot_sha256": item[
                                "selected_snapshot_sha256"
                            ],
                        }
                        for item in component_rows
                    ],
                    "manual_overlay_sha256": overlay_sha256,
                    "recommended_action": lkg_identity["recommended_action"],
                    "recommended_priority": lkg_identity[
                        "recommended_priority"
                    ],
                    "contract_sha256": lkg_identity["contract_sha256"],
                }
                row = {
                    "category": category,
                    "category_kind": "aggregate",
                    "selection": "derived-recompute-required",
                    "changed": changed,
                    "quarantined": False,
                    "reason_codes": reasons,
                    "candidate_delta_count": delta_counts.get(category, 0),
                    "aggregate_components": sorted(components[category]),
                    "manual_overlay_sha256": overlay_sha256,
                    "selected_snapshot_sha256": digest_payload(derivation),
                    "selected_normalized_rules_sha256": "",
                    "selected_rule_count": -1,
                    "selected_output_bundle_sha256": "",
                    "recommended_action": lkg_identity["recommended_action"],
                    "recommended_priority": lkg_identity[
                        "recommended_priority"
                    ],
                    "contract_sha256": lkg_identity["contract_sha256"],
                    "composite_materialization_required": True,
                }
            else:
                row = {
                    "category": category,
                    "category_kind": "aggregate",
                    "selection": "published-category-lkg",
                    "changed": changed,
                    "quarantined": category in held,
                    "reason_codes": reasons,
                    "candidate_delta_count": delta_counts.get(category, 0),
                    "aggregate_components": sorted(components[category]),
                    "selected_snapshot_sha256": lkg_identity[
                        "snapshot_sha256"
                    ],
                    "selected_normalized_rules_sha256": lkg_identity[
                        "normalized_rules_sha256"
                    ],
                    "selected_rule_count": lkg_identity["rule_count"],
                    "selected_output_bundle_sha256": lkg_identity[
                        "output_bundle_sha256"
                    ],
                    "recommended_action": lkg_identity["recommended_action"],
                    "recommended_priority": lkg_identity[
                        "recommended_priority"
                    ],
                    "contract_sha256": lkg_identity["contract_sha256"],
                    "composite_materialization_required": False,
                }
        selection_rows[category] = row
        return row

    for category in sorted(categories):
        category_selection(category)
    ordered_selection_rows = [selection_rows[item] for item in sorted(categories)]

    safe_derived_categories = {
        category
        for category in categories - leaves
        if selection_rows[category]["selection"] == "derived-recompute-required"
    }
    planned_categories = accepted_set | safe_derived_categories

    candidate_bound_categories = accepted_set | candidate_repository_closure
    stable_provenance = selected_provenance_rows(
        source_config, provenance, candidate_bound_categories
    )
    stable_category_rows: list[dict[str, Any]] = []
    stable_fields = (
        "category",
        "category_kind",
        "selection",
        "selected_snapshot_sha256",
        "selected_normalized_rules_sha256",
        "selected_rule_count",
        "selected_output_bundle_sha256",
        "recommended_action",
        "recommended_priority",
        "contract_sha256",
        "aggregate_components",
        "manual_overlay_sha256",
        "composite_materialization_required",
    )
    for row in ordered_selection_rows:
        stable_category_rows.append(
            {field: row[field] for field in stable_fields if field in row}
        )

    stable_selection: dict[str, Any] = {
        "schema": SELECTION_SCHEMA,
        "planner_policy": PLANNER_POLICY,
        "exact_main_sha": exact_main_sha,
        "lkg_anchor_sha256": lkg_anchor["anchor_sha256"],
        "source_config_sha256": digest_payload(source_config),
        "selected_repository_lock_sha256": digest_payload(
            repository_selections
        ),
        "repository_selections": repository_selections,
        "selected_source_provenance_sha256": digest_payload(stable_provenance),
        "selected_source_provenance": stable_provenance,
        "category_selections": stable_category_rows,
        "composite_materialization_required": bool(safe_derived_categories),
        "composite_identity_ready": False,
        "two_cycle_enforcement_eligible": False,
    }
    stable_selection_fingerprint = digest_payload(stable_selection)

    isolation = review["isolation_evidence"]
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "mode": "shadow-only",
        "enforcement_ready": False,
        "planner_policy": PLANNER_POLICY,
        "isolation_unit": "source-binding-with-shared-repository-closure",
        "fallback_granularity": "published-category-lkg",
        "per_source_lkg_bootstrap_required": True,
        "category_lkg_bootstrap_bound": True,
        "category_lkg_binding_sha256": lkg_binding["binding_sha256"],
        "category_lkg_anchor_sha256": lkg_anchor["anchor_sha256"],
        "exact_main_sha": exact_main_sha,
        "baseline_index_sha256": digest_payload(baseline_index),
        "candidate_index_sha256": digest_payload(candidate_index),
        "source_config_sha256": digest_payload(source_config),
        "source_provenance_sha256": digest_payload(provenance),
        "baseline_source_lock_sha256": baseline_lock_sha256,
        "observed_candidate_source_lock_sha256": candidate_lock_sha256,
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
        "held_categories": sorted(held),
        "safe_slice_changed": bool(accepted),
        "planned_safe_delta_count": sum(
            delta_counts.get(category, 0) for category in planned_categories
        ),
        "publishable_safe_delta_count": 0,
        "composite_validation_required": True,
        "composite_identity_ready": False,
        "quarantine_active": bool(quarantined_categories),
        "global_hold": global_hold,
        "unscoped_blockers": unscoped,
        "category_decisions": ordered_selection_rows,
        "stable_selection": stable_selection,
        "stable_selection_fingerprint": stable_selection_fingerprint,
        "stable_selection_fingerprint_kind": "shadow-selection-not-composite",
        "two_cycle_enforcement_eligible": False,
        "plan_fingerprint_kind": "exact-observation",
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
    parser.add_argument("--published-lkg-binding", type=pathlib.Path, required=True)
    parser.add_argument("--exact-main-sha", required=True)
    parser.add_argument("--source-root", type=pathlib.Path, default=pathlib.Path("ruleset"))
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
        lkg_binding = read_json(args.published_lkg_binding)
        plan = build_plan(
            review,
            source_config,
            baseline_index,
            candidate_index,
            provenance,
            exact_main_sha=args.exact_main_sha,
            baseline_dist=args.baseline_dist,
            candidate_dist=args.candidate_dist,
            lkg_binding=lkg_binding,
            source_root=args.source_root.resolve(),
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
