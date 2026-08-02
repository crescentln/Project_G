#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import sys
import urllib.parse
from collections import Counter
from typing import Any

try:
    from ruleset.scripts.public_suffix_policy import (
        PublicSuffixPolicyError,
        domain_topology_markers as psl_domain_topology_markers,
        load_public_suffix_database,
    )
except ModuleNotFoundError:
    from public_suffix_policy import (  # type: ignore[no-redef]
        PublicSuffixPolicyError,
        domain_topology_markers as psl_domain_topology_markers,
        load_public_suffix_database,
    )


REPORT_SCHEMA = "project-g-automated-review-v2"
REVIEW_POLICY = "unattended-evidence-gated-v2"
ISOLATION_EVIDENCE_SCHEMA = "project-g-isolation-evidence-v1"
ISOLATION_ARTIFACT_SCHEMA = "project-g-isolation-evidence-artifact-v1"
REQUIRED_STABLE_CYCLES = 2
MINIMUM_CYCLE_SEPARATION_SECONDS = 300
AUTOMATABLE_POLICIES = {"low-risk", "review"}
AUTOMATABLE_ELEVATED_MARKERS = {
    "category-policy-review",
    "direct-addition",
    "new-apex",
    "reject-addition",
    "single-community-tier",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RULE_LEAF_DOMAIN = b"project-g-rule-v1\0"
RULE_NODE_DOMAIN = b"project-g-rule-node-v1\0"


class AutomatedReviewError(RuntimeError):
    pass


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AutomatedReviewError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise AutomatedReviewError(f"JSON root must be an object: {path}")
    return payload


def canonical_bytes(payload: Any) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def digest_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def isolation_finding(
    *,
    code: str,
    scope: str,
    isolatable: bool,
    message: str,
    category: str = "",
    rule: str = "",
    source_ids: list[str] | None = None,
    repository_bindings: list[str] | None = None,
    dependency_closure: list[str] | None = None,
    blocker_sha256: str = "",
) -> dict[str, Any]:
    payload = {
        "code": code,
        "scope": scope,
        "isolatable": isolatable,
        "category": category,
        "rule": rule,
        "source_ids": sorted(set(source_ids or [])),
        "repository_bindings": sorted(set(repository_bindings or [])),
        "dependency_closure": sorted(set(dependency_closure or [])),
        "blocker_sha256": blocker_sha256,
        "message": message,
    }
    payload["evidence_digest"] = digest_payload(payload)
    return payload


def separate_isolation_artifact(
    report: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    automated_review = dict(report)
    isolation_evidence = automated_review.pop("isolation_evidence", None)
    if not isinstance(isolation_evidence, dict):
        raise AutomatedReviewError("automated review lacks isolation evidence")
    artifact = {
        "schema": ISOLATION_ARTIFACT_SCHEMA,
        "mode": "shadow-only",
        "automated_review_sha256": digest_payload(automated_review),
        "baseline_index_sha256": str(
            automated_review.get("baseline_index_sha256", "")
        ),
        "candidate_index_sha256": str(
            automated_review.get("current_index_sha256", "")
        ),
        "source_config_sha256": str(
            automated_review.get("source_config_sha256", "")
        ),
        "isolation_evidence": isolation_evidence,
    }
    artifact["artifact_sha256"] = digest_payload(artifact)
    return automated_review, artifact


def source_lock_identity(payload: dict[str, Any], label: str) -> tuple[str, dict[str, Any]]:
    version = payload.get("version", 1)
    repositories = payload.get("repositories")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise AutomatedReviewError(f"{label} source lock version must be 1")
    if not isinstance(repositories, dict):
        raise AutomatedReviewError(f"{label} source lock repositories must be an object")
    for repository, raw in repositories.items():
        if not REPOSITORY_RE.fullmatch(str(repository)) or not isinstance(raw, dict):
            raise AutomatedReviewError(f"{label} source lock repository is invalid")
        for field in ("resolved_revision", "tree_revision"):
            if not GIT_SHA_RE.fullmatch(str(raw.get(field, ""))):
                raise AutomatedReviewError(
                    f"{label} source lock {repository} {field} is invalid"
                )
        if not str(raw.get("requested_ref", "")).strip():
            raise AutomatedReviewError(
                f"{label} source lock {repository} requested_ref is absent"
            )
    identity = {"version": version, "repositories": repositories}
    digest = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return digest, repositories


def read_openclash_rule_file(path: pathlib.Path) -> set[str]:
    if not path.is_file():
        return set()
    rules: set[str] = set()
    observed = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line in {"payload:", "payload: []"} or line.startswith("#"):
            continue
        if not line.startswith("- "):
            raise AutomatedReviewError(f"unexpected OpenClash rule syntax: {path}: {line}")
        value = line[2:].strip()
        if value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1].replace("''", "'")
        observed += 1
        rules.add(value)
    if observed != len(rules):
        raise AutomatedReviewError(f"duplicate OpenClash rules: {path}")
    return rules


def index_categories(payload: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    rows = payload.get("categories")
    if not isinstance(rows, list):
        raise AutomatedReviewError(f"{label} index categories must be an array")
    result: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            raise AutomatedReviewError(f"{label} index category rows must be objects")
        category = str(raw.get("id", ""))
        if not category or category in result:
            raise AutomatedReviewError(f"{label} index categories must be unique and named")
        result[category] = raw
    return result


def informational_conflicts_by_category(payload: dict[str, Any]) -> dict[str, int]:
    rows = payload.get("conflicts")
    if not isinstance(rows, list):
        raise AutomatedReviewError("conflicts must contain an array")
    counts: Counter[str] = Counter()
    for item in rows:
        if not isinstance(item, dict):
            raise AutomatedReviewError("conflict rows must be objects")
        if (
            bool(item.get("gated", True))
            or bool(item.get("waived", False))
            or str(item.get("type", "")) == "same_action_overlap"
        ):
            continue
        categories = item.get("categories")
        if not isinstance(categories, list):
            raise AutomatedReviewError("conflict categories must be an array")
        for raw_category in categories:
            category = str(raw_category).strip()
            if category:
                counts[category] += 1
    return dict(counts)


def recompute_dist_evidence(
    baseline_dist: pathlib.Path,
    current_dist: pathlib.Path,
) -> dict[str, Any]:
    baseline_index = read_json(baseline_dist / "index.json")
    current_index = read_json(current_dist / "index.json")
    baseline_rows = index_categories(baseline_index, "baseline")
    current_rows = index_categories(current_index, "current")
    category_evidence: dict[str, dict[str, Any]] = {}
    baseline_rule_sets: dict[str, set[str]] = {}
    current_rule_sets: dict[str, set[str]] = {}
    baseline_actions: dict[str, str] = {}
    current_actions: dict[str, str] = {}
    baseline_priorities: dict[str, int] = {}
    current_priorities: dict[str, int] = {}

    for category, row in baseline_rows.items():
        rules = read_openclash_rule_file(
            baseline_dist / "openclash" / f"{category}.yaml"
        )
        if strict_int(row.get("rule_count"), f"baseline {category} rule_count", []) != len(rules):
            raise AutomatedReviewError(f"baseline rule count differs for {category}")
        baseline_rule_sets[category] = rules
        baseline_actions[category] = str(row.get("recommended_action", "UNSPECIFIED"))
        priority = row.get("recommended_priority")
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise AutomatedReviewError(f"baseline priority is invalid for {category}")
        baseline_priorities[category] = priority
    for category, row in current_rows.items():
        rules = read_openclash_rule_file(
            current_dist / "openclash" / f"{category}.yaml"
        )
        if strict_int(row.get("rule_count"), f"current {category} rule_count", []) != len(rules):
            raise AutomatedReviewError(f"current rule count differs for {category}")
        current_rule_sets[category] = rules
        current_actions[category] = str(row.get("recommended_action", "UNSPECIFIED"))
        priority = row.get("recommended_priority")
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise AutomatedReviewError(f"current priority is invalid for {category}")
        current_priorities[category] = priority

    def effective_action(
        rule: str,
        rule_sets: dict[str, set[str]],
        actions: dict[str, str],
        priorities: dict[str, int],
    ) -> str:
        matches = [category for category, rules in rule_sets.items() if rule in rules]
        if not matches:
            return "ABSENT"
        selected = min(matches, key=lambda item: (priorities.get(item, 9999), item))
        return actions.get(selected, "UNSPECIFIED")

    for category in sorted(set(baseline_rows) | set(current_rows)):
        before = baseline_rule_sets.get(category, set())
        after = current_rule_sets.get(category, set())
        additions = sorted(after - before)
        removals = sorted(before - after)
        category_added = category in current_rows and category not in baseline_rows
        category_removed = category in baseline_rows and category not in current_rows
        previous_action = baseline_actions.get(category, "ABSENT")
        action = current_actions.get(category, "REMOVED")
        previous_priority = baseline_priorities.get(category)
        priority = current_priorities.get(category)
        action_changed = (
            category in baseline_rows
            and category in current_rows
            and previous_action != action
        )
        priority_changed = (
            category in baseline_rows
            and category in current_rows
            and previous_priority != priority
        )
        if not (
            additions
            or removals
            or category_added
            or category_removed
            or action_changed
            or priority_changed
        ):
            continue
        category_evidence[category] = {
            "category_added": category_added,
            "category_removed": category_removed,
            "previous_action": previous_action,
            "action": action,
            "previous_priority": previous_priority,
            "priority": priority,
            "action_changed": action_changed,
            "priority_changed": priority_changed,
            "before_count": len(before),
            "after_count": len(after),
            "added": additions,
            "removed": removals,
            "added_effective_actions": {
                rule: {
                    "old": effective_action(
                        rule,
                        baseline_rule_sets,
                        baseline_actions,
                        baseline_priorities,
                    ),
                    "new": effective_action(
                        rule,
                        current_rule_sets,
                        current_actions,
                        current_priorities,
                    ),
                }
                for rule in additions
            },
            "removed_effective_actions": {
                rule: {
                    "old": effective_action(
                        rule,
                        baseline_rule_sets,
                        baseline_actions,
                        baseline_priorities,
                    ),
                    "new": effective_action(
                        rule,
                        current_rule_sets,
                        current_actions,
                        current_priorities,
                    ),
                }
                for rule in removals
            },
            "current_contract": current_rows.get(category, {}).get("contract"),
        }

    baseline_conflicts = read_json(baseline_dist / "conflicts.json")
    current_conflicts = read_json(current_dist / "conflicts.json")
    baseline_info = informational_conflicts_by_category(baseline_conflicts)
    current_info = informational_conflicts_by_category(current_conflicts)
    info_delta = {
        category: current_info.get(category, 0) - baseline_info.get(category, 0)
        for category in sorted(set(baseline_info) | set(current_info))
    }
    conflict_delta = {
        "cross_action": int(current_conflicts.get("cross_action_conflict_count", 0))
        - int(baseline_conflicts.get("cross_action_conflict_count", 0)),
        "informational_cross_action": int(
            current_conflicts.get("informational_cross_action_conflict_count", 0)
        )
        - int(baseline_conflicts.get("informational_cross_action_conflict_count", 0)),
        "high_severity": int(current_conflicts.get("high_severity_conflict_count", 0))
        - int(baseline_conflicts.get("high_severity_conflict_count", 0)),
        "informational_by_category": info_delta,
    }
    baseline_lock = read_json(baseline_dist / "sources.lock.json")
    current_lock = read_json(current_dist / "sources.lock.json")
    baseline_lock_digest, _baseline_repositories = source_lock_identity(
        baseline_lock, "baseline"
    )
    current_lock_digest, current_repositories = source_lock_identity(
        current_lock, "current"
    )
    current_provenance = read_json(current_dist / "source_provenance.json")
    current_health = read_json(current_dist / "source_health.json")
    if current_provenance.get("source_lock_sha256") != current_lock_digest:
        raise AutomatedReviewError(
            "current source provenance is not bound to sources.lock.json"
        )
    if current_health.get("source_lock_sha256") != current_lock_digest:
        raise AutomatedReviewError(
            "current source health is not bound to sources.lock.json"
        )
    if current_health.get("resolved_repositories") != current_repositories:
        raise AutomatedReviewError(
            "current source health repositories differ from sources.lock.json"
        )
    return {
        "baseline_index_sha256": digest_payload(baseline_index),
        "current_index_sha256": digest_payload(current_index),
        "changed_categories": sorted(category_evidence),
        "categories": category_evidence,
        "conflict_delta": conflict_delta,
        "baseline_source_lock_sha256": baseline_lock_digest,
        "current_source_lock_sha256": current_lock_digest,
        "source_lock_changed": baseline_lock_digest != current_lock_digest,
        "source_lock_repositories": current_repositories,
        "current_provenance_sha256": digest_payload(current_provenance),
    }


def collect_source_urls(source: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("url",):
        value = str(source.get(key, "")).strip()
        if value:
            values.append(value)
    for key in ("urls", "fallback_urls"):
        raw = source.get(key, [])
        if raw is None:
            continue
        if not isinstance(raw, list):
            raise AutomatedReviewError(f"source {key} must be an array")
        values.extend(str(item).strip() for item in raw if str(item).strip())
    return list(dict.fromkeys(values))


def configured_source_id(category: str, index: int, source: dict[str, Any]) -> str:
    explicit = str(source.get("source_id", "")).strip()
    if explicit:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{2,127}", explicit):
            raise AutomatedReviewError(f"configured source ID is invalid: {explicit}")
        return explicit
    identity = {
        "type": source.get("type"),
        "url": source.get("url"),
        "urls": source.get("urls"),
        "fallback_urls": source.get("fallback_urls"),
        "path": source.get("path"),
        "include_attrs": source.get("include_attrs"),
        "exclude_attrs": source.get("exclude_attrs"),
        "exclude_includes": source.get("exclude_includes"),
    }
    digest = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:12]
    return f"{category}:{index:02d}:{str(source.get('type', 'unknown'))}:{digest}"


def configured_binding_id(category: str, source: dict[str, Any]) -> str:
    """Return an order-independent identity for an exact configured source."""
    source_type = str(source.get("type", "unknown")).strip() or "unknown"
    return f"{category}:{source_type}:{digest_payload(source)}"


def canonical_source_bindings(source_config: dict[str, Any]) -> dict[str, Any]:
    categories = source_config.get("categories")
    if not isinstance(categories, list):
        raise AutomatedReviewError("source config categories must be an array")
    rows: dict[str, dict[str, Any]] = {}
    bindings: dict[str, dict[str, Any]] = {}
    direct_sources: dict[str, set[str]] = {}
    for raw in categories:
        if not isinstance(raw, dict):
            raise AutomatedReviewError("source config category rows must be objects")
        category = str(raw.get("id", ""))
        if not category or category in rows:
            raise AutomatedReviewError("source config categories must be unique and named")
        rows[category] = raw
        sources = raw.get("sources", [])
        if not isinstance(sources, list):
            raise AutomatedReviewError(f"category {category} sources must be an array")
        allowed: set[str] = set()
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                raise AutomatedReviewError(f"category {category} source is invalid")
            source_id = configured_source_id(category, index, source)
            binding = {
                "source_id": source_id,
                "binding_id": configured_binding_id(category, source),
                "category": category,
                "type": str(source.get("type", "")),
                "authority": str(source.get("authority", "unspecified")),
                "configured_source_sha256": digest_payload(source),
                "requested_refs": (
                    [str(source.get("path", ""))]
                    if str(source.get("type", "")) == "local_domain"
                    else collect_source_urls(source)
                ),
                "local_path": (
                    str(source.get("path", ""))
                    if str(source.get("type", "")) == "local_domain"
                    else ""
                ),
            }
            if source_id in bindings and bindings[source_id] != binding:
                raise AutomatedReviewError(f"source ID is configured inconsistently: {source_id}")
            bindings[source_id] = binding
            allowed.add(source_id)
        direct_sources[category] = allowed

    resolved: dict[str, set[str]] = {}
    resolving: set[str] = set()

    def allowed_for(category: str) -> set[str]:
        if category in resolved:
            return set(resolved[category])
        if category in resolving or category not in rows:
            raise AutomatedReviewError(f"source config aggregate graph is invalid: {category}")
        resolving.add(category)
        row = rows[category]
        allowed = set(direct_sources[category])
        aggregate = row.get("aggregate_of", [])
        if aggregate:
            if not isinstance(aggregate, list):
                raise AutomatedReviewError(f"category {category} aggregate_of must be an array")
            for component in aggregate:
                allowed.update(allowed_for(str(component)))
            overlay = str(row.get("manual_overlay_path", "")).strip()
            if overlay:
                source = {
                    "type": "local_domain",
                    "path": overlay,
                    "authority": "owner-controlled",
                }
                source_id = f"{category}:manual-overlay"
                bindings[source_id] = {
                    "source_id": source_id,
                    "binding_id": configured_binding_id(category, source),
                    "category": category,
                    "type": "local_domain",
                    "authority": "owner-controlled",
                    "configured_source_sha256": digest_payload(source),
                    "requested_refs": [overlay],
                    "local_path": overlay,
                }
                allowed.add(source_id)
        resolving.remove(category)
        resolved[category] = allowed
        return set(allowed)

    for category in rows:
        allowed_for(category)
    return {
        "config_sha256": digest_payload(source_config),
        "bindings": bindings,
        "allowed_by_category": {
            category: sorted(source_ids)
            for category, source_ids in sorted(resolved.items())
        },
    }


def protected_domain_roots(
    payload: dict[str, Any], repository_root: pathlib.Path
) -> dict[str, Any]:
    if payload.get("schema") != "project-g-protected-domain-roots-v1":
        raise AutomatedReviewError("protected domain root schema is invalid")
    roots: dict[str, Any] = {}
    for field in ("public_suffixes", "multi_tenant_roots"):
        raw = payload.get(field)
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise AutomatedReviewError(f"protected domain roots {field} must be an array")
        normalized = [item.lower().strip(".") for item in raw]
        if (
            normalized != sorted(normalized)
            or len(normalized) != len(set(normalized))
            or any(
                not re.fullmatch(
                    r"(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,62}",
                    item,
                )
                for item in normalized
            )
        ):
            raise AutomatedReviewError(f"protected domain roots {field} is invalid")
        roots[field] = set(normalized)
    if roots["public_suffixes"] & roots["multi_tenant_roots"]:
        raise AutomatedReviewError("protected domain root classes must not overlap")
    try:
        roots["public_suffix_database"] = load_public_suffix_database(
            payload.get("public_suffix_list"), repository_root
        )
    except PublicSuffixPolicyError as exc:
        raise AutomatedReviewError(str(exc)) from exc
    return roots


def domain_topology_risk_markers(
    value: str,
    protected_roots: dict[str, Any],
) -> set[str]:
    try:
        return psl_domain_topology_markers(
            value,
            protected_roots["public_suffix_database"],
            protected_roots["public_suffixes"],
            protected_roots["multi_tenant_roots"],
        )
    except PublicSuffixPolicyError:
        return {"invalid-domain"}


def string_list(value: Any, field: str, blockers: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        blockers.append(f"{field} must be an array of strings")
        return []
    normalized = sorted(set(value))
    if len(normalized) != len(value):
        blockers.append(f"{field} must contain unique values")
    return normalized


def strict_int(value: Any, field: str, blockers: list[str]) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        blockers.append(f"{field} must be an integer")
        return -1
    return value


def action_family(action: str) -> str:
    normalized = str(action).upper().strip()
    if normalized in {"REJECT", "REJECT-DROP", "REJECT-NO-DROP"}:
        return "REJECT"
    if normalized in {"DIRECT", "PROXY"}:
        return normalized
    return "UNSPECIFIED"


def rule_type(rule: str) -> str:
    return rule.partition(",")[0].strip().upper()


def rule_risk_markers(
    rule: str,
    action: str,
    *,
    added: bool,
    protected_roots: dict[str, set[str]],
) -> list[str]:
    markers: set[str] = set()
    raw_type, separator, raw_value = rule.partition(",")
    normalized_type = raw_type.upper().strip()
    value = raw_value.split(",", 1)[0].strip()
    if not separator or not normalized_type or not value:
        return ["invalid-rule"]
    family = action_family(action)
    if added and family in {"DIRECT", "REJECT"}:
        markers.add(f"{family.lower()}-addition")
    if normalized_type in {"DOMAIN-REGEX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}:
        markers.add(f"new-{normalized_type.lower()}")
    if normalized_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        markers.update(domain_topology_risk_markers(value, protected_roots))
    if normalized_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            markers.add("invalid-cidr")
        else:
            if (network.version == 4 and network.prefixlen <= 16) or (
                network.version == 6 and network.prefixlen <= 48
            ):
                markers.add("new-wide-cidr")
    return sorted(markers)


def budget_dimensions(
    added_rules: list[str],
    protected_roots: dict[str, set[str]],
) -> dict[str, int]:
    return {
        "new_apex": sum(
            1
            for rule in added_rules
            if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,"))
            and "new-apex"
            in domain_topology_risk_markers(
                rule.split(",", 1)[1], protected_roots
            )
        ),
        "new_regex": sum(
            1 for rule in added_rules if rule.startswith("DOMAIN-REGEX,")
        ),
        "new_cidr": sum(
            1
            for rule in added_rules
            if rule.startswith(("IP-CIDR,", "IP-CIDR6,"))
        ),
    }


def stable_rule_evidence(rows: list[dict[str, Any]], *, removed: bool) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "rule": str(row.get("rule", "")),
            "sources": sorted(str(value) for value in row.get("sources", [])),
            "old_effective_action": str(row.get("old_effective_action", "")),
            "new_effective_action": str(row.get("new_effective_action", "")),
            "risk": sorted(str(value) for value in row.get("risk", [])),
        }
        if not removed:
            item["source_tiers"] = sorted(
                str(value) for value in row.get("source_tiers", [])
            )
            item["source_membership"] = sorted(
                row.get("source_membership", []),
                key=lambda value: str(value.get("source_id", ""))
                if isinstance(value, dict)
                else "",
            )
        evidence.append(item)
    return sorted(evidence, key=lambda item: (item["rule"], canonical_bytes(item)))


def expected_contract(
    category: str,
    action: str,
    canonical: dict[str, Any],
    source_config: dict[str, Any],
) -> dict[str, Any]:
    defaults = canonical.get("defaults")
    action_profiles = canonical.get("action_profiles")
    overrides = canonical.get("categories")
    if not all(isinstance(value, dict) for value in (defaults, action_profiles, overrides)):
        raise AutomatedReviewError("canonical category contracts are malformed")
    contract = dict(defaults)
    profile = action_profiles.get(action_family(action), {})
    override = overrides.get(category, {})
    if not isinstance(profile, dict) or not isinstance(override, dict):
        raise AutomatedReviewError(f"canonical contract is malformed for {category}")
    contract.update(profile)
    contract.update(override)

    categories = source_config.get("categories")
    if not isinstance(categories, list):
        raise AutomatedReviewError("source config categories must be an array")
    source_row = next(
        (
            item
            for item in categories
            if isinstance(item, dict) and str(item.get("id", "")) == category
        ),
        None,
    )
    if not isinstance(source_row, dict):
        raise AutomatedReviewError(f"category {category} is absent from source config")
    aggregate = source_row.get("aggregate_of")
    if aggregate:
        normalized = [str(item).strip() for item in aggregate if str(item).strip()]
        configured = contract.get("aggregate_of")
        if configured is not None and configured != normalized:
            raise AutomatedReviewError(
                f"canonical aggregate contract is inconsistent for {category}"
            )
        contract["aggregate_of"] = normalized
    contract["category"] = category
    contract["action"] = action
    return contract


def validate_membership(
    rule: str,
    witness: dict[str, Any],
    source: dict[str, Any],
    blockers: list[str],
) -> None:
    source_id = str(source.get("source_id", ""))
    leaf_count = strict_int(
        witness.get("leaf_count"), f"source membership leaf_count for {source_id}", blockers
    )
    leaf_index = strict_int(
        witness.get("leaf_index"), f"source membership leaf_index for {source_id}", blockers
    )
    expected_count = strict_int(
        source.get("accepted_rules_merkle_leaf_count"),
        f"accepted rule count for {source_id}",
        blockers,
    )
    root = str(source.get("accepted_rules_merkle_root", ""))
    if leaf_count <= 0 or leaf_count != expected_count:
        blockers.append(f"source membership count mismatch for {source_id}: {rule}")
        return
    if leaf_index < 0 or leaf_index >= leaf_count or not SHA256_RE.fullmatch(root):
        blockers.append(f"source membership index or root is invalid for {source_id}: {rule}")
        return
    proof = witness.get("proof")
    if not isinstance(proof, list):
        blockers.append(f"source membership proof is absent for {source_id}: {rule}")
        return

    current = hashlib.sha256(RULE_LEAF_DOMAIN + rule.encode("utf-8")).digest()
    cursor = leaf_index
    width = leaf_count
    for raw in proof:
        if not isinstance(raw, dict):
            blockers.append(f"source membership proof is malformed for {source_id}: {rule}")
            return
        side = str(raw.get("side", ""))
        sibling_hex = str(raw.get("sha256", ""))
        if side not in {"left", "right"} or not SHA256_RE.fullmatch(sibling_hex):
            blockers.append(f"source membership proof is malformed for {source_id}: {rule}")
            return
        expected_side = "left" if cursor % 2 else "right"
        if side != expected_side:
            blockers.append(f"source membership path is inconsistent for {source_id}: {rule}")
            return
        sibling = bytes.fromhex(sibling_hex)
        if cursor % 2:
            current = hashlib.sha256(RULE_NODE_DOMAIN + sibling + current).digest()
        else:
            if cursor + 1 >= width and sibling != current:
                blockers.append(
                    f"source membership duplicate leaf is inconsistent for {source_id}: {rule}"
                )
                return
            current = hashlib.sha256(RULE_NODE_DOMAIN + current + sibling).digest()
        cursor //= 2
        width = (width + 1) // 2
    if width != 1 or current.hex() != root:
        blockers.append(f"source membership proof does not reach root for {source_id}: {rule}")


def validate_source(
    source_id: str,
    source: dict[str, Any],
    binding: dict[str, Any] | None,
    profiles: dict[str, Any],
    repository_root: pathlib.Path,
    blockers: list[str],
) -> dict[str, Any]:
    if not isinstance(binding, dict):
        blockers.append(f"source {source_id} is absent from canonical source config")
        binding = {}
    for field in ("type", "authority", "configured_source_sha256", "requested_refs"):
        if source.get(field) != binding.get(field):
            blockers.append(f"source {source_id} {field} does not match canonical source config")
    local_path = str(binding.get("local_path", ""))
    if local_path:
        configured_path = (repository_root / local_path).resolve()
        try:
            configured_path.relative_to(repository_root.resolve())
        except ValueError:
            blockers.append(f"source {source_id} local path escapes the repository")
        else:
            try:
                local_sha256 = hashlib.sha256(configured_path.read_bytes()).hexdigest()
            except OSError:
                blockers.append(f"source {source_id} canonical local file cannot be read")
            else:
                if str(source.get("content_sha256", "")) != local_sha256:
                    blockers.append(f"source {source_id} local content digest drifted")

    authority = str(source.get("authority", ""))
    profile = profiles.get(authority)
    if not isinstance(profile, dict):
        blockers.append(f"source {source_id} uses unregistered authority {authority}")
        return {"source_id": source_id, "authority": authority}
    for field in (
        "trust_tier",
        "license",
        "owner",
        "revision_strategy",
        "critical",
        "no_cache_publish",
    ):
        if source.get(field) != profile.get(field):
            blockers.append(f"source {source_id} {field} does not match authority profile")
    if source.get("used_cache") is not False:
        blockers.append(f"source {source_id} used cache")
    content_sha256 = str(source.get("content_sha256", ""))
    if not SHA256_RE.fullmatch(content_sha256):
        blockers.append(f"source {source_id} has an invalid content digest")
    parser_stats = source.get("parser_stats")
    if not isinstance(parser_stats, dict):
        blockers.append(f"source {source_id} lacks parser statistics")
        parser_stats = {}
    accepted_count = strict_int(
        parser_stats.get("accepted_rule_count"),
        f"source {source_id} accepted_rule_count",
        blockers,
    )
    if accepted_count != source.get("accepted_rules_merkle_leaf_count"):
        blockers.append(f"source {source_id} Merkle count does not match parser evidence")

    limits = source.get("limits")
    if not isinstance(limits, dict):
        blockers.append(f"source {source_id} lacks source limits")
        limits = {}
    allowed_hosts = sorted(str(value) for value in profile.get("allowed_hosts", []))
    if sorted(str(value) for value in limits.get("allowed_hosts", [])) != allowed_hosts:
        blockers.append(f"source {source_id} allowed hosts do not match authority profile")

    strategy = str(profile.get("revision_strategy", ""))
    resolved_ref = str(source.get("resolved_ref", ""))
    repository = str(source.get("repository", ""))
    resolved_revision = str(source.get("resolved_revision", ""))
    if strategy == "github-commit-lock":
        if not GIT_SHA_RE.fullmatch(resolved_revision) or not REPOSITORY_RE.fullmatch(repository):
            blockers.append(f"source {source_id} lacks an immutable repository revision")
        expected_prefix = f"https://github.com/{repository}/blob/{resolved_revision}/"
        if not resolved_ref.startswith(expected_prefix):
            blockers.append(f"source {source_id} resolved ref is not bound to its repository revision")
        if profile.get("owner") != repository:
            blockers.append(f"source {source_id} repository does not match authority owner")
    elif strategy == "https-validators-and-content-sha256":
        parsed = urllib.parse.urlparse(resolved_ref)
        if parsed.scheme != "https" or parsed.hostname not in set(allowed_hosts):
            blockers.append(f"source {source_id} resolved HTTPS host is not allowlisted")
        if source.get("cache_mode") != "network":
            blockers.append(f"source {source_id} was not fetched from the network")
    elif strategy == "local-content-sha256":
        if source.get("cache_mode") not in {"local", "network"} or not resolved_ref:
            blockers.append(f"source {source_id} has an invalid local content binding")
    else:
        blockers.append(f"source {source_id} uses unsupported revision strategy {strategy}")

    return {
        "source_id": source_id,
        "configured_source_sha256": str(
            source.get("configured_source_sha256", "")
        ),
        "authority": authority,
        "trust_tier": str(source.get("trust_tier", "")),
        "owner": str(source.get("owner", "")),
        "repository": repository,
        "resolved_host": urllib.parse.urlparse(resolved_ref).hostname or "",
        "revision_strategy": strategy,
        "resolved_ref": resolved_ref,
        "resolved_revision": resolved_revision,
        "content_sha256": content_sha256,
        "accepted_rules_merkle_root": str(
            source.get("accepted_rules_merkle_root", "")
        ),
        "accepted_rules_merkle_leaf_count": source.get(
            "accepted_rules_merkle_leaf_count"
        ),
        "cache_mode": str(source.get("cache_mode", "")),
    }


def radar_evidence(
    radar: dict[str, Any], snapshot: dict[str, Any], blockers: list[str]
) -> list[dict[str, Any]]:
    if snapshot.get("candidate_only") is not True:
        blockers.append("source radar snapshot is not candidate-only")
    rows = snapshot.get("repositories")
    if not isinstance(rows, list) or not rows:
        raise AutomatedReviewError("source radar repositories must be a non-empty array")
    evidence: list[dict[str, Any]] = []
    seen: set[str] = set()
    independent_changes: list[str] = []
    advanced_active: list[str] = []
    for raw in rows:
        if not isinstance(raw, dict):
            raise AutomatedReviewError("source radar rows must be objects")
        repository = str(raw.get("repository", ""))
        if not REPOSITORY_RE.fullmatch(repository) or repository in seen:
            raise AutomatedReviewError("source radar repositories must be unique and valid")
        seen.add(repository)
        role = str(raw.get("role", ""))
        revision = str(raw.get("resolved_revision", ""))
        tree_revision = str(raw.get("head_tree_revision", ""))
        locked_revision = str(raw.get("locked_revision", ""))
        previous_revision = str(raw.get("previous_revision", ""))
        if not GIT_SHA_RE.fullmatch(revision) or not GIT_SHA_RE.fullmatch(tree_revision):
            blockers.append(f"source radar revision is invalid for {repository}")
        for field, value in (
            ("locked_revision", locked_revision),
            ("previous_revision", previous_revision),
        ):
            if value and not GIT_SHA_RE.fullmatch(value):
                blockers.append(f"source radar {field} is invalid for {repository}")
        changed = bool(previous_revision and previous_revision != revision)
        if raw.get("changed") is not changed:
            blockers.append(f"source radar changed state is inconsistent for {repository}")
        if role == "active-locked-source":
            if not locked_revision or raw.get("candidate_only") is not False:
                blockers.append(f"active source radar binding is invalid for {repository}")
            if revision != locked_revision:
                advanced_active.append(repository)
        else:
            if raw.get("candidate_only") is not True:
                blockers.append(f"independent radar source is not candidate-only: {repository}")
            if changed:
                independent_changes.append(repository)
        evidence.append(
            {
                "repository": repository,
                "role": role,
                "trust_tier": str(raw.get("trust_tier", "")),
                "candidate_only": raw.get("candidate_only"),
                "resolved_revision": revision,
                "head_tree_revision": tree_revision,
                "locked_revision": locked_revision,
                "previous_revision": previous_revision,
                "comparison_basis": str(raw.get("comparison_basis", "")),
                "changed": changed,
            }
        )
    expected_independent = sorted(independent_changes)
    expected_advanced = sorted(advanced_active)
    if string_list(
        radar.get("independent_changed_repositories"),
        "source_radar.independent_changed_repositories",
        blockers,
    ) != expected_independent:
        blockers.append("source radar independent change list is inconsistent")
    if string_list(
        radar.get("advanced_active_repositories"),
        "source_radar.advanced_active_repositories",
        blockers,
    ) != expected_advanced:
        blockers.append("source radar active-source list is inconsistent")
    unbuilt = snapshot.get("v2fly_tree", {}).get("unbuilt_head_files", [])
    if not isinstance(unbuilt, list) or any(not isinstance(item, str) for item in unbuilt):
        blockers.append("source radar unbuilt file evidence is invalid")
        unbuilt = []
    if string_list(
        radar.get("unbuilt_head_files"), "source_radar.unbuilt_head_files", blockers
    ) != sorted(set(unbuilt)):
        blockers.append("source radar unbuilt file list is inconsistent")
    return sorted(evidence, key=lambda item: item["repository"])


def build_report(
    manifest: dict[str, Any],
    rule_delta: dict[str, Any],
    contracts: dict[str, Any],
    canonical_contracts: dict[str, Any],
    source_config: dict[str, Any],
    dist_evidence: dict[str, Any],
    source_bindings: dict[str, Any],
    protected_roots_payload: dict[str, Any],
    provenance: dict[str, Any],
    source_registry: dict[str, Any],
    radar: dict[str, Any],
    radar_snapshot: dict[str, Any],
    repository_root: pathlib.Path,
    collect_isolation: bool = True,
) -> dict[str, Any]:
    blockers: list[str] = []
    isolation_findings: list[dict[str, Any]] = []
    mapped_isolation_blockers: set[str] = set()
    derived_isolation_blockers: set[str] = set()

    def record_isolation_finding(
        *,
        code: str,
        scope: str,
        isolatable: bool,
        message: str,
        category: str = "",
        rule: str = "",
        source_ids: list[str] | None = None,
        repository_bindings: list[str] | None = None,
        dependency_closure: list[str] | None = None,
        maps_blocker: bool = False,
    ) -> None:
        if not collect_isolation:
            return
        isolation_findings.append(
            isolation_finding(
                code=code,
                scope=scope,
                isolatable=isolatable,
                message=message,
                category=category,
                rule=rule,
                source_ids=source_ids,
                repository_bindings=repository_bindings,
                dependency_closure=dependency_closure,
                blocker_sha256=(
                    hashlib.sha256(message.encode("utf-8")).hexdigest()
                    if maps_blocker
                    else ""
                ),
            )
        )
        if maps_blocker:
            mapped_isolation_blockers.add(message)

    protected_roots = protected_domain_roots(
        protected_roots_payload, repository_root
    )
    independently_changed_categories = sorted(
        str(item) for item in dist_evidence.get("changed_categories", [])
    )
    changed = manifest.get("changed") is True
    if changed is not bool(independently_changed_categories):
        blockers.append("candidate changed state differs from independently recomputed dist")
    if not changed:
        blockers.append("candidate has no semantic changes")
    if manifest.get("baseline_available") is not True:
        blockers.append("candidate has no verified baseline")
    current_lock_digest = str(
        dist_evidence.get("current_source_lock_sha256", "")
    )
    baseline_lock_digest = str(
        dist_evidence.get("baseline_source_lock_sha256", "")
    )
    if not SHA256_RE.fullmatch(current_lock_digest) or not SHA256_RE.fullmatch(
        baseline_lock_digest
    ):
        raise AutomatedReviewError("independent source lock digests are invalid")
    if manifest.get("source_lock_sha256") != current_lock_digest:
        blockers.append("manifest source lock digest was not independently reproduced")
    independent_lock_changed = bool(dist_evidence.get("source_lock_changed"))
    if manifest.get("source_lock_changed") is not independent_lock_changed:
        blockers.append("manifest source lock change state was not independently reproduced")
    if rule_delta.get("source_lock_changed") is not independent_lock_changed:
        blockers.append("rule delta source lock change state was not independently reproduced")
    if manifest.get("source_head_advanced_after_lock") is not False:
        blockers.append("active source advanced after lock")
    if strict_int(manifest.get("fallback_cache_count"), "fallback_cache_count", blockers) != 0:
        blockers.append("candidate used fallback cache")
    if manifest.get("cache_blocked_source_ids"):
        blockers.append("candidate contains cache-blocked sources")
    if manifest.get("budget_exceeded"):
        blockers.append("candidate exceeds category budgets")
    conflict_delta = manifest.get("conflict_delta")
    if not isinstance(conflict_delta, dict):
        blockers.append("candidate conflict delta is invalid")
        conflict_delta = {}
    independent_conflict_delta = dist_evidence.get("conflict_delta")
    if conflict_delta != independent_conflict_delta:
        blockers.append("candidate conflict delta was not independently reproduced")
    if strict_int(conflict_delta.get("cross_action"), "conflict_delta.cross_action", blockers) != 0:
        blockers.append("candidate introduces gated cross-action conflicts")
    if strict_int(conflict_delta.get("high_severity"), "conflict_delta.high_severity", blockers) != 0:
        blockers.append("candidate introduces high-severity conflicts")

    if radar.get("candidate_only") is not True or radar.get("promotion_blocked") is not False:
        blockers.append("source radar blocks promotion")
    radar_rows = radar_evidence(radar, radar_snapshot, blockers)
    if radar.get("advanced_active_repositories"):
        blockers.append("source radar reports an active-source race")
    unbuilt_head_files = string_list(
        radar.get("unbuilt_head_files"), "source_radar.unbuilt_head_files", blockers
    )
    if unbuilt_head_files:
        blockers.append("source radar reports unbuilt active-source files")
    high_impact_quorum = strict_int(
        radar.get("high_impact_quorum"), "source_radar.high_impact_quorum", blockers
    )
    if high_impact_quorum < 2 or high_impact_quorum != radar_snapshot.get("high_impact_quorum"):
        blockers.append("source radar high-impact quorum is invalid or inconsistent")

    changed_categories = string_list(
        manifest.get("changed_categories"), "changed_categories", blockers
    )
    if changed_categories != independently_changed_categories:
        blockers.append("manifest changed categories differ from independently recomputed dist")
    delta_changed_categories = string_list(
        rule_delta.get("changed_categories"), "rule_delta.changed_categories", blockers
    )
    if delta_changed_categories != changed_categories:
        blockers.append("manifest and rule delta changed categories do not match")
    if rule_delta.get("changed") is not changed:
        blockers.append("manifest and rule delta changed state do not match")
    if rule_delta.get("budget_exceeded") != manifest.get("budget_exceeded"):
        blockers.append("manifest and rule delta budget evidence does not match")
    if rule_delta.get("conflict_delta") != manifest.get("conflict_delta"):
        blockers.append("manifest and rule delta conflict evidence does not match")
    if rule_delta.get("conflict_delta") != independent_conflict_delta:
        blockers.append("rule delta conflicts differ from independently recomputed dist")

    delta_categories = rule_delta.get("categories")
    if not isinstance(delta_categories, list):
        raise AutomatedReviewError("rule_delta.categories must be an array")
    delta_by_category: dict[str, dict[str, Any]] = {}
    for raw in delta_categories:
        if not isinstance(raw, dict):
            raise AutomatedReviewError("rule delta category rows must be objects")
        category = str(raw.get("category", ""))
        if not category or category in delta_by_category:
            raise AutomatedReviewError("rule delta categories must be unique and named")
        delta_by_category[category] = raw
    if sorted(delta_by_category) != changed_categories:
        blockers.append("manifest and rule delta changed categories do not match")

    contract_map = contracts.get("categories")
    if not isinstance(contract_map, dict):
        raise AutomatedReviewError("contracts.categories must be an object")
    manual_only = canonical_contracts.get("manual_only_categories")
    if not isinstance(manual_only, list) or any(not isinstance(item, str) for item in manual_only):
        raise AutomatedReviewError("canonical manual_only_categories must be an array")
    manual_only_set = set(manual_only)

    source_rows = provenance.get("sources")
    if not isinstance(source_rows, list):
        raise AutomatedReviewError("source_provenance.sources must be an array")
    source_by_id: dict[str, dict[str, Any]] = {}
    for raw in source_rows:
        if not isinstance(raw, dict):
            raise AutomatedReviewError("source provenance rows must be objects")
        source_id = str(raw.get("source_id", ""))
        if not source_id or source_id in source_by_id:
            raise AutomatedReviewError("source provenance IDs must be unique and named")
        source_by_id[source_id] = raw
    profiles = source_registry.get("authority_profiles")
    if not isinstance(profiles, dict):
        raise AutomatedReviewError("source registry authority_profiles must be an object")
    if source_bindings.get("config_sha256") != digest_payload(source_config):
        raise AutomatedReviewError("canonical source binding digest is inconsistent")
    if provenance.get("source_lock_sha256") != current_lock_digest:
        blockers.append("source provenance lock digest differs from sources.lock.json")
    if digest_payload(provenance) != dist_evidence.get("current_provenance_sha256"):
        blockers.append("source provenance differs from independently loaded dist evidence")
    source_lock_repositories = dist_evidence.get("source_lock_repositories")
    if not isinstance(source_lock_repositories, dict):
        raise AutomatedReviewError("independent source lock repositories are malformed")
    for source_id, source in source_by_id.items():
        if str(source.get("revision_strategy", "")) != "github-commit-lock":
            continue
        repository = str(source.get("repository", ""))
        lock_entry = source_lock_repositories.get(repository)
        if not isinstance(lock_entry, dict):
            blockers.append(f"source {source_id} repository is absent from sources.lock.json")
            continue
        if source.get("resolved_revision") != lock_entry.get("resolved_revision"):
            blockers.append(f"source {source_id} revision differs from sources.lock.json")
        if source.get("requested_ref") != lock_entry.get("requested_ref"):
            blockers.append(f"source {source_id} requested ref differs from sources.lock.json")
    for row in radar_rows:
        if row.get("role") != "active-locked-source":
            continue
        repository = str(row.get("repository", ""))
        lock_entry = source_lock_repositories.get(repository)
        if not isinstance(lock_entry, dict):
            blockers.append(f"active radar repository is absent from source lock: {repository}")
            continue
        if row.get("locked_revision") != lock_entry.get("resolved_revision"):
            blockers.append(f"active radar lock revision differs for {repository}")
    canonical_bindings = source_bindings.get("bindings")
    allowed_sources_by_category = source_bindings.get("allowed_by_category")
    if not isinstance(canonical_bindings, dict) or not isinstance(
        allowed_sources_by_category, dict
    ):
        raise AutomatedReviewError("canonical source bindings are malformed")
    independent_categories = dist_evidence.get("categories")
    if not isinstance(independent_categories, dict):
        raise AutomatedReviewError("independent dist category evidence is malformed")

    category_evidence: list[dict[str, Any]] = []
    used_source_ids: set[str] = set()
    policy_modes: set[str] = set()
    recomputed_delta_risks: set[str] = set()
    recomputed_budget_exceeded: list[str] = []
    for category in changed_categories:
        row = delta_by_category.get(category)
        contract = contract_map.get(category)
        independent = independent_categories.get(category)
        if (
            not isinstance(row, dict)
            or not isinstance(contract, dict)
            or not isinstance(independent, dict)
        ):
            blockers.append(
                f"category {category} lacks delta, contract, or independent dist evidence"
            )
            continue
        action = str(independent.get("action", ""))
        for field in (
            "category_added",
            "category_removed",
            "previous_action",
            "action",
            "previous_priority",
            "priority",
            "action_changed",
            "priority_changed",
            "before_count",
            "after_count",
        ):
            if row.get(field) != independent.get(field):
                blockers.append(
                    f"category {category} {field} differs from independently recomputed dist"
                )
        try:
            canonical_contract = expected_contract(
                category, action, canonical_contracts, source_config
            )
        except AutomatedReviewError as exc:
            blockers.append(str(exc))
            canonical_contract = {}
        if contract != canonical_contract:
            blockers.append(f"category {category} resolved contract differs from canonical policy")
        if independent.get("current_contract") != canonical_contract:
            blockers.append(f"category {category} index contract differs from canonical policy")
        policy = str(canonical_contract.get("auto_promotion_policy", ""))
        policy_modes.add(policy)
        if category in manual_only_set or policy == "manual":
            blockers.append(f"category {category} is canonical manual-only")
        elif policy not in AUTOMATABLE_POLICIES:
            blockers.append(f"category {category} has unsupported promotion policy {policy}")
        if policy != "low-risk":
            recomputed_delta_risks.add(f"category-policy-{policy or 'invalid'}")
        if action != str(canonical_contract.get("action", "")):
            blockers.append(f"category {category} action does not match canonical contract")
        required_action = canonical_contract.get("required_action")
        if required_action is not None and action_family(action) != action_family(
            str(required_action)
        ):
            blockers.append(f"category {category} violates canonical required_action")
        if independent.get("category_added"):
            recomputed_delta_risks.add("category-added")
        if independent.get("category_removed"):
            recomputed_delta_risks.add("category-removed")
        if independent.get("action_changed"):
            recomputed_delta_risks.add("effective-action-change")
        if independent.get("priority_changed"):
            recomputed_delta_risks.add("priority-change")
        if independent.get("category_added") or independent.get("category_removed"):
            blockers.append(f"category {category} was added or removed")
        if independent.get("action_changed") or independent.get("priority_changed"):
            blockers.append(f"category {category} changed action or priority")

        allowed_rule_types = {
            str(value) for value in canonical_contract.get("allowed_rule_types", [])
        }
        allowed_source_tiers = {
            str(value) for value in canonical_contract.get("allowed_source_tiers", [])
        }
        additions = row.get("added")
        removals = row.get("removed")
        if not isinstance(additions, list) or not isinstance(removals, list):
            raise AutomatedReviewError(f"category {category} rule evidence is invalid")
        declared_added_rules = [
            str(item.get("rule", "")) for item in additions if isinstance(item, dict)
        ]
        declared_removed_rules = [
            str(item.get("rule", "")) for item in removals if isinstance(item, dict)
        ]
        if (
            len(declared_added_rules) != len(additions)
            or len(declared_added_rules) != len(set(declared_added_rules))
            or sorted(declared_added_rules) != independent.get("added")
        ):
            blockers.append(
                f"category {category} additions differ from independently recomputed dist"
            )
        if (
            len(declared_removed_rules) != len(removals)
            or len(declared_removed_rules) != len(set(declared_removed_rules))
            or sorted(declared_removed_rules) != independent.get("removed")
        ):
            blockers.append(
                f"category {category} removals differ from independently recomputed dist"
            )

        dimensions = budget_dimensions(
            list(independent.get("added", [])), protected_roots
        )
        before_count = int(independent.get("before_count", 0))
        delta_count = len(independent.get("added", [])) + len(
            independent.get("removed", [])
        )
        delta_pct = (
            delta_count * 100.0 / before_count
            if before_count
            else (100.0 if independent.get("after_count", 0) else 0.0)
        )
        observed_budget = {
            "max_add": len(independent.get("added", [])),
            "max_remove": len(independent.get("removed", [])),
            "max_pct": delta_pct,
            "max_new_apex": dimensions["new_apex"],
            "max_new_regex": dimensions["new_regex"],
            "max_new_cidr": dimensions["new_cidr"],
        }
        expected_category_budget: list[str] = []
        if independent.get("category_removed"):
            expected_category_budget.append(
                f"{category}:category_removed observed=1 allowed=0"
            )
        else:
            for budget_name, observed in observed_budget.items():
                allowed = float(canonical_contract.get(budget_name, -1))
                if observed > allowed:
                    expected_category_budget.append(
                        f"{category}:{budget_name} observed={observed:.6g} "
                        f"allowed={allowed:.6g}"
                    )
        info_delta = int(
            independent_conflict_delta.get("informational_by_category", {}).get(
                category, 0
            )
        )
        allowed_info_delta = int(
            canonical_contract.get("max_informational_overlap_delta", -1)
        )
        informational_budget = ""
        if info_delta > allowed_info_delta:
            informational_budget = (
                f"{category}:max_informational_overlap_delta "
                f"observed={info_delta} allowed={allowed_info_delta}"
            )
        declared_category_budget = row.get("budget_exceeded")
        if not isinstance(declared_category_budget, list) or sorted(
            str(item) for item in declared_category_budget
        ) != sorted(expected_category_budget):
            blockers.append(
                f"category {category} budget blockers were not independently recomputed"
            )
        if row.get("budget_observed") != observed_budget:
            blockers.append(
                f"category {category} budget observations were not independently recomputed"
            )
        recomputed_budget_exceeded.extend(expected_category_budget)
        if informational_budget:
            recomputed_budget_exceeded.append(informational_budget)
        if expected_category_budget or informational_budget:
            blockers.append(f"category {category} exceeds its contract budget")
        allowed_category_source_ids = {
            str(item) for item in allowed_sources_by_category.get(category, [])
        }
        source_counts: Counter[str] = Counter()
        for raw_rule in additions:
            if not isinstance(raw_rule, dict):
                raise AutomatedReviewError(f"category {category} addition is invalid")
            rule = str(raw_rule.get("rule", ""))
            sources = string_list(raw_rule.get("sources"), f"category {category} sources", blockers)
            declared_tiers = string_list(
                raw_rule.get("source_tiers"), f"category {category} source_tiers", blockers
            )
            actual_tiers = sorted(
                {
                    str(source_by_id[source_id].get("trust_tier", ""))
                    for source_id in sources
                    if source_id in source_by_id
                }
            )
            expected_rule_risks = set(
                rule_risk_markers(
                    rule,
                    action,
                    added=True,
                    protected_roots=protected_roots,
                )
            )
            if actual_tiers == ["community"]:
                expected_rule_risks.add("single-community-tier")
            unsupported_rule_risks = sorted(
                expected_rule_risks - AUTOMATABLE_ELEVATED_MARKERS
            )
            declared_rule_risks = string_list(
                raw_rule.get("risk"), f"category {category} addition risk", blockers
            )
            if declared_rule_risks != sorted(expected_rule_risks):
                blockers.append(f"category {category} addition risk was not recomputed exactly: {rule}")
            recomputed_delta_risks.update(expected_rule_risks)
            if rule_type(rule) not in allowed_rule_types:
                blockers.append(f"category {category} adds disallowed rule type: {rule}")
            if not sources or not declared_tiers:
                blockers.append(f"category {category} addition lacks source evidence: {rule}")
            if declared_tiers != actual_tiers:
                blockers.append(f"category {category} source tiers are not exact: {rule}")
            if not set(actual_tiers).issubset(allowed_source_tiers):
                blockers.append(f"category {category} addition uses a disallowed tier: {rule}")
            effective = independent.get("added_effective_actions", {}).get(rule, {})
            if (
                str(raw_rule.get("old_effective_action", ""))
                != str(effective.get("old", ""))
                or str(raw_rule.get("new_effective_action", ""))
                != str(effective.get("new", ""))
            ):
                blockers.append(
                    f"category {category} addition effective action was not independently recomputed: {rule}"
                )

            membership = raw_rule.get("source_membership")
            membership_by_source: dict[str, dict[str, Any]] = {}
            if not isinstance(membership, list):
                blockers.append(f"category {category} addition lacks source membership: {rule}")
            else:
                for witness in membership:
                    if not isinstance(witness, dict):
                        blockers.append(f"category {category} source membership is malformed: {rule}")
                        continue
                    witness_source = str(witness.get("source_id", ""))
                    if not witness_source or witness_source in membership_by_source:
                        blockers.append(f"category {category} source membership IDs are invalid: {rule}")
                        continue
                    membership_by_source[witness_source] = witness
            if sorted(membership_by_source) != sources:
                blockers.append(f"category {category} source membership set is not exact: {rule}")

            owners: set[str] = set()
            bindings: set[str] = set()
            stable_binding_ids: set[str] = set()
            repository_bindings: set[str] = set()
            privileged_tier = False
            for source_id in sources:
                source_counts[source_id] += 1
                used_source_ids.add(source_id)
                if source_id not in allowed_category_source_ids:
                    blockers.append(
                        f"category {category} cites source outside canonical source graph: {source_id}"
                    )
                source = source_by_id.get(source_id)
                if not isinstance(source, dict):
                    blockers.append(f"category {category} cites unknown source {source_id}")
                    continue
                canonical_binding = canonical_bindings.get(source_id)
                if isinstance(canonical_binding, dict):
                    stable_binding_id = str(
                        canonical_binding.get("binding_id", "")
                    )
                    if stable_binding_id:
                        stable_binding_ids.add(stable_binding_id)
                profile = profiles.get(str(source.get("authority", "")))
                profile_rule_types = {
                    str(value)
                    for value in profile.get("allowed_rule_types", [])
                } if isinstance(profile, dict) else set()
                if rule_type(rule) not in profile_rule_types:
                    blockers.append(
                        f"category {category} source authority disallows rule type: {source_id}: {rule}"
                    )
                witness = membership_by_source.get(source_id)
                if isinstance(witness, dict):
                    validate_membership(rule, witness, source, blockers)
                tier = str(source.get("trust_tier", ""))
                privileged_tier = privileged_tier or tier in {"owner", "official"}
                owner = str(source.get("owner", ""))
                if owner:
                    owners.add(owner)
                binding = str(source.get("repository", "")) or (
                    urllib.parse.urlparse(str(source.get("resolved_ref", ""))).hostname or ""
                )
                if binding:
                    bindings.add(binding)
                    repository_bindings.add(binding)
            for marker in unsupported_rule_risks:
                record_isolation_finding(
                    code="unsupported-rule-risk-marker",
                    scope="rule",
                    isolatable=True,
                    category=category,
                    rule=rule,
                    source_ids=sources,
                    repository_bindings=sorted(repository_bindings),
                    dependency_closure=(
                        [f"category:{category}"]
                        + [
                            f"source-binding:{binding_id}"
                            for binding_id in sorted(stable_binding_ids)
                        ]
                        + [
                            f"repository:{binding}"
                            for binding in sorted(repository_bindings)
                        ]
                    ),
                    message=(
                        f"category {category} rule has unsupported risk marker "
                        f"{marker}: {rule}"
                    ),
                )
            elevated = policy != "low-risk" or bool(expected_rule_risks)
            if elevated and not privileged_tier and not (
                len(owners) >= high_impact_quorum
                and len(bindings) >= high_impact_quorum
            ):
                message = (
                    f"category {category} elevated addition lacks rule-level "
                    f"independent authority: {rule}"
                )
                blockers.append(message)
                record_isolation_finding(
                    code="addition-independent-authority",
                    scope="rule",
                    isolatable=True,
                    category=category,
                    rule=rule,
                    source_ids=sources,
                    repository_bindings=sorted(repository_bindings),
                    dependency_closure=(
                        [f"category:{category}"]
                        + [
                            f"source-binding:{binding_id}"
                            for binding_id in sorted(stable_binding_ids)
                        ]
                        + [
                            f"repository:{binding}"
                            for binding in sorted(repository_bindings)
                        ]
                    ),
                    message=message,
                    maps_blocker=True,
                )

        for raw_rule in removals:
            if not isinstance(raw_rule, dict):
                raise AutomatedReviewError(f"category {category} removal is invalid")
            rule = str(raw_rule.get("rule", ""))
            expected_rule_risks = set(
                rule_risk_markers(
                    rule,
                    action,
                    added=False,
                    protected_roots=protected_roots,
                )
            )
            declared_rule_risks = string_list(
                raw_rule.get("risk"), f"category {category} removal risk", blockers
            )
            if declared_rule_risks != sorted(expected_rule_risks):
                blockers.append(f"category {category} removal risk was not recomputed exactly: {rule}")
            recomputed_delta_risks.update(expected_rule_risks)
            if raw_rule.get("sources") != ["previous_snapshot"]:
                blockers.append(f"category {category} removal lacks baseline provenance: {rule}")
            effective = independent.get("removed_effective_actions", {}).get(rule, {})
            if (
                str(raw_rule.get("old_effective_action", ""))
                != str(effective.get("old", ""))
                or str(raw_rule.get("new_effective_action", ""))
                != str(effective.get("new", ""))
            ):
                blockers.append(
                    f"category {category} removal effective action was not independently recomputed: {rule}"
                )
            message = (
                f"category {category} automated removal lacks current-source "
                f"absence proof: {rule}"
            )
            blockers.append(message)
            record_isolation_finding(
                code="removal-current-source-absence-proof",
                scope="rule",
                isolatable=True,
                category=category,
                rule=rule,
                source_ids=["previous_snapshot"],
                dependency_closure=[f"category:{category}"],
                message=message,
                maps_blocker=True,
            )

        category_evidence.append(
            {
                "category": category,
                "policy": policy,
                "action": action,
                "priority": row.get("priority"),
                "added_count": len(additions),
                "removed_count": len(removals),
                "added_rule_evidence_sha256": digest_payload(
                    stable_rule_evidence(additions, removed=False)
                ),
                "removed_rule_evidence_sha256": digest_payload(
                    stable_rule_evidence(removals, removed=True)
                ),
                "addition_source_counts": dict(sorted(source_counts.items())),
            }
        )

    declared_manifest_budget = string_list(
        manifest.get("budget_exceeded"), "budget_exceeded", blockers
    )
    declared_delta_budget = string_list(
        rule_delta.get("budget_exceeded"), "rule_delta.budget_exceeded", blockers
    )
    expected_budget = sorted(set(recomputed_budget_exceeded))
    if declared_manifest_budget != expected_budget:
        blockers.append("manifest budget blockers were not independently recomputed")
    if declared_delta_budget != expected_budget:
        blockers.append("rule delta budget blockers were not independently recomputed")

    declared_delta_risks = string_list(
        rule_delta.get("risk_markers"), "rule_delta.risk_markers", blockers
    )
    if declared_delta_risks != sorted(recomputed_delta_risks):
        blockers.append("rule delta risk markers were not independently recomputed")
    manifest_risks = set(recomputed_delta_risks)
    if radar.get("advanced_active_repositories"):
        manifest_risks.add("source-head-advanced-after-lock")
    declared_manifest_risks = string_list(
        manifest.get("risk_markers"), "risk_markers", blockers
    )
    if declared_manifest_risks != sorted(manifest_risks):
        blockers.append("manifest risk markers were not independently recomputed")
    unsupported_elevated = sorted(
        manifest_risks - AUTOMATABLE_ELEVATED_MARKERS
    )
    if unsupported_elevated:
        message = "unsupported elevated risk markers: " + ", ".join(
            unsupported_elevated
        )
        blockers.append(message)
        derived_isolation_blockers.add(message)

    expected_quorum_review = changed and "single-community-tier" in manifest_risks
    if radar.get("quorum_review_required") is not expected_quorum_review:
        blockers.append("source radar quorum-review state is inconsistent")
    expected_auto_blocked = bool(radar.get("advanced_active_repositories")) or expected_quorum_review
    if radar.get("auto_promotion_blocked") is not expected_auto_blocked:
        blockers.append("source radar auto-promotion state is inconsistent")

    source_evidence: list[dict[str, Any]] = []
    for source_id in sorted(used_source_ids):
        if source_id not in source_by_id:
            continue
        source = source_by_id[source_id]
        binding = canonical_bindings.get(source_id)
        prior_blocker_count = len(blockers)
        source_evidence.append(
            validate_source(
                source_id,
                source,
                binding,
                profiles,
                repository_root,
                blockers,
            )
        )
        new_source_blockers = blockers[prior_blocker_count:]
        binding_id = (
            str(binding.get("binding_id", ""))
            if isinstance(binding, dict)
            else ""
        )
        category = (
            str(binding.get("category", ""))
            if isinstance(binding, dict)
            else ""
        )
        repository = str(source.get("repository", "")) or (
            urllib.parse.urlparse(str(source.get("resolved_ref", ""))).hostname
            or ""
        )
        expected_network_message = (
            f"source {source_id} was not fetched from the network"
        )
        for message in new_source_blockers:
            network_freshness = message == expected_network_message
            record_isolation_finding(
                code=(
                    "source-network-freshness"
                    if network_freshness
                    else "source-integrity-failure"
                ),
                scope="source-binding" if binding_id else "global",
                isolatable=bool(binding_id) and network_freshness,
                category=category,
                source_ids=[source_id],
                repository_bindings=[repository] if repository else [],
                dependency_closure=(
                    ([f"category:{category}"] if category else [])
                    + (
                        [f"source-binding:{binding_id}"]
                        if binding_id
                        else []
                    )
                    + ([f"repository:{repository}"] if repository else [])
                ),
                message=message,
                maps_blocker=True,
            )
    risk_level = str(manifest.get("risk_level", ""))
    expected_risk = (
        "high"
        if manifest_risks
        or manifest.get("budget_exceeded")
        or manifest.get("cache_blocked_source_ids")
        else ("low" if changed else "none")
    )
    if risk_level != expected_risk:
        blockers.append(f"candidate risk level {risk_level} does not match {expected_risk} evidence")
    expected_legacy_auto = (
        changed
        and manifest.get("baseline_available") is True
        and manifest.get("source_head_advanced_after_lock") is False
        and manifest.get("fallback_cache_count") == 0
        and not manifest.get("cache_blocked_source_ids")
        and not manifest.get("budget_exceeded")
        and not manifest_risks
        and policy_modes == {"low-risk"}
    )
    if manifest.get("auto_promotion_eligible") is not expected_legacy_auto:
        blockers.append("legacy auto promotion eligibility does not match candidate evidence")
    if manifest.get("requires_review") is not (changed and not expected_legacy_auto):
        blockers.append("legacy review-required state does not match candidate evidence")

    unique_blockers = sorted(set(blockers))
    unscoped_isolation_blockers = sorted(
        set(unique_blockers)
        - mapped_isolation_blockers
        - derived_isolation_blockers
    )
    ordered_isolation_findings = sorted(
        isolation_findings,
        key=lambda item: (
            str(item["scope"]),
            str(item["category"]),
            str(item["rule"]),
            str(item["code"]),
            str(item["evidence_digest"]),
        ),
    )
    isolation_evidence = {
        "schema": ISOLATION_EVIDENCE_SCHEMA,
        "mode": "shadow-only",
        "source_provenance_sha256": str(
            dist_evidence.get("current_provenance_sha256", "")
        ),
        "complete_blocker_mapping": not unscoped_isolation_blockers,
        "blocker_count": len(unique_blockers),
        "mapped_blocker_count": len(
            set(unique_blockers) & mapped_isolation_blockers
        ),
        "derived_blocker_count": len(
            set(unique_blockers) & derived_isolation_blockers
        ),
        "derived_blocker_sha256s": sorted(
            hashlib.sha256(message.encode("utf-8")).hexdigest()
            for message in set(unique_blockers) & derived_isolation_blockers
        ),
        "unscoped_blockers": unscoped_isolation_blockers,
        "findings": ordered_isolation_findings,
        "findings_sha256": digest_payload(ordered_isolation_findings),
    }
    isolation_evidence["evidence_sha256"] = digest_payload(isolation_evidence)

    return {
        "schema": REPORT_SCHEMA,
        "eligible": not blockers,
        "required_stable_cycles": REQUIRED_STABLE_CYCLES,
        "minimum_cycle_separation_seconds": MINIMUM_CYCLE_SEPARATION_SECONDS,
        "review_policy": REVIEW_POLICY,
        "baseline_index_sha256": str(
            dist_evidence.get("baseline_index_sha256", "")
        ),
        "current_index_sha256": str(
            dist_evidence.get("current_index_sha256", "")
        ),
        "baseline_source_lock_sha256": baseline_lock_digest,
        "current_source_lock_sha256": current_lock_digest,
        "source_lock_changed": independent_lock_changed,
        "source_config_sha256": str(source_bindings.get("config_sha256", "")),
        "protected_domain_roots_sha256": digest_payload(protected_roots_payload),
        "public_suffix_list_sha256": protected_roots[
            "public_suffix_database"
        ].sha256,
        "public_suffix_list_source_commit": protected_roots[
            "public_suffix_database"
        ].source_commit,
        "changed_categories": changed_categories,
        "risk_level": risk_level,
        "risk_markers": declared_manifest_risks,
        "policy_modes": sorted(policy_modes),
        "category_evidence": sorted(
            category_evidence, key=lambda item: str(item["category"])
        ),
        "source_evidence": sorted(
            source_evidence, key=lambda item: str(item["source_id"])
        ),
        "radar_evidence": radar_rows,
        "isolation_evidence": isolation_evidence,
        "blockers": unique_blockers,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate or enforce deterministic unattended review evidence."
    )
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--rule-delta", type=pathlib.Path, required=True)
    parser.add_argument("--contracts", type=pathlib.Path, required=True)
    parser.add_argument("--canonical-contracts", type=pathlib.Path, required=True)
    parser.add_argument("--source-config", type=pathlib.Path, required=True)
    parser.add_argument("--baseline-dist", type=pathlib.Path, required=True)
    parser.add_argument("--current-dist", type=pathlib.Path, required=True)
    parser.add_argument("--protected-domain-roots", type=pathlib.Path, required=True)
    parser.add_argument("--repository-root", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--provenance", type=pathlib.Path, required=True)
    parser.add_argument("--source-registry", type=pathlib.Path, required=True)
    parser.add_argument("--radar-decision", type=pathlib.Path, required=True)
    parser.add_argument("--radar-snapshot", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--isolation-output", type=pathlib.Path)
    parser.add_argument("--require-eligible", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = build_report(
            read_json(args.manifest),
            read_json(args.rule_delta),
            read_json(args.contracts),
            read_json(args.canonical_contracts),
            read_json(args.source_config),
            recompute_dist_evidence(args.baseline_dist, args.current_dist),
            canonical_source_bindings(read_json(args.source_config)),
            read_json(args.protected_domain_roots),
            read_json(args.provenance),
            read_json(args.source_registry),
            read_json(args.radar_decision),
            read_json(args.radar_snapshot),
            args.repository_root.resolve(),
            args.isolation_output is not None,
        )
        automated_review, isolation_artifact = separate_isolation_artifact(report)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_bytes(automated_review))
        if args.isolation_output is not None:
            args.isolation_output.parent.mkdir(parents=True, exist_ok=True)
            args.isolation_output.write_bytes(canonical_bytes(isolation_artifact))
        print(
            "[automated-review] "
            f"eligible={str(automated_review['eligible']).lower()} "
            f"blockers={len(automated_review['blockers'])}"
        )
        if args.require_eligible and automated_review["eligible"] is not True:
            for blocker in automated_review["blockers"]:
                print(f"[automated-review] blocker: {blocker}")
            return 1
        return 0
    except (AutomatedReviewError, OSError, TypeError, ValueError) as exc:
        print(f"[automated-review] error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
