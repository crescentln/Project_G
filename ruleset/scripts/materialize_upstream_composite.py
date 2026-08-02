#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
import tempfile
from collections import defaultdict
from typing import Any

try:
    from ruleset.scripts import build_rulesets as builder
    from ruleset.scripts import generate_recommended_templates as templates
    from ruleset.scripts.build_category_lkg_binding import (
        CategoryLkgBindingError,
        category_output_identities,
        directory_manifest,
        validate_source_provenance,
    )
    from ruleset.scripts.check_automated_review import (
        AutomatedReviewError,
        ISOLATION_ARTIFACT_SCHEMA,
        ISOLATION_EVIDENCE_SCHEMA,
        canonical_bytes,
        canonical_source_bindings,
        digest_payload,
        source_lock_identity,
        validate_membership,
    )
    from ruleset.scripts.plan_upstream_isolation import (
        PLAN_SCHEMA,
        PLANNER_POLICY,
        SELECTION_SCHEMA,
        category_graph,
        validate_category_lkg_binding,
    )
except ModuleNotFoundError:
    import build_rulesets as builder  # type: ignore[no-redef]
    import generate_recommended_templates as templates  # type: ignore[no-redef]
    from build_category_lkg_binding import (  # type: ignore[no-redef]
        CategoryLkgBindingError,
        category_output_identities,
        directory_manifest,
        validate_source_provenance,
    )
    from check_automated_review import (  # type: ignore[no-redef]
        AutomatedReviewError,
        ISOLATION_ARTIFACT_SCHEMA,
        ISOLATION_EVIDENCE_SCHEMA,
        canonical_bytes,
        canonical_source_bindings,
        digest_payload,
        source_lock_identity,
        validate_membership,
    )
    from plan_upstream_isolation import (  # type: ignore[no-redef]
        PLAN_SCHEMA,
        PLANNER_POLICY,
        SELECTION_SCHEMA,
        category_graph,
        validate_category_lkg_binding,
    )


COMPOSITE_SCHEMA = "project-g-upstream-isolation-composite-v1"
REVIEW_SCHEMA = "project-g-upstream-isolation-composite-review-v1"
MATERIALIZER_POLICY = "atomic-repository-complete-category-lkg-v1"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CompositeError(RuntimeError):
    pass


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompositeError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CompositeError(f"JSON root must be an object: {path}")
    return payload


def verify_digest(payload: dict[str, Any], field: str, label: str) -> None:
    expected = str(payload.get(field, ""))
    without_digest = dict(payload)
    without_digest.pop(field, None)
    if not SHA256_RE.fullmatch(expected) or digest_payload(without_digest) != expected:
        raise CompositeError(f"{label} digest is invalid")


def validate_shadow_output_path(
    path: pathlib.Path,
    label: str,
    *,
    repository_root: pathlib.Path,
) -> pathlib.Path:
    if path.exists() and path.is_symlink():
        raise CompositeError(f"refusing symlink {label}: {path}")
    resolved = path.expanduser().resolve(strict=False)
    try:
        resolved.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise CompositeError(f"{label} must be outside the repository tree")
    temp_root = pathlib.Path(tempfile.gettempdir()).resolve(strict=False)
    try:
        relative = resolved.relative_to(temp_root)
    except ValueError as exc:
        raise CompositeError(f"{label} must be inside the OS temporary directory") from exc
    if not relative.parts:
        raise CompositeError(f"{label} cannot be the OS temporary directory")
    return resolved


def validate_shadow_outputs(args: argparse.Namespace) -> None:
    repository_root = builder.ROOT_DIR.parent.resolve(strict=False)
    output_dist = validate_shadow_output_path(
        args.output_dist,
        "output dist",
        repository_root=repository_root,
    )
    output_identity = validate_shadow_output_path(
        args.output_identity,
        "output identity",
        repository_root=repository_root,
    )
    output_review = validate_shadow_output_path(
        args.output_review,
        "output review",
        repository_root=repository_root,
    )
    if output_identity == output_review:
        raise CompositeError("output identity and review paths must differ")
    for path, label in (
        (output_identity, "output identity"),
        (output_review, "output review"),
    ):
        try:
            path.relative_to(output_dist)
        except ValueError:
            continue
        raise CompositeError(f"{label} must be outside the output dist tree")
    args.output_dist = output_dist
    args.output_identity = output_identity
    args.output_review = output_review


def parse_generated_at(value: str) -> str:
    if not value or value.endswith("Z"):
        normalized = value.removesuffix("Z") + "+00:00"
    else:
        normalized = value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CompositeError("generated-at-utc must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise CompositeError("generated-at-utc must include a timezone")
    return parsed.astimezone(dt.timezone.utc).isoformat()


def index_rows(index: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    raw_rows = index.get("categories")
    if not isinstance(raw_rows, list) or any(
        not isinstance(item, dict) for item in raw_rows
    ):
        raise CompositeError(f"{label} index categories are invalid")
    rows: dict[str, dict[str, Any]] = {}
    for raw in raw_rows:
        category = str(raw.get("id", "")).strip()
        if not category or category in rows:
            raise CompositeError(f"{label} index category IDs are invalid")
        rows[category] = raw
    if index.get("category_count") != len(rows):
        raise CompositeError(f"{label} index category count is invalid")
    return rows


def provenance_rows(
    payload: dict[str, Any], label: str
) -> dict[str, dict[str, Any]]:
    rows = payload.get("sources")
    if (
        not isinstance(rows, list)
        or payload.get("source_count") != len(rows)
        or any(not isinstance(item, dict) for item in rows)
    ):
        raise CompositeError(f"{label} source provenance is invalid")
    result: dict[str, dict[str, Any]] = {}
    for raw in rows:
        source_id = str(raw.get("source_id", "")).strip()
        if not source_id or source_id in result:
            raise CompositeError(f"{label} source provenance IDs are invalid")
        result[source_id] = raw
    return result


def read_rules(dist: pathlib.Path, category: str) -> list[str]:
    try:
        rules = builder.read_openclash_rule_file(
            dist / "openclash" / f"{category}.yaml"
        )
    except (OSError, UnicodeDecodeError, builder.BuildError) as exc:
        raise CompositeError(f"failed to read category {category}: {exc}") from exc
    return sorted(rules, key=builder.rule_sort_key)


def decision_rows(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = plan.get("category_decisions")
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise CompositeError("isolation plan category decisions are invalid")
    rows: dict[str, dict[str, Any]] = {}
    for item in raw:
        category = str(item.get("category", ""))
        if not category or category in rows:
            raise CompositeError("isolation plan category decision IDs are invalid")
        rows[category] = item
    return rows


def isolation_observation_summary(
    *,
    artifact: dict[str, Any],
    plan: dict[str, Any],
    source_config: dict[str, Any],
    baseline_index: dict[str, Any],
    candidate_index: dict[str, Any],
    candidate_provenance: dict[str, Any],
) -> dict[str, Any]:
    if (
        artifact.get("schema") != ISOLATION_ARTIFACT_SCHEMA
        or artifact.get("mode") != "shadow-only"
    ):
        raise CompositeError("isolation observation artifact is invalid")
    verify_digest(artifact, "artifact_sha256", "isolation observation artifact")
    for artifact_field, expected in (
        ("automated_review_sha256", plan.get("automated_review_sha256")),
        ("baseline_index_sha256", digest_payload(baseline_index)),
        ("candidate_index_sha256", digest_payload(candidate_index)),
        ("source_config_sha256", digest_payload(source_config)),
    ):
        if artifact.get(artifact_field) != expected:
            raise CompositeError(
                f"isolation observation {artifact_field} binding is invalid"
            )
    evidence = artifact.get("isolation_evidence")
    if (
        not isinstance(evidence, dict)
        or evidence.get("schema") != ISOLATION_EVIDENCE_SCHEMA
        or evidence.get("mode") != "shadow-only"
    ):
        raise CompositeError("isolation observation evidence is invalid")
    verify_digest(evidence, "evidence_sha256", "isolation observation evidence")
    if (
        evidence.get("evidence_sha256") != plan.get("isolation_evidence_sha256")
        or evidence.get("source_provenance_sha256")
        != digest_payload(candidate_provenance)
    ):
        raise CompositeError("isolation observation provenance binding is invalid")
    findings = evidence.get("findings")
    unscoped = evidence.get("unscoped_blockers")
    if (
        not isinstance(findings, list)
        or any(not isinstance(item, dict) for item in findings)
        or evidence.get("findings_sha256") != digest_payload(findings)
        or not isinstance(unscoped, list)
        or any(not isinstance(item, str) or not item for item in unscoped)
        or unscoped != sorted(set(unscoped))
    ):
        raise CompositeError("isolation observation findings are invalid")

    source_ids: set[str] = set()
    finding_categories: set[str] = set()
    finding_codes: set[str] = set()
    for finding in findings:
        verify_digest(finding, "evidence_digest", "isolation observation finding")
        raw_source_ids = finding.get("source_ids")
        if (
            not isinstance(raw_source_ids, list)
            or any(not isinstance(item, str) or not item for item in raw_source_ids)
            or raw_source_ids != sorted(set(raw_source_ids))
        ):
            raise CompositeError("isolation observation source IDs are invalid")
        source_ids.update(raw_source_ids)
        category = str(finding.get("category", ""))
        code = str(finding.get("code", ""))
        if category:
            finding_categories.add(category)
        if code:
            finding_codes.add(code)

    blocker_count = evidence.get("blocker_count")
    if (
        isinstance(blocker_count, bool)
        or not isinstance(blocker_count, int)
        or blocker_count < 0
        or not isinstance(evidence.get("complete_blocker_mapping"), bool)
    ):
        raise CompositeError("isolation observation blocker summary is invalid")
    plan_category_lists: dict[str, list[str]] = {}
    for field in ("quarantined_categories", "held_categories"):
        values = plan.get(field)
        if (
            not isinstance(values, list)
            or any(not isinstance(item, str) or not item for item in values)
            or values != sorted(set(values))
        ):
            raise CompositeError(f"isolation plan {field} is invalid")
        plan_category_lists[field] = values
    summary: dict[str, Any] = {
        "schema": "project-g-upstream-isolation-observation-summary-v1",
        "evidence_sha256": str(evidence["evidence_sha256"]),
        "complete_blocker_mapping": bool(evidence["complete_blocker_mapping"]),
        "blocker_count": blocker_count,
        "finding_count": len(findings),
        "unscoped_blocker_count": len(unscoped),
        "finding_categories": sorted(finding_categories),
        "finding_codes": sorted(finding_codes),
        "isolated_source_ids": sorted(source_ids),
        "quarantined_categories": list(
            plan_category_lists["quarantined_categories"]
        ),
        "held_categories": list(plan_category_lists["held_categories"]),
    }
    summary["summary_sha256"] = digest_payload(summary)
    return summary


def selected_source_lock(
    *,
    plan: dict[str, Any],
    baseline_lock: dict[str, Any],
    candidate_lock: dict[str, Any],
    generated_at_utc: str,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    try:
        _baseline_digest, baseline_repositories = source_lock_identity(
            baseline_lock, "composite baseline"
        )
        _candidate_digest, candidate_repositories = source_lock_identity(
            candidate_lock, "composite candidate"
        )
    except AutomatedReviewError as exc:
        raise CompositeError(str(exc)) from exc
    rows = plan.get("stable_selection", {}).get("repository_selections")
    if not isinstance(rows, list) or any(not isinstance(item, dict) for item in rows):
        raise CompositeError("composite repository selections are invalid")
    if digest_payload(rows) != plan.get("stable_selection", {}).get(
        "selected_repository_lock_sha256"
    ):
        raise CompositeError("composite repository selection binding is invalid")

    selected: dict[str, Any] = {}
    seen: set[str] = set()
    expected = set(baseline_repositories) | set(candidate_repositories)
    for raw in rows:
        repository = str(raw.get("repository", ""))
        selection = str(raw.get("selection", ""))
        if not repository or repository in seen:
            raise CompositeError("composite repository selection IDs are invalid")
        seen.add(repository)
        if selection == "observed-candidate-lock":
            entry = candidate_repositories.get(repository)
        elif selection == "published-lkg-lock":
            entry = baseline_repositories.get(repository)
        else:
            raise CompositeError(f"unsupported repository selection: {selection}")
        if not isinstance(entry, dict) or digest_payload(entry) != raw.get(
            "selected_entry_sha256"
        ):
            raise CompositeError(
                f"selected source lock entry is invalid: {repository}"
            )
        selected[repository] = copy.deepcopy(entry)
    if seen != expected:
        raise CompositeError("composite repository selection coverage is not exact")
    payload = {
        "version": 1,
        "generated_at_utc": generated_at_utc,
        "repositories": selected,
        "selection_policy": MATERIALIZER_POLICY,
    }
    try:
        lock_digest, repositories = source_lock_identity(payload, "composite")
    except AutomatedReviewError as exc:
        raise CompositeError(str(exc)) from exc
    return payload, lock_digest, repositories


def validate_configured_source(
    *,
    source: dict[str, Any],
    source_id: str,
    provenance: dict[str, Any],
    legacy_config_digest: str = "",
) -> None:
    try:
        controls = builder.source_controls(source)
    except builder.BuildError as exc:
        raise CompositeError(str(exc)) from exc
    expected = {
        "authority": str(source.get("authority", "unspecified")),
        "trust_tier": str(controls["trust_tier"]),
        "license": str(controls["license"]),
        "owner": str(controls["owner"]),
        "revision_strategy": str(controls["revision_strategy"]),
    }
    for field, value in expected.items():
        if provenance.get(field) != value:
            raise CompositeError(
                f"selected provenance differs from current source policy: "
                f"{source_id}/{field}"
            )
    configured_digest = str(provenance.get("configured_source_sha256", ""))
    expected_digest = builder.configured_source_digest(source)
    if configured_digest:
        if configured_digest != expected_digest:
            raise CompositeError(
                f"selected provenance differs from current source policy: "
                f"{source_id}/configured_source_sha256"
            )
    elif legacy_config_digest != expected_digest:
        raise CompositeError(
            f"selected provenance lacks an exact bound config digest: {source_id}"
        )
    expected_refs = (
        [str(source.get("path", ""))]
        if str(source.get("type", "")) == "local_domain"
        else builder.collect_source_urls(source)
    )
    if (
        provenance.get("type") != source.get("type")
        or provenance.get("requested_refs") != expected_refs
    ):
        raise CompositeError(
            f"selected provenance source binding differs from config: {source_id}"
        )
    expected_limits = {
        "allowed_hosts": list(controls["allowed_hosts"]),
        "max_bytes": int(controls["max_bytes"]),
        "max_files": int(controls["max_files"]),
        "max_include_depth": int(controls["max_include_depth"]),
        "freshness_ttl_hours": float(controls["freshness_ttl_hours"]),
    }
    parser_stats = provenance.get("parser_stats")
    observed_rule_types = (
        set(parser_stats.get("rule_type_counts", {}))
        if isinstance(parser_stats, dict)
        and isinstance(parser_stats.get("rule_type_counts"), dict)
        else set()
    )
    allowed_rule_types = {
        str(item).strip().upper()
        for item in controls.get("allowed_rule_types", [])
        if str(item).strip()
    }
    try:
        observed_line_ratio = float(
            parser_stats.get("accepted_line_ratio", -1)
            if isinstance(parser_stats, dict)
            else -1
        )
    except (TypeError, ValueError) as exc:
        raise CompositeError(
            f"selected provenance parser ratio is invalid: {source_id}"
        ) from exc
    if (
        provenance.get("limits") != expected_limits
        or provenance.get("critical") is not bool(controls["critical"])
        or provenance.get("no_cache_publish")
        is not bool(controls["no_cache_publish"])
        or not isinstance(parser_stats, dict)
        or observed_line_ratio < float(controls["accepted_line_ratio"])
        or (allowed_rule_types and not observed_rule_types <= allowed_rule_types)
    ):
        raise CompositeError(
            f"selected provenance controls differ from current policy: {source_id}"
        )


def raw_delta_attribution(
    *,
    category: str,
    before_rules: set[str],
    after_rules: set[str],
    candidate_delta_rows: dict[str, dict[str, Any]],
    selected_provenance: dict[str, dict[str, Any]],
    allowed_source_ids: set[str],
) -> tuple[dict[str, set[str]], dict[tuple[str, str], dict[str, Any]]]:
    additions = after_rules - before_rules
    removals = before_rules - after_rules
    if removals:
        raise CompositeError(
            f"candidate selection contains removals without absence proof: {category}"
        )
    if not additions:
        return {}, {}
    raw = candidate_delta_rows.get(category)
    if not isinstance(raw, dict):
        raise CompositeError(f"candidate delta is absent for selected category {category}")
    raw_added = raw.get("added")
    if not isinstance(raw_added, list) or any(
        not isinstance(item, dict) for item in raw_added
    ):
        raise CompositeError(f"candidate additions are invalid for {category}")
    by_rule = {str(item.get("rule", "")): item for item in raw_added}
    if (
        len(by_rule) != len(raw_added)
        or "" in by_rule
        or set(by_rule) != additions
    ):
        raise CompositeError(
            f"candidate addition evidence is not exact for selected category {category}"
        )

    attribution: dict[str, set[str]] = {}
    witnesses: dict[tuple[str, str], dict[str, Any]] = {}
    for rule in sorted(additions, key=builder.rule_sort_key):
        item = by_rule[rule]
        source_ids = item.get("sources")
        membership = item.get("source_membership")
        if (
            not isinstance(source_ids, list)
            or source_ids != sorted(set(str(value) for value in source_ids))
            or not source_ids
            or not set(source_ids) <= allowed_source_ids
            or not isinstance(membership, list)
        ):
            raise CompositeError(
                f"candidate source attribution is invalid: {category}/{rule}"
            )
        membership_by_source = {
            str(raw_witness.get("source_id", "")): raw_witness
            for raw_witness in membership
            if isinstance(raw_witness, dict)
        }
        if (
            len(membership_by_source) != len(membership)
            or "" in membership_by_source
            or sorted(membership_by_source) != source_ids
        ):
            raise CompositeError(
                f"candidate membership coverage is invalid: {category}/{rule}"
            )
        for source_id in source_ids:
            source = selected_provenance.get(source_id)
            if not isinstance(source, dict):
                raise CompositeError(
                    f"candidate attribution source is not selected: {source_id}"
                )
            blockers: list[str] = []
            validate_membership(
                rule, membership_by_source[source_id], source, blockers
            )
            if blockers:
                raise CompositeError("; ".join(blockers))
            witnesses[(source_id, rule)] = copy.deepcopy(
                membership_by_source[source_id]
            )
        attribution[rule] = set(source_ids)
    return attribution, witnesses


def aggregate_rules(
    *,
    category: dict[str, Any],
    rules_by_category: dict[str, list[str]],
    attribution_by_category: dict[str, dict[str, set[str]]],
    source_root: pathlib.Path,
) -> tuple[list[str], dict[str, set[str]], set[str]]:
    category_id = str(category["id"])
    components = [str(item) for item in category.get("aggregate_of", [])]
    if not components or any(item not in rules_by_category for item in components):
        raise CompositeError(f"aggregate component coverage is invalid: {category_id}")
    rules: set[str] = set()
    attribution: dict[str, set[str]] = defaultdict(set)
    for component in components:
        rules.update(rules_by_category[component])
        for rule, source_ids in attribution_by_category[component].items():
            attribution[rule].update(source_ids)

    overlay_rules: set[str] = set()
    overlay = str(category.get("manual_overlay_path", "")).strip()
    if overlay:
        overlay_path = source_root / overlay
        try:
            overlay_rules = builder.parse_local_domain_text(
                overlay_path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, builder.BuildError) as exc:
            raise CompositeError(
                f"aggregate overlay is invalid: {category_id}: {exc}"
            ) from exc
        rules.update(overlay_rules)
        overlay_id = f"{category_id}:manual-overlay"
        for rule in overlay_rules:
            attribution[rule].add(overlay_id)

    for field in ("exclude_rules_path", "allow_rules_path"):
        raw_path = str(category.get(field, "")).strip()
        if not raw_path:
            continue
        try:
            removed = builder.parse_local_domain_text(
                (source_root / raw_path).read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, builder.BuildError) as exc:
            raise CompositeError(
                f"aggregate filter is invalid: {category_id}/{field}: {exc}"
            ) from exc
        rules.difference_update(removed)

    ordered = sorted(rules, key=builder.rule_sort_key)
    return (
        ordered,
        {rule: set(attribution.get(rule, set())) for rule in ordered},
        overlay_rules,
    )


def provenance_for_aggregate(
    category: dict[str, Any],
    rules: list[str],
) -> dict[str, Any]:
    category_id = str(category["id"])
    components = [str(item) for item in category.get("aggregate_of", [])]
    rule_set = set(rules)
    return {
        "source_id": f"{category_id}:aggregate",
        "type": "aggregate",
        "configured_source_sha256": builder.configured_source_digest(
            {
                "type": "aggregate",
                "category": category_id,
                "aggregate_of": components,
            }
        ),
        "authority": "owner-controlled",
        "trust_tier": "derived",
        "license": "inherits-components",
        "owner": "crescentln",
        "revision_strategy": "derived-from-locked-components",
        "requested_refs": components,
        "resolved_ref": category_id,
        "content_sha256": hashlib.sha256(
            "\n".join(rules).encode("utf-8")
        ).hexdigest(),
        "byte_count": sum(len(rule.encode("utf-8")) + 1 for rule in rules),
        "used_cache": False,
        "cache_mode": "aggregate",
        "parser_stats": {
            "accepted_rule_count": len(rules),
            "rule_type_counts": builder.rule_type_counts(rule_set),
        },
        "accepted_rules_merkle_root": builder.rule_set_merkle_root(rule_set),
        "accepted_rules_merkle_leaf_count": len(rules),
        "components": components,
        "critical": True,
        "no_cache_publish": True,
        "snapshot_origin": "derived-composite",
    }


def witness_for_rules(source_id: str, rule: str, rules: set[str]) -> dict[str, Any]:
    ordered, levels = builder.build_rule_merkle_levels(rules)
    try:
        index = ordered.index(rule)
    except ValueError as exc:
        raise CompositeError(f"membership rule is absent: {source_id}/{rule}") from exc
    cursor = index
    proof: list[dict[str, str]] = []
    for level in levels[:-1]:
        if cursor % 2:
            sibling_index = cursor - 1
            side = "left"
        else:
            sibling_index = cursor + 1 if cursor + 1 < len(level) else cursor
            side = "right"
        proof.append({"side": side, "sha256": level[sibling_index].hex()})
        cursor //= 2
    return {
        "source_id": source_id,
        "leaf_index": index,
        "leaf_count": len(ordered),
        "proof": proof,
    }


def render_templates(dist: pathlib.Path) -> None:
    categories = templates.load_categories(dist / "policy_reference.json")
    stash_categories = templates.load_index_categories(dist / "index.json")
    raw_base = (
        "https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist"
    )
    outputs = {
        "recommended_openclash.yaml": templates.render_openclash_template(
            categories, raw_base, 86400, "PROXY"
        ),
        "recommended_surge.conf": templates.render_surge_template(
            categories, raw_base, 86400, "PROXY"
        ),
        "recommended_stash.yaml": templates.render_stash_template(
            categories, raw_base, 86400, "PROXY"
        ),
        "recommended_stash_native.yaml": templates.render_stash_native_template(
            stash_categories, raw_base, 86400, "PROXY"
        ),
    }
    for name, content in outputs.items():
        (dist / name).write_text(content, encoding="utf-8")


def write_changelog(
    *, dist: pathlib.Path, baseline_dist: pathlib.Path, generated_at_utc: str
) -> None:
    current = index_rows(read_json(dist / "index.json"), "composite")
    baseline = index_rows(read_json(baseline_dist / "index.json"), "baseline")
    conflicts = read_json(dist / "conflicts.json")
    fetch = read_json(dist / "fetch_report.json")
    changes: list[tuple[str, int, int, int]] = []
    for category in sorted(set(current) | set(baseline)):
        old = int(baseline.get(category, {}).get("rule_count", 0))
        new = int(current.get(category, {}).get("rule_count", 0))
        if old != new:
            changes.append((category, old, new, new - old))
    changes.sort(key=lambda item: (-abs(item[3]), item[0]))
    lines = [
        "# Ruleset Dist Changelog",
        "",
        "Auto-generated summary for `ruleset/dist` updates.",
        "",
        f"## {generated_at_utc}",
        "",
        f"- Category Count: {len(current)}",
        "- Conflict Summary: "
        f"total={int(conflicts.get('conflict_count', 0))}, "
        f"gated_cross_action={int(conflicts.get('cross_action_conflict_count', 0))}, "
        "informational_cross_action="
        f"{int(conflicts.get('informational_cross_action_conflict_count', 0))}, "
        f"high={int(conflicts.get('high_severity_conflict_count', 0))}",
        "- Fetch Summary: "
        f"network={int(fetch.get('network_success_count', 0))}, "
        f"offline_cache={int(fetch.get('offline_cache_count', 0))}, "
        f"fallback_cache={int(fetch.get('fallback_cache_count', 0))}",
    ]
    if changes:
        lines.append("- Top Rule Count Changes:")
        lines.extend(
            f"- `{category}`: {old} -> {new} ({delta:+d})"
            for category, old, new, delta in changes[:20]
        )
    else:
        lines.append("- Top Rule Count Changes: none")
    (dist / "CHANGELOG.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_composite(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_shadow_outputs(args)
    generated_at_utc = parse_generated_at(args.generated_at_utc)
    if not SHA1_RE.fullmatch(args.exact_main_sha):
        raise CompositeError("exact main SHA is invalid")
    plan = read_json(args.plan)
    if (
        plan.get("schema") != PLAN_SCHEMA
        or plan.get("planner_policy") != PLANNER_POLICY
        or plan.get("mode") != "shadow-only"
        or plan.get("enforcement_ready") is not False
        or plan.get("exact_main_sha") != args.exact_main_sha
    ):
        raise CompositeError("isolation plan safety mode is invalid")
    verify_digest(plan, "plan_fingerprint", "isolation plan")
    stable_selection = plan.get("stable_selection")
    if (
        not isinstance(stable_selection, dict)
        or stable_selection.get("schema") != SELECTION_SCHEMA
        or digest_payload(stable_selection)
        != plan.get("stable_selection_fingerprint")
        or stable_selection.get("composite_identity_ready") is not False
        or stable_selection.get("two_cycle_enforcement_eligible") is not False
    ):
        raise CompositeError("stable isolation selection is invalid")

    config = read_json(args.source_config)
    policy = read_json(args.policy)
    contracts = read_json(args.category_contracts)
    registry = read_json(args.source_registry)
    if digest_payload(config) != plan.get("source_config_sha256"):
        raise CompositeError("source config differs from isolation plan")
    if digest_payload(registry) != plan.get("source_registry_sha256"):
        raise CompositeError("source registry differs from isolation plan")
    builder.SOURCE_REGISTRY = registry

    baseline_index = read_json(args.lkg_dist / "index.json")
    candidate_index = read_json(args.candidate_dist / "index.json")
    baseline_rows = index_rows(baseline_index, "LKG")
    candidate_rows = index_rows(candidate_index, "candidate")
    if digest_payload(baseline_index) != plan.get("baseline_index_sha256"):
        raise CompositeError("LKG index differs from isolation plan")
    if digest_payload(candidate_index) != plan.get("candidate_index_sha256"):
        raise CompositeError("candidate index differs from isolation plan")
    lkg_binding = read_json(args.lkg_binding)
    try:
        lkg_identities, lkg_anchor = validate_category_lkg_binding(
            lkg_binding,
            exact_main_sha=args.exact_main_sha,
            baseline_dist=args.lkg_dist,
            baseline_index=baseline_index,
            source_config=config,
            source_registry=registry,
        )
    except Exception as exc:
        raise CompositeError(f"category LKG binding is invalid: {exc}") from exc
    if (
        lkg_binding.get("binding_sha256")
        != plan.get("category_lkg_binding_sha256")
        or lkg_anchor.get("anchor_sha256")
        != plan.get("category_lkg_anchor_sha256")
    ):
        raise CompositeError("category LKG anchor differs from isolation plan")
    legacy_rows = lkg_binding.get("legacy_provenance_exception", {}).get(
        "derived_sources"
    )
    if not isinstance(legacy_rows, list):
        raise CompositeError("category LKG legacy provenance mapping is invalid")
    legacy_config_digests = {
        str(item.get("source_id", "")): str(
            item.get("derived_configured_source_sha256", "")
        )
        for item in legacy_rows
        if isinstance(item, dict)
    }
    if len(legacy_config_digests) != len(legacy_rows) or "" in legacy_config_digests:
        raise CompositeError("category LKG legacy provenance mapping is not exact")
    try:
        candidate_identities = category_output_identities(
            args.candidate_dist, candidate_index
        )
    except CategoryLkgBindingError as exc:
        raise CompositeError(str(exc)) from exc

    categories, components, _dependents = category_graph(config)
    config_rows = {
        str(raw.get("id", "")): raw
        for raw in config.get("categories", [])
        if isinstance(raw, dict)
    }
    decisions = decision_rows(plan)
    if (
        set(decisions)
        != categories
        or set(baseline_rows) != categories
        or set(candidate_rows) != categories
    ):
        raise CompositeError("composite category coverage is not exact")

    baseline_provenance_payload = read_json(
        args.lkg_dist / "source_provenance.json"
    )
    candidate_provenance_payload = read_json(
        args.candidate_dist / "source_provenance.json"
    )
    baseline_provenance = provenance_rows(
        baseline_provenance_payload, "LKG"
    )
    candidate_provenance = provenance_rows(
        candidate_provenance_payload, "candidate"
    )
    if digest_payload(candidate_provenance_payload) != plan.get(
        "source_provenance_sha256"
    ):
        raise CompositeError("candidate provenance differs from isolation plan")
    observation_summary = isolation_observation_summary(
        artifact=read_json(args.isolation_evidence),
        plan=plan,
        source_config=config,
        baseline_index=baseline_index,
        candidate_index=candidate_index,
        candidate_provenance=candidate_provenance_payload,
    )

    selected_lock, selected_lock_sha256, selected_repositories = selected_source_lock(
        plan=plan,
        baseline_lock=read_json(args.lkg_dist / "sources.lock.json"),
        candidate_lock=read_json(args.candidate_dist / "sources.lock.json"),
        generated_at_utc=generated_at_utc,
    )
    bindings_payload = canonical_source_bindings(config)
    bindings = bindings_payload.get("bindings", {})
    if not isinstance(bindings, dict):
        raise CompositeError("canonical source bindings are invalid")

    delta_payload = read_json(args.candidate_dist / "rule_delta.json")
    raw_delta_rows = {
        str(item.get("category", "")): item
        for item in delta_payload.get("categories", [])
        if isinstance(item, dict)
    }

    rules_by_category: dict[str, list[str]] = {}
    attribution_by_category: dict[str, dict[str, set[str]]] = {}
    source_meta_by_category: dict[str, list[dict[str, Any]]] = {}
    membership_witnesses: dict[tuple[str, str], dict[str, Any]] = {}
    selected_provenance: dict[str, dict[str, Any]] = {}
    origin_by_category: dict[str, str] = {}

    for category in config_rows:
        raw_category = config_rows[category]
        decision = decisions[category]
        selection = str(decision.get("selection", ""))
        is_aggregate = bool(components[category])
        if not is_aggregate:
            if selection in {"candidate-category", "candidate-equivalent-category"}:
                source_dist = args.candidate_dist
                source_row = candidate_rows[category]
                identity = candidate_identities[category]
                provenance_source = candidate_provenance
                origin = "observed-candidate"
            elif selection == "published-category-lkg":
                source_dist = args.lkg_dist
                source_row = baseline_rows[category]
                identity = lkg_identities[category]
                provenance_source = baseline_provenance
                origin = "published-lkg"
            else:
                raise CompositeError(
                    f"unsupported leaf selection: {category}/{selection}"
                )
            for field in (
                "selected_snapshot_sha256",
                "selected_normalized_rules_sha256",
                "selected_rule_count",
                "selected_output_bundle_sha256",
            ):
                identity_field = {
                    "selected_snapshot_sha256": "snapshot_sha256",
                    "selected_normalized_rules_sha256": "normalized_rules_sha256",
                    "selected_rule_count": "rule_count",
                    "selected_output_bundle_sha256": "output_bundle_sha256",
                }[field]
                if decision.get(field) != identity.get(identity_field):
                    raise CompositeError(
                        f"selected category identity is invalid: {category}/{field}"
                    )
            rules = read_rules(source_dist, category)
            rules_by_category[category] = rules
            source_meta = source_row.get("sources")
            if not isinstance(source_meta, list) or any(
                not isinstance(item, dict) for item in source_meta
            ):
                raise CompositeError(f"category source metadata is invalid: {category}")
            source_meta_by_category[category] = copy.deepcopy(source_meta)
            configured_sources = raw_category.get("sources", [])
            if not isinstance(configured_sources, list):
                raise CompositeError(f"category sources are invalid: {category}")
            configured_ids: set[str] = set()
            for source_index, source in enumerate(configured_sources):
                if not isinstance(source, dict):
                    raise CompositeError(f"configured source is invalid: {category}")
                source_id = builder.make_source_id(category, source_index, source)
                configured_ids.add(source_id)
                row = provenance_source.get(source_id)
                if not isinstance(row, dict):
                    raise CompositeError(f"selected provenance is absent: {source_id}")
                validate_configured_source(
                    source=source,
                    source_id=source_id,
                    provenance=row,
                    legacy_config_digest=(
                        legacy_config_digests.get(source_id, "")
                        if origin == "published-lkg"
                        else ""
                    ),
                )
                selected = copy.deepcopy(row)
                selected["snapshot_origin"] = origin
                selected_provenance[source_id] = selected
            meta_ids = {
                str(item.get("source_id", "")) for item in source_meta
            }
            if meta_ids != configured_ids:
                raise CompositeError(
                    f"category source metadata coverage is invalid: {category}"
                )
            if origin == "observed-candidate":
                attribution, witnesses = raw_delta_attribution(
                    category=category,
                    before_rules=set(read_rules(args.lkg_dist, category)),
                    after_rules=set(rules),
                    candidate_delta_rows=raw_delta_rows,
                    selected_provenance=selected_provenance,
                    allowed_source_ids=configured_ids,
                )
                attribution_by_category[category] = attribution
                membership_witnesses.update(witnesses)
            else:
                attribution_by_category[category] = {}
            origin_by_category[category] = origin
            continue

        if selection == "published-category-lkg":
            rules_by_category[category] = read_rules(args.lkg_dist, category)
            attribution_by_category[category] = {}
            source_meta = baseline_rows[category].get("sources")
            if not isinstance(source_meta, list):
                raise CompositeError(f"aggregate source metadata is invalid: {category}")
            source_meta_by_category[category] = copy.deepcopy(source_meta)
            for source_id in (
                f"{category}:aggregate",
                f"{category}:manual-overlay",
            ):
                row = baseline_provenance.get(source_id)
                if row is None and source_id.endswith(":manual-overlay"):
                    continue
                if not isinstance(row, dict):
                    raise CompositeError(
                        f"aggregate LKG provenance is absent: {source_id}"
                    )
                selected = copy.deepcopy(row)
                selected["snapshot_origin"] = "published-lkg"
                selected_provenance[source_id] = selected
            origin_by_category[category] = "published-lkg"
            continue
        if selection != "derived-recompute-required":
            raise CompositeError(
                f"unsupported aggregate selection: {category}/{selection}"
            )
        rules, attribution, overlay_rules = aggregate_rules(
            category=raw_category,
            rules_by_category=rules_by_category,
            attribution_by_category=attribution_by_category,
            source_root=args.source_root,
        )
        baseline_rules = set(read_rules(args.lkg_dist, category))
        if baseline_rules - set(rules):
            raise CompositeError(
                f"derived aggregate contains removals without absence proof: {category}"
            )
        additions = set(rules) - baseline_rules
        for rule in additions:
            if not attribution.get(rule):
                raise CompositeError(
                    f"derived aggregate addition lacks attribution: {category}/{rule}"
                )
        rules_by_category[category] = rules
        attribution_by_category[category] = {
            rule: set(attribution.get(rule, set()))
            for rule in additions
        }
        components_for_category = [str(item) for item in components[category]]
        source_meta: list[dict[str, Any]] = [
            {
                "source_id": f"{category}:aggregate:{component}",
                "type": "aggregate",
                "authority": "owner-controlled",
                "trust_tier": "derived",
                "ref": component,
                "resolved_revision": None,
                "content_sha256": "",
                "used_cache": False,
                "rule_count": len(rules_by_category[component]),
            }
            for component in components_for_category
        ]
        overlay_id = f"{category}:manual-overlay"
        if overlay_rules:
            overlay_row = candidate_provenance.get(overlay_id)
            candidate_meta = {
                str(item.get("source_id", "")): item
                for item in candidate_rows[category].get("sources", [])
                if isinstance(item, dict)
            }.get(overlay_id)
            if not isinstance(overlay_row, dict) or not isinstance(candidate_meta, dict):
                raise CompositeError(f"aggregate overlay evidence is absent: {category}")
            binding = bindings.get(overlay_id)
            if (
                not isinstance(binding, dict)
                or overlay_row.get("configured_source_sha256")
                != binding.get("configured_source_sha256")
                or overlay_row.get("accepted_rules_merkle_root")
                != builder.rule_set_merkle_root(overlay_rules)
            ):
                raise CompositeError(f"aggregate overlay identity is invalid: {category}")
            selected_overlay = copy.deepcopy(overlay_row)
            selected_overlay["snapshot_origin"] = "exact-main-overlay"
            selected_provenance[overlay_id] = selected_overlay
            source_meta.append(copy.deepcopy(candidate_meta))
            for rule in additions & overlay_rules:
                witness = witness_for_rules(overlay_id, rule, overlay_rules)
                blockers: list[str] = []
                validate_membership(rule, witness, selected_overlay, blockers)
                if blockers:
                    raise CompositeError("; ".join(blockers))
                membership_witnesses[(overlay_id, rule)] = witness
        source_meta_by_category[category] = source_meta
        selected_provenance[f"{category}:aggregate"] = provenance_for_aggregate(
            raw_category, rules
        )
        origin_by_category[category] = "derived-composite"

    if set(rules_by_category) != categories:
        raise CompositeError("materialized rule coverage is not exact")
    provenance_payload = {
        "generated_at_utc": generated_at_utc,
        "source_count": len(selected_provenance),
        "source_lock_sha256": selected_lock_sha256,
        "sources": [
            selected_provenance[source_id]
            for source_id in sorted(selected_provenance)
        ],
    }
    try:
        validate_source_provenance(
            provenance_payload, selected_lock_sha256, selected_repositories
        )
    except CategoryLkgBindingError as exc:
        raise CompositeError(str(exc)) from exc

    published_lkg_sources = sum(
        1
        for row in selected_provenance.values()
        if row.get("snapshot_origin") == "published-lkg"
    )
    candidate_sources = sum(
        1
        for row in selected_provenance.values()
        if row.get("snapshot_origin") == "observed-candidate"
    )
    fetch_report = {
        "generated_at_utc": generated_at_utc,
        "url_count": 0,
        "network_success_count": 0,
        "primary_success_count": 0,
        "mirror_success_count": 0,
        "offline_cache_count": 0,
        "fallback_cache_count": 0,
        "fallback_events": [],
        "attempts": [],
        "materialization_mode": "frozen-verified-snapshots",
        "materialization_fetch_count": 0,
        "source_health_status": "unknown",
        "source_health_complete": False,
        "source_health_basis": (
            "frozen-composite-snapshots-not-current-live-fetch-health"
        ),
        "upstream_observation": observation_summary,
        "published_lkg_source_count": published_lkg_sources,
        "observed_candidate_source_count": candidate_sources,
    }
    context = builder.PreselectedBuildContext(
        generated_at_utc=generated_at_utc,
        source_lock=selected_lock,
        source_provenance=list(provenance_payload["sources"]),
        rules_by_category=rules_by_category,
        source_meta_by_category=source_meta_by_category,
        attribution_by_category=attribution_by_category,
        membership_witnesses=membership_witnesses,
        fetch_report=fetch_report,
    )
    code = builder.build_all_staged(
        config_path=args.source_config,
        policy_path=args.policy,
        source_registry_path=args.source_registry,
        category_contracts_path=args.category_contracts,
        source_lock_path=None,
        baseline_dist_dir=args.lkg_dist,
        dist_dir=args.output_dist,
        cache_dir=pathlib.Path(tempfile.gettempdir()) / "project-g-composite-cache-unused",
        offline=True,
        fail_on_conflicts=False,
        fail_on_cross_action_conflicts=True,
        preselected_context=context,
    )
    if code != 0:
        raise CompositeError(f"composite build failed with exit code {code}")
    render_templates(args.output_dist)
    write_changelog(
        dist=args.output_dist,
        baseline_dist=args.lkg_dist,
        generated_at_utc=generated_at_utc,
    )
    manifest = read_json(args.output_dist / "candidate_manifest.json")
    manifest.update(
        {
            "source_commit_sha": args.exact_main_sha,
            "materialization_mode": "upstream-isolation-composite",
            "materializer_policy": MATERIALIZER_POLICY,
            "stable_selection_fingerprint": plan[
                "stable_selection_fingerprint"
            ],
            "category_lkg_anchor_sha256": plan[
                "category_lkg_anchor_sha256"
            ],
        }
    )
    (args.output_dist / "candidate_manifest.json").write_bytes(
        canonical_bytes(manifest)
    )

    try:
        actual_identities = category_output_identities(
            args.output_dist, read_json(args.output_dist / "index.json")
        )
    except CategoryLkgBindingError as exc:
        raise CompositeError(str(exc)) from exc
    category_identity_rows: list[dict[str, Any]] = []
    for category in sorted(categories):
        selection = str(decisions[category]["selection"])
        actual = actual_identities[category]
        if selection != "derived-recompute-required":
            expected = (
                candidate_identities[category]
                if selection
                in {"candidate-category", "candidate-equivalent-category"}
                else lkg_identities[category]
            )
            if actual != expected:
                raise CompositeError(
                    f"selected complete category bundle did not reproduce: {category}"
                )
        category_identity_rows.append(
            {
                "category": category,
                "selection": selection,
                "snapshot_origin": origin_by_category[category],
                "snapshot_sha256": actual["snapshot_sha256"],
                "normalized_rules_sha256": actual[
                    "normalized_rules_sha256"
                ],
                "rule_count": actual["rule_count"],
                "output_bundle_sha256": actual["output_bundle_sha256"],
                "recommended_action": actual["recommended_action"],
                "recommended_priority": actual["recommended_priority"],
                "contract_sha256": actual["contract_sha256"],
            }
        )

    conflicts = read_json(args.output_dist / "conflicts.json")
    output_manifest = directory_manifest(args.output_dist)
    dist_tree_sha256 = digest_payload(output_manifest)
    changed_categories = read_json(
        args.output_dist / "rule_delta.json"
    ).get("changed_categories", [])
    review: dict[str, Any] = {
        "schema": REVIEW_SCHEMA,
        "mode": "shadow-only",
        "materialization_valid": True,
        "validation_complete": False,
        "publishable": False,
        "enforcement_ready": False,
        "materializer_policy": MATERIALIZER_POLICY,
        "exact_main_sha": args.exact_main_sha,
        "stable_selection_fingerprint": plan["stable_selection_fingerprint"],
        "category_lkg_anchor_sha256": plan["category_lkg_anchor_sha256"],
        "dist_tree_sha256": dist_tree_sha256,
        "changed_categories": changed_categories,
        "category_count": len(category_identity_rows),
        "candidate_category_count": sum(
            1
            for row in category_identity_rows
            if row["snapshot_origin"] == "observed-candidate"
        ),
        "published_lkg_category_count": sum(
            1
            for row in category_identity_rows
            if row["snapshot_origin"] == "published-lkg"
        ),
        "derived_category_count": sum(
            1
            for row in category_identity_rows
            if row["snapshot_origin"] == "derived-composite"
        ),
        "cross_action_conflict_count": int(
            conflicts.get("cross_action_conflict_count", 0)
        ),
        "high_severity_conflict_count": int(
            conflicts.get("high_severity_conflict_count", 0)
        ),
        "fallback_cache_count": 0,
        "source_health_status": "unknown",
        "source_health_complete": False,
        "licensing_assertions_complete": False,
        "isolation_observation_summary_sha256": observation_summary[
            "summary_sha256"
        ],
        "isolation_blocker_count": observation_summary["blocker_count"],
        "isolated_source_ids": observation_summary["isolated_source_ids"],
        "quarantined_categories": observation_summary[
            "quarantined_categories"
        ],
        "held_categories": observation_summary["held_categories"],
        "complete_category_bundles": True,
        "repository_atomicity_preserved": True,
        "category_removals_allowed": False,
    }
    review["review_sha256"] = digest_payload(review)

    content_identity_payload: dict[str, Any] = {
        "schema": "project-g-upstream-isolation-content-identity-v1",
        "identity_kind": "selected-complete-category-output-v1",
        "materializer_policy": MATERIALIZER_POLICY,
        "source_config_sha256": digest_payload(config),
        "policy_sha256": digest_payload(policy),
        "category_contracts_sha256": digest_payload(contracts),
        "source_registry_sha256": digest_payload(registry),
        "selected_source_lock_sha256": selected_lock_sha256,
        "category_selections": category_identity_rows,
        "semantic_digest": manifest["semantic_digest"],
    }
    content_identity = digest_payload(content_identity_payload)
    observation_identity_payload: dict[str, Any] = {
        "schema": "project-g-upstream-isolation-observation-identity-v1",
        "exact_main_sha": args.exact_main_sha,
        "generated_at_utc": generated_at_utc,
        "plan_fingerprint": plan["plan_fingerprint"],
        "stable_selection_fingerprint": plan["stable_selection_fingerprint"],
        "category_lkg_anchor_sha256": plan["category_lkg_anchor_sha256"],
        "selected_source_provenance_sha256": digest_payload(
            provenance_payload
        ),
        "isolation_observation_summary_sha256": observation_summary[
            "summary_sha256"
        ],
        "dist_tree_sha256": dist_tree_sha256,
        "review_sha256": review["review_sha256"],
    }
    observation_identity = digest_payload(observation_identity_payload)
    composite: dict[str, Any] = {
        "schema": COMPOSITE_SCHEMA,
        "mode": "shadow-only",
        "enforcement_ready": False,
        "two_cycle_enforcement_eligible": False,
        "source_health_complete": False,
        "licensing_assertions_complete": False,
        "materializer_policy": MATERIALIZER_POLICY,
        "content_identity_schema": (
            "project-g-upstream-isolation-content-identity-v1"
        ),
        "content_identity_kind": "selected-complete-category-output-v1",
        "observation_identity_schema": (
            "project-g-upstream-isolation-observation-identity-v1"
        ),
        "observation_identity_kind": "exact-shadow-observation-v1",
        "exact_main_sha": args.exact_main_sha,
        "generated_at_utc": generated_at_utc,
        "stable_selection_fingerprint": plan["stable_selection_fingerprint"],
        "category_lkg_anchor_sha256": plan["category_lkg_anchor_sha256"],
        "source_config_sha256": digest_payload(config),
        "policy_sha256": digest_payload(policy),
        "category_contracts_sha256": digest_payload(contracts),
        "source_registry_sha256": digest_payload(registry),
        "selected_source_lock_sha256": selected_lock_sha256,
        "selected_source_provenance_sha256": digest_payload(
            provenance_payload
        ),
        "category_selections": category_identity_rows,
        "semantic_digest": manifest["semantic_digest"],
        "dist_tree_sha256": dist_tree_sha256,
        "dist_file_count": len(output_manifest),
        "review_sha256": review["review_sha256"],
        "isolation_observation_summary_sha256": observation_summary[
            "summary_sha256"
        ],
        "observation_evidence_identity": observation_identity,
    }
    composite["composite_content_identity"] = content_identity
    return composite, review


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Materialize one complete shadow ruleset from repository-atomic "
            "candidate categories and immutable published category LKGs."
        )
    )
    parser.add_argument("--plan", type=pathlib.Path, required=True)
    parser.add_argument("--isolation-evidence", type=pathlib.Path, required=True)
    parser.add_argument("--lkg-binding", type=pathlib.Path, required=True)
    parser.add_argument("--candidate-dist", type=pathlib.Path, required=True)
    parser.add_argument("--lkg-dist", type=pathlib.Path, required=True)
    parser.add_argument("--source-config", type=pathlib.Path, required=True)
    parser.add_argument("--policy", type=pathlib.Path, required=True)
    parser.add_argument("--source-registry", type=pathlib.Path, required=True)
    parser.add_argument("--category-contracts", type=pathlib.Path, required=True)
    parser.add_argument("--source-root", type=pathlib.Path, required=True)
    parser.add_argument("--exact-main-sha", required=True)
    parser.add_argument("--generated-at-utc", required=True)
    parser.add_argument("--output-dist", type=pathlib.Path, required=True)
    parser.add_argument("--output-identity", type=pathlib.Path, required=True)
    parser.add_argument("--output-review", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        composite, review = build_composite(args)
        args.output_identity.parent.mkdir(parents=True, exist_ok=True)
        args.output_review.parent.mkdir(parents=True, exist_ok=True)
        args.output_identity.write_bytes(canonical_bytes(composite))
        args.output_review.write_bytes(canonical_bytes(review))
        print(
            "[upstream-composite] "
            f"identity={composite['composite_content_identity']} "
            f"changed={len(review['changed_categories'])} "
            "enforcement_ready=false"
        )
        return 0
    except (CompositeError, AutomatedReviewError, builder.BuildError) as exc:
        print(f"[upstream-composite] error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
