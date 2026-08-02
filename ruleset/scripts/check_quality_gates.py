#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any


class GateError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[gates] {message}")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GateError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"invalid json: {path}: {exc}") from exc


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_approved_drift(
    path: pathlib.Path,
    baseline_path: pathlib.Path,
) -> dict[str, dict[str, Any]]:
    payload = read_json(path)
    expected_hash = str(payload.get("baseline_policy_sha256", "")).strip().lower()
    if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
        raise GateError(f"{path}: baseline_policy_sha256 must be a lowercase SHA-256 digest")

    actual_hash = sha256_file(baseline_path)
    if actual_hash != expected_hash:
        log(
            "approved drift is inactive because the baseline hash changed: "
            f"expected={expected_hash} actual={actual_hash}"
        )
        return {}

    raw_approvals = payload.get("approvals")
    if not isinstance(raw_approvals, list):
        raise GateError(f"{path}: approvals must be an array")

    approvals: dict[str, dict[str, Any]] = {}
    for idx, raw in enumerate(raw_approvals):
        if not isinstance(raw, dict):
            raise GateError(f"{path}: approvals[{idx}] must be an object")
        category_id = str(raw.get("category", "")).strip()
        reason = str(raw.get("reason", "")).strip()
        if not category_id or not reason:
            raise GateError(f"{path}: approvals[{idx}] requires category and reason")
        if category_id in approvals:
            raise GateError(f"{path}: duplicate approval for category '{category_id}'")
        try:
            before = int(raw["before"])
            after_min = int(raw["after_min"])
            after_max = int(raw["after_max"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GateError(
                f"{path}: approvals[{idx}] requires integer before, after_min, and after_max"
            ) from exc
        if min(before, after_min, after_max) < 0 or after_min > after_max:
            raise GateError(f"{path}: invalid count bounds for category '{category_id}'")
        approvals[category_id] = {
            "before": before,
            "after_min": after_min,
            "after_max": after_max,
            "reason": reason,
        }

    return approvals


def read_count_thresholds(path: pathlib.Path) -> tuple[dict[str, int], dict[str, int]]:
    payload = read_json(path)

    minimum_raw: Any
    if isinstance(payload.get("minimum_rule_counts"), dict):
        minimum_raw = payload.get("minimum_rule_counts", {})
    else:
        minimum_raw = payload

    if not isinstance(minimum_raw, dict):
        raise GateError(f"{path}: minimum counts must be an object")

    warning_raw = payload.get("warning_rule_counts", {}) if isinstance(payload, dict) else {}
    if warning_raw is None:
        warning_raw = {}
    if not isinstance(warning_raw, dict):
        raise GateError(f"{path}: warning counts must be an object")

    def parse_threshold_map(raw: dict[str, Any], *, field_name: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for key, value in raw.items():
            category_id = str(key).strip()
            if not category_id:
                continue
            try:
                count_value = int(value)
            except (TypeError, ValueError) as exc:
                raise GateError(f"{path}: invalid {field_name} for '{category_id}'") from exc
            if count_value < 0:
                raise GateError(f"{path}: {field_name} for '{category_id}' must be >= 0")
            out[category_id] = count_value
        return out

    minimum_counts = parse_threshold_map(minimum_raw, field_name="minimum count")
    warning_counts = parse_threshold_map(warning_raw, field_name="warning count")

    for category_id, warn_value in warning_counts.items():
        min_value = minimum_counts.get(category_id)
        if min_value is not None and warn_value < min_value:
            raise GateError(
                f"{path}: warning count for '{category_id}' ({warn_value}) must be >= minimum ({min_value})"
            )

    return minimum_counts, warning_counts


def parse_rule_counts(payload: dict[str, Any], source_path: pathlib.Path) -> dict[str, int]:
    categories = payload.get("categories")
    if not isinstance(categories, list):
        raise GateError(f"{source_path}: 'categories' must be an array")

    out: dict[str, int] = {}
    for idx, row in enumerate(categories):
        if not isinstance(row, dict):
            raise GateError(f"{source_path}: categories[{idx}] must be an object")
        category_id = str(row.get("id", "")).strip()
        if not category_id:
            continue
        try:
            count = int(row.get("rule_count", 0))
        except (TypeError, ValueError) as exc:
            raise GateError(f"{source_path}: invalid rule_count for '{category_id}'") from exc
        out[category_id] = count
    return out


def compute_count_drift(
    baseline_counts: dict[str, int],
    current_counts: dict[str, int],
    max_change_pct: float,
    min_abs_delta: int,
    min_baseline_rules: int,
    approved_drift: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    changes: list[dict[str, Any]] = []
    violations: list[str] = []

    common_ids = sorted(set(baseline_counts) & set(current_counts))
    for category_id in common_ids:
        before = baseline_counts[category_id]
        after = current_counts[category_id]
        delta = after - before
        abs_delta = abs(delta)
        pct = (abs_delta * 100.0 / before) if before > 0 else (100.0 if after > 0 else 0.0)

        changes.append(
            {
                "id": category_id,
                "before": before,
                "after": after,
                "delta": delta,
                "delta_pct": pct,
            }
        )

        if before < min_baseline_rules:
            continue
        if abs_delta < min_abs_delta:
            continue
        if pct > max_change_pct:
            approval = (approved_drift or {}).get(category_id)
            if (
                approval is not None
                and before == int(approval["before"])
                and int(approval["after_min"]) <= after <= int(approval["after_max"])
            ):
                log(
                    "approved count drift: "
                    f"{category_id} before={before} after={after} reason={approval['reason']}"
                )
                continue
            violations.append(
                f"rule count drift too large: {category_id} before={before} after={after} "
                f"delta={delta:+d} ({pct:.2f}%)"
            )

    removed_ids = sorted(set(baseline_counts) - set(current_counts))
    for category_id in removed_ids:
        before = baseline_counts[category_id]
        violations.append(
            f"category removed from current output: {category_id} (baseline={before})"
        )

    return changes, violations


def resolve_conflict_counts(payload: dict[str, Any]) -> tuple[int, int]:
    has_explicit_counts = (
        "cross_action_conflict_count" in payload
        or "high_severity_conflict_count" in payload
    )
    try:
        cross_action_conflicts = int(payload.get("cross_action_conflict_count", 0))
    except (TypeError, ValueError):
        cross_action_conflicts = 0
    try:
        high_severity_conflicts = int(payload.get("high_severity_conflict_count", 0))
    except (TypeError, ValueError):
        high_severity_conflicts = 0

    if has_explicit_counts:
        return cross_action_conflicts, high_severity_conflicts

    raw_conflicts = payload.get("conflicts", [])
    if not isinstance(raw_conflicts, list):
        return 0, 0

    cross_action_conflicts = 0
    high_severity_conflicts = 0
    for item in raw_conflicts:
        if not isinstance(item, dict):
            continue
        conflict_type = str(item.get("type", "")).strip()
        severity = str(item.get("severity", "")).strip().lower()
        if conflict_type and conflict_type != "same_action_overlap":
            cross_action_conflicts += 1
        if severity == "high":
            high_severity_conflicts += 1
    return cross_action_conflicts, high_severity_conflicts


def validate_source_provenance(path: pathlib.Path) -> list[str]:
    payload = read_json(path)
    raw_sources = payload.get("sources", [])
    if not isinstance(raw_sources, list) or not raw_sources:
        return [f"{path}: sources must be a non-empty array"]
    violations: list[str] = []
    source_ids: set[str] = set()
    required_fields = (
        "source_id",
        "type",
        "authority",
        "trust_tier",
        "license",
        "owner",
        "revision_strategy",
        "resolved_ref",
        "content_sha256",
        "byte_count",
        "used_cache",
        "cache_mode",
        "parser_stats",
        "critical",
        "no_cache_publish",
    )
    for index, raw in enumerate(raw_sources):
        if not isinstance(raw, dict):
            violations.append(f"{path}: sources[{index}] must be an object")
            continue
        missing = [field for field in required_fields if field not in raw]
        if missing:
            violations.append(
                f"{path}: sources[{index}] missing fields: {', '.join(missing)}"
            )
            continue
        source_id = str(raw.get("source_id", "")).strip()
        if not source_id:
            violations.append(f"{path}: sources[{index}] has empty source_id")
        elif source_id in source_ids:
            violations.append(f"{path}: duplicate source_id: {source_id}")
        source_ids.add(source_id)
        digest = str(raw.get("content_sha256", "")).strip().lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            violations.append(f"{path}: {source_id} has invalid content_sha256")
        try:
            byte_count = int(raw.get("byte_count", -1))
        except (TypeError, ValueError):
            byte_count = -1
        if byte_count < 0:
            violations.append(f"{path}: {source_id} has invalid byte_count")
        resolved_ref = str(raw.get("resolved_ref", ""))
        if (
            str(raw.get("type", "")) == "v2fly_dlc"
            and (
                "/master/" in resolved_ref
                or "@master/" in resolved_ref
                or not str(raw.get("resolved_revision", "")).strip()
            )
        ):
            violations.append(
                f"{path}: {source_id} v2fly resolved_ref is not commit locked"
            )
        parser_stats = raw.get("parser_stats")
        if not isinstance(parser_stats, dict):
            violations.append(f"{path}: {source_id} parser_stats must be an object")
    declared_count = payload.get("source_count")
    try:
        declared_count_int = int(declared_count)
    except (TypeError, ValueError):
        declared_count_int = -1
    if declared_count_int != len(raw_sources):
        violations.append(
            f"{path}: source_count={declared_count_int} does not match rows={len(raw_sources)}"
        )
    return violations


def read_plain_rule_file(path: pathlib.Path) -> set[str]:
    if not path.is_file():
        return set()
    return {
        line
        for raw in path.read_text(encoding="utf-8").splitlines()
        if (line := raw.strip()) and not line.startswith(("#", ";"))
    }


def read_openclash_rule_file(path: pathlib.Path) -> set[str]:
    if not path.is_file():
        return set()
    rules: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if (
            not line
            or line in {"payload:", "payload: []"}
            or line.startswith("#")
            or not line.startswith("- ")
        ):
            continue
        value = line[2:].strip()
        if value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1].replace("''", "'")
        rules.add(value)
    return rules


def count_rule_types(rules: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rule in rules:
        rule_type = rule.split(",", 1)[0].strip()
        counts[rule_type] = counts.get(rule_type, 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def validate_client_parity(path: pathlib.Path, expected_categories: set[str]) -> list[str]:
    payload = read_json(path)
    rows = payload.get("categories", [])
    if not isinstance(rows, list):
        return [f"{path}: categories must be an array"]
    violations: list[str] = []
    observed: set[str] = set()
    recomputed_totals = {
        "openclash_effective_rules": 0,
        "surge_effective_rules": 0,
        "surge_lost_rules": 0,
        "stash_effective_rules": 0,
    }
    dist_dir = path.parent
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            violations.append(f"{path}: categories[{index}] must be an object")
            continue
        category_id = str(row.get("category", "")).strip()
        if category_id:
            observed.add(category_id)
        for client in ("openclash", "surge", "stash"):
            client_row = row.get(client)
            if not isinstance(client_row, dict):
                violations.append(f"{path}: {category_id}/{client} must be an object")
                continue
            for field_name in ("effective_rule_count", "lost_rule_count", "lost_rule_types"):
                if field_name not in client_row:
                    violations.append(
                        f"{path}: {category_id}/{client} missing {field_name}"
                    )
        contract = row.get("contract", {})
        if not isinstance(contract, dict):
            violations.append(f"{path}: {category_id} contract must be an object")
            continue
        for client in ("openclash", "surge", "stash"):
            client_contract = contract.get(client, {})
            client_row = row.get(client, {})
            if not isinstance(client_contract, dict) or not isinstance(
                client_row,
                dict,
            ):
                continue
            try:
                effective_count = int(client_row.get("effective_rule_count", 0))
                lost_count = int(client_row.get("lost_rule_count", 0))
                max_loss_count = int(client_contract["max_loss_count"])
                max_loss_pct = float(client_contract["max_loss_pct"])
            except (KeyError, TypeError, ValueError):
                violations.append(
                    f"{path}: {category_id}/{client} has invalid loss budget"
                )
                continue
            denominator = effective_count + lost_count
            loss_pct = (
                lost_count * 100.0 / denominator if denominator else 0.0
            )
            if lost_count > max_loss_count or loss_pct > max_loss_pct:
                violations.append(
                    f"{path}: {category_id}/{client} loss budget exceeded "
                    f"count={lost_count}/{max_loss_count} "
                    f"pct={loss_pct:.6g}/{max_loss_pct:.6g}"
                )
        surge_contract = contract.get("surge", {})
        if not isinstance(surge_contract, dict):
            violations.append(f"{path}: {category_id}/contract.surge must be an object")
            continue
        declared_unsupported = {
            str(item)
            for item in surge_contract.get("unsupported_rule_types", [])
        }
        surge_row = row.get("surge", {})
        observed_lost = {
            str(item)
            for item in (
                surge_row.get("lost_rule_types", {})
                if isinstance(surge_row, dict)
                else {}
            )
        }
        if observed_lost - declared_unsupported:
            violations.append(
                f"{path}: {category_id}/surge lost undeclared rule types "
                f"{sorted(observed_lost - declared_unsupported)}"
            )
        openclash_path = dist_dir / "openclash" / f"{category_id}.yaml"
        surge_path = dist_dir / "surge" / f"{category_id}.list"
        stash_path = dist_dir / "stash" / f"{category_id}.list"
        for client_name, client_path in (
            ("openclash", openclash_path),
            ("surge", surge_path),
            ("stash", stash_path),
        ):
            if not client_path.is_file():
                violations.append(
                    f"{path}: {category_id}/{client_name} output is missing: "
                    f"{client_path}"
                )
        if not (
            openclash_path.is_file()
            and surge_path.is_file()
            and stash_path.is_file()
        ):
            continue

        openclash_rules = read_openclash_rule_file(openclash_path)
        surge_rules = read_plain_rule_file(surge_path)
        stash_rules = read_plain_rule_file(stash_path)
        expected_surge = {
            rule
            for rule in openclash_rules
            if rule.split(",", 1)[0] not in declared_unsupported
        }
        expected_lost = openclash_rules - expected_surge
        if stash_rules != openclash_rules:
            violations.append(
                f"{path}: {category_id}/stash content differs from OpenClash "
                f"missing={len(openclash_rules - stash_rules)} "
                f"extra={len(stash_rules - openclash_rules)}"
            )
        if surge_rules != expected_surge:
            violations.append(
                f"{path}: {category_id}/surge content violates compatibility contract "
                f"missing={len(expected_surge - surge_rules)} "
                f"extra={len(surge_rules - expected_surge)}"
            )
        stash_classical_path = (
            dist_dir / "stash" / "classical" / f"{category_id}.list"
        )
        stash_domainset_path = (
            dist_dir / "stash" / "domainset" / f"{category_id}.txt"
        )
        stash_ipcidr_path = (
            dist_dir / "stash" / "ipcidr" / f"{category_id}.txt"
        )
        if not all(
            item.is_file()
            for item in (
                stash_classical_path,
                stash_domainset_path,
                stash_ipcidr_path,
            )
        ):
            violations.append(
                f"{path}: {category_id}/stash native split output is missing"
            )
        else:
            expected_stash_classical = {
                rule
                for rule in openclash_rules
                if not rule.startswith(
                    ("DOMAIN,", "DOMAIN-SUFFIX,", "IP-CIDR,", "IP-CIDR6,")
                )
            }
            expected_stash_domains = {
                (
                    f"+.{rule.split(',', 1)[1]}"
                    if rule.startswith("DOMAIN-SUFFIX,")
                    else rule.split(",", 1)[1]
                )
                for rule in openclash_rules
                if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,"))
            }
            expected_stash_cidrs = {
                rule.split(",", 2)[1]
                for rule in openclash_rules
                if rule.startswith(("IP-CIDR,", "IP-CIDR6,"))
            }
            actual_stash_classical = read_plain_rule_file(
                stash_classical_path
            )
            actual_stash_domains = read_plain_rule_file(stash_domainset_path)
            actual_stash_cidrs = read_plain_rule_file(stash_ipcidr_path)
            if actual_stash_classical != expected_stash_classical:
                violations.append(
                    f"{path}: {category_id}/stash classical split mismatch"
                )
            if actual_stash_domains != expected_stash_domains:
                violations.append(
                    f"{path}: {category_id}/stash domainset split mismatch"
                )
            if actual_stash_cidrs != expected_stash_cidrs:
                violations.append(
                    f"{path}: {category_id}/stash ipcidr split mismatch"
                )

        actual = {
            "openclash": (len(openclash_rules), 0, {}),
            "surge": (
                len(surge_rules),
                len(expected_lost),
                count_rule_types(expected_lost),
            ),
            "stash": (len(stash_rules), 0, {}),
        }
        for client_name, (
            effective_count,
            lost_count,
            lost_types,
        ) in actual.items():
            client_row = row.get(client_name, {})
            if not isinstance(client_row, dict):
                continue
            if int(client_row.get("effective_rule_count", -1)) != effective_count:
                violations.append(
                    f"{path}: {category_id}/{client_name} effective count does not "
                    "match output"
                )
            if int(client_row.get("lost_rule_count", -1)) != lost_count:
                violations.append(
                    f"{path}: {category_id}/{client_name} lost count does not "
                    "match output"
                )
            if client_row.get("lost_rule_types", {}) != lost_types:
                violations.append(
                    f"{path}: {category_id}/{client_name} lost rule types do not "
                    "match output"
                )
        recomputed_totals["openclash_effective_rules"] += len(openclash_rules)
        recomputed_totals["surge_effective_rules"] += len(surge_rules)
        recomputed_totals["surge_lost_rules"] += len(expected_lost)
        recomputed_totals["stash_effective_rules"] += len(stash_rules)
    if observed != expected_categories:
        violations.append(
            f"{path}: category coverage mismatch missing={sorted(expected_categories - observed)} "
            f"extra={sorted(observed - expected_categories)}"
        )
    declared_totals = payload.get("clients", {})
    if not isinstance(declared_totals, dict):
        violations.append(f"{path}: clients must be an object")
    else:
        for field_name, observed_total in recomputed_totals.items():
            try:
                declared_total = int(declared_totals.get(field_name, -1))
            except (TypeError, ValueError):
                declared_total = -1
            if declared_total != observed_total:
                violations.append(
                    f"{path}: clients.{field_name}={declared_total} does not "
                    f"match outputs={observed_total}"
                )
    return violations


def validate_resolved_contracts(path: pathlib.Path, expected_categories: set[str]) -> list[str]:
    payload = read_json(path)
    categories = payload.get("categories", {})
    if not isinstance(categories, dict):
        return [f"{path}: categories must be an object"]
    violations: list[str] = []
    observed = {str(item) for item in categories}
    if observed != expected_categories:
        violations.append(
            f"{path}: category coverage mismatch missing={sorted(expected_categories - observed)} "
            f"extra={sorted(observed - expected_categories)}"
        )
    required = (
        "max_add",
        "max_remove",
        "max_pct",
        "max_new_apex",
        "max_new_regex",
        "max_new_cidr",
        "max_informational_overlap_delta",
        "allowed_source_tiers",
        "allowed_rule_types",
        "required_action",
        "must_be_disjoint_from",
        "auto_promotion_policy",
        "per_client_support",
    )
    for category_id, raw in categories.items():
        if not isinstance(raw, dict):
            violations.append(f"{path}: category {category_id} must be an object")
            continue
        missing = [field for field in required if field not in raw]
        if missing:
            violations.append(
                f"{path}: category {category_id} missing {', '.join(missing)}"
            )
    return violations


def validate_candidate_manifest(
    path: pathlib.Path,
    *,
    require_promotable: bool,
) -> list[str]:
    payload = read_json(path)
    violations: list[str] = []
    semantic_digest = str(payload.get("semantic_digest", "")).strip().lower()
    if len(semantic_digest) != 64 or any(
        ch not in "0123456789abcdef" for ch in semantic_digest
    ):
        violations.append(f"{path}: semantic_digest must be a lowercase SHA-256")
    if require_promotable:
        if int(payload.get("fallback_cache_count", 0)) != 0:
            violations.append(f"{path}: promotion forbids fallback cache")
        if payload.get("cache_blocked_source_ids"):
            violations.append(f"{path}: promotion contains cache-blocked sources")
        if payload.get("budget_exceeded"):
            violations.append(
                f"{path}: promotion exceeds category budgets: "
                + "; ".join(str(item) for item in payload["budget_exceeded"])
            )
        if bool(payload.get("source_head_advanced_after_lock", False)):
            violations.append(
                f"{path}: active source head advanced after the candidate lock"
            )
        if not bool(payload.get("changed", False)):
            violations.append(f"{path}: promotion candidate has no semantic changes")
    if bool(payload.get("source_head_advanced_after_lock", False)) and bool(
        payload.get("auto_promotion_eligible", False)
    ):
        violations.append(
            f"{path}: stale source lock cannot be automatically promoted"
        )
    return violations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Quality gates for ruleset pipeline outputs.")
    parser.add_argument(
        "--current",
        type=pathlib.Path,
        required=True,
        help="Current policy reference JSON path (usually ruleset/dist/policy_reference.json).",
    )
    parser.add_argument(
        "--baseline",
        type=pathlib.Path,
        default=None,
        help="Previous policy reference JSON path for drift comparison.",
    )
    parser.add_argument(
        "--fetch-report",
        type=pathlib.Path,
        required=True,
        help="Fetch report JSON path (ruleset/dist/fetch_report.json).",
    )
    parser.add_argument(
        "--conflicts",
        type=pathlib.Path,
        required=True,
        help="Conflicts report JSON path (ruleset/dist/conflicts.json).",
    )
    parser.add_argument(
        "--max-change-pct",
        type=float,
        default=20.0,
        help="Maximum allowed percentage change per category (default: 20).",
    )
    parser.add_argument(
        "--min-abs-delta",
        type=int,
        default=50,
        help="Minimum absolute delta before applying pct gate (default: 50).",
    )
    parser.add_argument(
        "--min-baseline-rules",
        type=int,
        default=100,
        help="Minimum baseline size before applying pct gate (default: 100).",
    )
    parser.add_argument(
        "--max-fetch-fallbacks",
        type=int,
        default=0,
        help="Maximum allowed fallback_cache_count in fetch report (default: 0).",
    )
    parser.add_argument(
        "--max-cross-action-conflicts",
        type=int,
        default=0,
        help="Maximum allowed cross-action conflicts (default: 0).",
    )
    parser.add_argument(
        "--max-high-severity-conflicts",
        type=int,
        default=0,
        help="Maximum allowed high severity conflicts (default: 0).",
    )
    parser.add_argument(
        "--minimums",
        type=pathlib.Path,
        default=None,
        help="JSON file defining minimum rule counts per category.",
    )
    parser.add_argument(
        "--approved-drift",
        type=pathlib.Path,
        default=None,
        help=(
            "Optional one-time drift approval bound to the exact baseline policy SHA-256 "
            "and per-category before/after counts."
        ),
    )
    parser.add_argument(
        "--source-provenance",
        type=pathlib.Path,
        default=None,
        help="Source provenance JSON to validate.",
    )
    parser.add_argument(
        "--client-parity",
        type=pathlib.Path,
        default=None,
        help="Per-client effective rule counts and losses.",
    )
    parser.add_argument(
        "--contracts",
        type=pathlib.Path,
        default=None,
        help="Resolved category semantic contracts.",
    )
    parser.add_argument(
        "--candidate-manifest",
        type=pathlib.Path,
        default=None,
        help="Candidate manifest with risk and semantic digest.",
    )
    parser.add_argument(
        "--require-promotable",
        action="store_true",
        help="Require a changed, cache-clean candidate suitable for evidence-gated promotion.",
    )
    parser.add_argument(
        "--require-auto-promotion-eligible",
        action="store_true",
        help="Require candidate_manifest.auto_promotion_eligible=true.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    violations: list[str] = []

    current_payload = read_json(args.current)
    current_counts = parse_rule_counts(current_payload, args.current)
    current_category_ids = set(current_counts)
    log(f"current categories: {len(current_counts)}")

    if args.minimums is not None:
        minimum_counts, warning_counts = read_count_thresholds(args.minimums)
        log(f"minimum-count checks: {len(minimum_counts)} categories")
        for category_id in sorted(minimum_counts):
            minimum = minimum_counts[category_id]
            current = current_counts.get(category_id, 0)
            if current < minimum:
                violations.append(
                    f"minimum rule count not met: {category_id} current={current} required>={minimum}"
                )

        if warning_counts:
            log(f"warning-count checks: {len(warning_counts)} categories")
            for category_id in sorted(warning_counts):
                warning_value = warning_counts[category_id]
                current = current_counts.get(category_id, 0)
                minimum = minimum_counts.get(category_id, 0)
                if current < warning_value and current >= minimum:
                    log(
                        "warning threshold breached: "
                        f"{category_id} current={current} warning>={warning_value}"
                    )

    baseline_counts: dict[str, int] | None = None
    if args.baseline is not None and args.baseline.exists():
        baseline_payload = read_json(args.baseline)
        baseline_counts = parse_rule_counts(baseline_payload, args.baseline)

    if args.contracts is not None and baseline_counts is not None:
        log(
            "resolved category contracts provided; skip legacy uniform count-drift "
            "thresholds in favor of per-category candidate budgets"
        )
        for category_id in sorted(set(baseline_counts) - set(current_counts)):
            violations.append(
                "category removed from current output: "
                f"{category_id} (baseline={baseline_counts[category_id]})"
            )
    elif args.baseline is None:
        log("baseline not provided, skip rule-count drift gate")
    elif not args.baseline.exists():
        log(f"baseline file not found, skip rule-count drift gate: {args.baseline}")
    else:
        assert baseline_counts is not None
        approved_drift: dict[str, dict[str, Any]] = {}
        if args.approved_drift is not None:
            approved_drift = read_approved_drift(args.approved_drift, args.baseline)
        changes, drift_violations = compute_count_drift(
            baseline_counts=baseline_counts,
            current_counts=current_counts,
            max_change_pct=args.max_change_pct,
            min_abs_delta=args.min_abs_delta,
            min_baseline_rules=args.min_baseline_rules,
            approved_drift=approved_drift,
        )
        top_changes = sorted(changes, key=lambda x: abs(int(x["delta"])), reverse=True)[:8]
        for item in top_changes:
            log(
                "drift "
                f"{item['id']}: {item['before']} -> {item['after']} "
                f"({item['delta']:+d}, {item['delta_pct']:.2f}%)"
            )
        violations.extend(drift_violations)

    fetch_payload = read_json(args.fetch_report)
    try:
        fallback_cache_count = int(fetch_payload.get("fallback_cache_count", 0))
    except (TypeError, ValueError) as exc:
        raise GateError(f"{args.fetch_report}: invalid fallback_cache_count") from exc
    log(
        "fetch report "
        f"network={fetch_payload.get('network_success_count', 0)} "
        f"offline_cache={fetch_payload.get('offline_cache_count', 0)} "
        f"fallback_cache={fallback_cache_count}"
    )
    if fallback_cache_count > args.max_fetch_fallbacks:
        violations.append(
            f"fetch fallback exceeded: fallback_cache_count={fallback_cache_count}, "
            f"limit={args.max_fetch_fallbacks}"
        )

    conflict_payload = read_json(args.conflicts)
    cross_action_conflicts, high_severity_conflicts = resolve_conflict_counts(conflict_payload)
    log(
        "conflicts report "
        f"cross_action={cross_action_conflicts} high_severity={high_severity_conflicts}"
    )
    if cross_action_conflicts > args.max_cross_action_conflicts:
        violations.append(
            f"cross-action conflicts exceeded: {cross_action_conflicts} > {args.max_cross_action_conflicts}"
        )
    if high_severity_conflicts > args.max_high_severity_conflicts:
        violations.append(
            f"high-severity conflicts exceeded: {high_severity_conflicts} > {args.max_high_severity_conflicts}"
        )

    if args.source_provenance is not None:
        violations.extend(validate_source_provenance(args.source_provenance))
    if args.client_parity is not None:
        violations.extend(
            validate_client_parity(args.client_parity, current_category_ids)
        )
    if args.contracts is not None:
        violations.extend(
            validate_resolved_contracts(args.contracts, current_category_ids)
        )
    if args.candidate_manifest is not None:
        violations.extend(
            validate_candidate_manifest(
                args.candidate_manifest,
                require_promotable=args.require_promotable,
            )
        )
        if args.require_auto_promotion_eligible:
            candidate_payload = read_json(args.candidate_manifest)
            if not bool(candidate_payload.get("auto_promotion_eligible", False)):
                violations.append(
                    f"{args.candidate_manifest}: candidate is not eligible for automatic promotion"
                )

    if violations:
        log(f"FAILED with {len(violations)} violation(s):")
        for item in violations:
            log(f"- {item}")
        return 2

    log("all quality gates passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        log(f"error: {exc}")
        raise SystemExit(1) from exc
