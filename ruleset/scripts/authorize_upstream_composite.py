#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import urllib.parse
from typing import Any

try:
    from ruleset.scripts import verify_upstream_composite as verifier
    from ruleset.scripts.build_category_lkg_binding import (
        CategoryLkgBindingError,
        category_output_identities,
    )
except ModuleNotFoundError:
    import verify_upstream_composite as verifier  # type: ignore[no-redef]
    from build_category_lkg_binding import (  # type: ignore[no-redef]
        CategoryLkgBindingError,
        category_output_identities,
    )


DECISION_SCHEMA = "project-g-upstream-isolation-promotion-decision-v1"
PAIR_SCHEMA = "project-g-upstream-isolation-pair-v1"
PUBLISHED_RECEIPT_SCHEMA = "project-g-published-verification-receipt-v2"
AUTHORIZATION_POLICY = "isolated-source-category-lkg-promotion-v1"
SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+:[^\s]+$")
SEMANTIC_FIELDS = (
    "normalized_rules_sha256",
    "rule_count",
    "recommended_action",
    "recommended_priority",
    "contract_sha256",
)
PREPARED_FILES = {
    "automated-review.json",
    "category-lkg-binding.json",
    "composite-gate-receipt.json",
    "composite-identity.json",
    "composite-review.json",
    "gitleaks-composite.sarif",
    "isolation-evidence.json",
    "ruleset-dist.sha256",
    "ruleset-dist.tar.gz",
    "upstream-isolation-composite-evidence.sha256",
    "upstream-isolation-composite-evidence.tar",
    "upstream-isolation-plan.json",
}


class CompositeAuthorizationError(RuntimeError):
    pass


def read_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        return verifier.read_json_bytes(path.read_bytes(), label)
    except OSError as exc:
        raise CompositeAuthorizationError(f"cannot read {label}: {exc}") from exc


def verify_receipt_digest(
    payload: dict[str, Any], field: str, label: str
) -> str:
    try:
        return verifier.verify_self_digest(payload, field, label)
    except verifier.CompositeVerificationError as exc:
        raise CompositeAuthorizationError(str(exc)) from exc


def validate_pair_receipt(
    payload: dict[str, Any], *, repository: str, expected_main_sha: str
) -> str:
    receipt_sha256 = verify_receipt_digest(payload, "receipt_sha256", "pair receipt")
    if (
        payload.get("schema") != PAIR_SCHEMA
        or payload.get("eligible") is not False
        or payload.get("publication_authority") is not False
        or payload.get("decision") != "REQUIRES_PROMOTION_AUTHORIZATION"
        or payload.get("source_sha") != expected_main_sha
        or payload.get("minimum_cycle_separation_seconds") != 300
        or not isinstance(payload.get("cycle_separation_seconds"), int)
        or payload.get("cycle_separation_seconds") < 300
        or payload.get("allowed_cycle_variant_dist_files")
        != sorted(verifier.VOLATILE_DIST_FILES)
    ):
        raise CompositeAuthorizationError("pair receipt is not authorization-ready")
    changed = verifier.require_sorted_strings(
        payload.get("changed_categories"), "pair changed categories"
    )
    if (
        not changed
        or payload.get("changed_category_count") != len(changed)
        or verifier.require_nonnegative_int(
            payload.get("candidate_category_count"), "pair candidate category count"
        )
        + verifier.require_nonnegative_int(
            payload.get("derived_category_count"), "pair derived category count"
        )
        <= 0
    ):
        raise CompositeAuthorizationError("pair has no isolated publishable delta")
    current = payload.get("current")
    previous = payload.get("previous")
    if not isinstance(current, dict) or not isinstance(previous, dict):
        raise CompositeAuthorizationError("pair remote identities are absent")
    for label, cycle in (("current", current), ("previous", previous)):
        if (
            not isinstance(cycle.get("run_id"), int)
            or cycle.get("run_id") <= 0
            or not isinstance(cycle.get("run_attempt"), int)
            or cycle.get("run_attempt") <= 0
            or not isinstance(cycle.get("artifact_id"), int)
            or cycle.get("artifact_id") <= 0
            or not str(cycle.get("artifact_api_digest", "")).startswith("sha256:")
        ):
            raise CompositeAuthorizationError(f"pair {label} remote identity is invalid")
        verifier.require_sha256(
            str(cycle.get("artifact_api_digest", "")).removeprefix("sha256:"),
            f"pair {label} API digest",
        )
        for field in (
            "artifact_zip_sha256",
            "outer_evidence_sha256",
            "dist_archive_sha256",
            "dist_tree_sha256",
            "observation_evidence_identity",
        ):
            verifier.require_sha256(cycle.get(field), f"pair {label} {field}")
        verifier.parse_timestamp(
            cycle.get("inner_attestation_tlog_timestamp"),
            f"pair {label} inner TLog timestamp",
        )
        verifier.parse_timestamp(
            cycle.get("outer_attestation_tlog_timestamp"),
            f"pair {label} outer TLog timestamp",
        )
    if (
        current["run_id"] == previous["run_id"]
        or current["artifact_id"] == previous["artifact_id"]
    ):
        raise CompositeAuthorizationError("pair remote identities are not distinct")
    if not verifier.REPOSITORY_RE.fullmatch(repository):
        raise CompositeAuthorizationError("repository must be owner/name")
    return receipt_sha256


def validate_prepared(
    prepared: pathlib.Path,
    pair: dict[str, Any],
    *,
    expected_main_sha: str,
) -> tuple[
    dict[str, bytes],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    verifier.validate_exact_directory(prepared, PREPARED_FILES, "prepared composite")
    archive = prepared / "ruleset-dist.tar.gz"
    archive_sha256 = verifier.sha256_file(archive)
    checksum_rows = verifier.parse_checksum_bytes(
        (prepared / "ruleset-dist.sha256").read_bytes(),
        expected_names={"ruleset-dist.tar.gz"},
        label="prepared dist checksum",
    )
    if (
        checksum_rows["ruleset-dist.tar.gz"] != archive_sha256
        or pair["current"]["dist_archive_sha256"] != archive_sha256
    ):
        raise CompositeAuthorizationError("prepared dist archive binding is invalid")
    evidence_sha256 = verifier.sha256_file(
        prepared / "upstream-isolation-composite-evidence.tar"
    )
    if pair["current"]["outer_evidence_sha256"] != evidence_sha256:
        raise CompositeAuthorizationError("prepared outer evidence binding is invalid")
    dist_files, manifest = verifier.read_dist_tar(archive.read_bytes())
    identity = read_json(prepared / "composite-identity.json", "composite identity")
    review = read_json(prepared / "composite-review.json", "composite review")
    plan = read_json(prepared / "upstream-isolation-plan.json", "isolation plan")
    lkg_binding = read_json(
        prepared / "category-lkg-binding.json", "category LKG binding"
    )
    if (
        identity.get("exact_main_sha") != expected_main_sha
        or identity.get("composite_content_identity")
        != pair.get("composite_content_identity")
        or identity.get("stable_selection_fingerprint")
        != pair.get("stable_selection_fingerprint")
        or identity.get("semantic_digest") != pair.get("semantic_digest")
        or identity.get("selected_source_lock_sha256")
        != pair.get("selected_source_lock_sha256")
        or identity.get("category_lkg_anchor_sha256")
        != pair.get("category_lkg_anchor_sha256")
        or identity.get("dist_tree_sha256") != pair["current"]["dist_tree_sha256"]
        or verifier.digest_payload(manifest) != identity.get("dist_tree_sha256")
        or review.get("changed_categories") != pair.get("changed_categories")
    ):
        raise CompositeAuthorizationError("prepared composite differs from pair receipt")
    return dist_files, identity, review, plan, lkg_binding


def validate_current_contracts(
    *,
    identity: dict[str, Any],
    source_config: dict[str, Any],
    source_registry: dict[str, Any],
    policy: dict[str, Any],
    contracts: dict[str, Any],
) -> None:
    for field, payload in (
        ("source_config_sha256", source_config),
        ("source_registry_sha256", source_registry),
        ("policy_sha256", policy),
        ("category_contracts_sha256", contracts),
    ):
        if identity.get(field) != verifier.digest_payload(payload):
            raise CompositeAuthorizationError(
                f"current repository contract differs from composite: {field}"
            )
    profiles = source_registry.get("authority_profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise CompositeAuthorizationError("source authority registry is invalid")
    for name, profile in profiles.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(profile, dict)
            or not isinstance(profile.get("license"), str)
            or not profile.get("license")
            or not isinstance(profile.get("owner"), str)
            or not profile.get("owner")
        ):
            raise CompositeAuthorizationError("source authority licensing is incomplete")


def validate_category_delta(
    *,
    baseline_dist: pathlib.Path,
    dist_files: dict[str, bytes],
    identity: dict[str, Any],
    review: dict[str, Any],
    plan: dict[str, Any],
) -> tuple[list[str], list[str]]:
    baseline_index = read_json(baseline_dist / "index.json", "baseline index")
    try:
        baseline_identities = category_output_identities(baseline_dist, baseline_index)
    except CategoryLkgBindingError as exc:
        raise CompositeAuthorizationError(f"baseline category identity is invalid: {exc}") from exc
    with tempfile_dist(dist_files) as current_dist:
        current_index = read_json(current_dist / "index.json", "composite index")
        try:
            current_identities = category_output_identities(current_dist, current_index)
        except CategoryLkgBindingError as exc:
            raise CompositeAuthorizationError(
                f"composite category identity is invalid: {exc}"
            ) from exc
    if set(baseline_identities) != set(current_identities):
        raise CompositeAuthorizationError("category removals or additions are not authorized")
    computed_changed = sorted(
        category
        for category in current_identities
        if any(
            baseline_identities[category].get(field)
            != current_identities[category].get(field)
            for field in SEMANTIC_FIELDS
        )
    )
    declared_changed = verifier.require_sorted_strings(
        review.get("changed_categories"), "review changed categories"
    )
    if not computed_changed or computed_changed != declared_changed:
        raise CompositeAuthorizationError("semantic changed-category set is not reproducible")
    selections = identity.get("category_selections")
    if not isinstance(selections, list):
        raise CompositeAuthorizationError("composite selections are absent")
    origin_by_category = {
        str(row.get("category", "")): str(row.get("snapshot_origin", ""))
        for row in selections
        if isinstance(row, dict)
    }
    if any(
        origin_by_category.get(category)
        not in {"observed-candidate", "derived-composite"}
        for category in computed_changed
    ):
        raise CompositeAuthorizationError("changed category is not from an accepted slice")
    accepted = verifier.require_sorted_strings(
        plan.get("accepted_candidate_categories"), "accepted candidate categories"
    )
    selected_candidate = sorted(
        category
        for category, origin in origin_by_category.items()
        if origin == "observed-candidate"
    )
    if (
        not set(selected_candidate).issubset(accepted)
        or set(accepted)
        & (
            set(verifier.require_sorted_strings(plan.get("held_categories"), "held categories"))
            | set(
                verifier.require_sorted_strings(
                    plan.get("quarantined_categories"), "quarantined categories"
                )
            )
        )
        or plan.get("global_hold") is not False
        or verifier.require_sorted_strings(
            plan.get("unscoped_blockers"), "unscoped blockers"
        )
    ):
        raise CompositeAuthorizationError("accepted category containment is invalid")
    return computed_changed, selected_candidate


class tempfile_dist:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.temp: Any = None
        self.path: pathlib.Path | None = None

    def __enter__(self) -> pathlib.Path:
        import tempfile

        self.temp = tempfile.TemporaryDirectory(prefix="project-g-authorize-dist.")
        self.path = pathlib.Path(self.temp.name)
        for relative, payload in self.files.items():
            path = pathlib.PurePosixPath(relative)
            if path.is_absolute() or ".." in path.parts:
                raise CompositeAuthorizationError("unsafe composite dist path")
            target = self.path.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return self.path

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.temp is not None:
            self.temp.cleanup()


def validate_selected_provenance(
    *,
    dist_files: dict[str, bytes],
    identity: dict[str, Any],
    source_registry: dict[str, Any],
    selected_candidate_categories: list[str],
) -> tuple[int, int]:
    raw = dist_files.get("source_provenance.json")
    if raw is None:
        raise CompositeAuthorizationError("composite source provenance is absent")
    provenance = verifier.read_json_bytes(raw, "composite source provenance")
    rows = provenance.get("sources")
    if (
        not isinstance(rows, list)
        or provenance.get("source_count") != len(rows)
        or provenance.get("source_lock_sha256")
        != identity.get("selected_source_lock_sha256")
        or verifier.digest_payload(provenance)
        != identity.get("selected_source_provenance_sha256")
    ):
        raise CompositeAuthorizationError("composite source provenance binding is invalid")
    profiles = source_registry.get("authority_profiles")
    if not isinstance(profiles, dict):
        raise CompositeAuthorizationError("source authority profiles are absent")
    selected_counts = {category: 0 for category in selected_candidate_categories}
    observed_count = 0
    licensed_count = 0
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise CompositeAuthorizationError("source provenance row is invalid")
        source_id = str(row.get("source_id", ""))
        if not SOURCE_ID_RE.fullmatch(source_id) or source_id in seen_ids:
            raise CompositeAuthorizationError("source provenance IDs are invalid")
        seen_ids.add(source_id)
        origin = str(row.get("snapshot_origin", ""))
        if origin not in {
            "observed-candidate",
            "published-lkg",
            "derived-composite",
            "exact-main-overlay",
        }:
            raise CompositeAuthorizationError("source provenance origin is invalid")
        if origin == "derived-composite":
            components = row.get("components")
            if (
                not source_id.endswith(":aggregate")
                or row.get("type") != "aggregate"
                or row.get("authority") != "owner-controlled"
                or row.get("license") != "inherits-components"
                or row.get("owner") != "crescentln"
                or row.get("revision_strategy")
                != "derived-from-locked-components"
                or row.get("used_cache") is not False
                or row.get("cache_mode") != "aggregate"
                or not isinstance(components, list)
                or not components
                or any(not isinstance(item, str) or not item for item in components)
            ):
                raise CompositeAuthorizationError(
                    f"derived provenance is invalid: {source_id}"
                )
            verifier.require_sha256(
                row.get("content_sha256"), f"source {source_id} content"
            )
            continue
        if origin == "exact-main-overlay":
            requested = row.get("requested_refs")
            resolved_ref = str(row.get("resolved_ref", ""))
            path = pathlib.PurePosixPath(resolved_ref)
            profile = profiles.get("owner-controlled")
            if (
                not source_id.endswith(":manual-overlay")
                or row.get("type") != "local_domain"
                or row.get("authority") != "owner-controlled"
                or not isinstance(profile, dict)
                or row.get("license") != profile.get("license")
                or row.get("owner") != profile.get("owner")
                or row.get("revision_strategy") != "local-content-sha256"
                or row.get("used_cache") is not False
                or row.get("cache_mode") != "local"
                or not isinstance(requested, list)
                or requested != [resolved_ref]
                or not resolved_ref.startswith("manual/categories/")
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise CompositeAuthorizationError(
                    f"exact-main overlay provenance is invalid: {source_id}"
                )
            verifier.require_sha256(
                row.get("content_sha256"), f"source {source_id} content"
            )
            continue
        if origin != "observed-candidate":
            continue
        observed_count += 1
        category = source_id.split(":", 1)[0]
        if category in selected_counts:
            selected_counts[category] += 1
        authority = str(row.get("authority", ""))
        profile = profiles.get(authority)
        if not isinstance(profile, dict):
            raise CompositeAuthorizationError(
                f"observed source uses an unregistered authority: {source_id}"
            )
        if (
            row.get("license") != profile.get("license")
            or row.get("owner") != profile.get("owner")
            or not isinstance(row.get("license"), str)
            or not row.get("license")
            or row.get("used_cache") is not False
            or row.get("cache_mode") not in {"network", "local"}
        ):
            raise CompositeAuthorizationError(
                f"observed source health or licensing is invalid: {source_id}"
            )
        verifier.require_sha256(row.get("content_sha256"), f"source {source_id} content")
        strategy = str(profile.get("revision_strategy", ""))
        allowed_hosts = sorted(str(item) for item in profile.get("allowed_hosts", []))
        limits = row.get("limits")
        if (
            not isinstance(limits, dict)
            or sorted(str(item) for item in limits.get("allowed_hosts", []))
            != allowed_hosts
        ):
            raise CompositeAuthorizationError(
                f"observed source authority limits are invalid: {source_id}"
            )
        resolved_ref = str(row.get("resolved_ref", ""))
        requested = row.get("requested_refs")
        if (
            not isinstance(requested, list)
            or not requested
            or any(not isinstance(item, str) or not item for item in requested)
        ):
            raise CompositeAuthorizationError(
                f"observed source transport identity is invalid: {source_id}"
            )
        if strategy == "github-commit-lock":
            repository = str(row.get("repository", ""))
            revision = str(row.get("resolved_revision", ""))
            if (
                not verifier.REPOSITORY_RE.fullmatch(repository)
                or not verifier.SHA1_RE.fullmatch(revision)
                or profile.get("owner") != repository
                or not resolved_ref.startswith(
                    f"https://github.com/{repository}/blob/{revision}/"
                )
                or row.get("cache_mode") != "network"
            ):
                raise CompositeAuthorizationError(
                    f"observed source commit lock is invalid: {source_id}"
                )
        elif strategy == "https-validators-and-content-sha256":
            parsed = urllib.parse.urlparse(resolved_ref)
            if (
                parsed.scheme != "https"
                or parsed.hostname not in set(allowed_hosts)
                or row.get("cache_mode") != "network"
                or any(not item.startswith("https://") for item in requested)
            ):
                raise CompositeAuthorizationError(
                    f"observed HTTPS source binding is invalid: {source_id}"
                )
        elif strategy == "local-content-sha256":
            resolved_path = pathlib.PurePosixPath(resolved_ref)
            if (
                row.get("cache_mode") not in {"local", "network"}
                or not resolved_ref
                or resolved_path.is_absolute()
                or ".." in resolved_path.parts
            ):
                raise CompositeAuthorizationError(
                    f"observed local source binding is invalid: {source_id}"
                )
        else:
            raise CompositeAuthorizationError(
                f"observed source revision strategy is invalid: {source_id}"
            )
        if profile.get("no_cache_publish") is True and row.get("cache_mode") != "network":
            raise CompositeAuthorizationError(
                f"observed source violates no-cache publication: {source_id}"
            )
        licensed_count += 1
    missing = sorted(category for category, count in selected_counts.items() if count == 0)
    if missing or licensed_count != observed_count:
        raise CompositeAuthorizationError(
            "accepted candidate categories lack healthy licensed source provenance: "
            + ", ".join(missing)
        )
    return observed_count, licensed_count


def validate_lkg_remote(
    *,
    lkg_binding: dict[str, Any],
    receipt: dict[str, Any],
    attestation_path: pathlib.Path,
    archive_path: pathlib.Path,
    repository: str,
) -> str:
    receipt_sha256 = verify_receipt_digest(
        receipt, "receipt_sha256", "live LKG verification receipt"
    )
    anchor = lkg_binding.get("lkg_anchor")
    if not isinstance(anchor, dict):
        raise CompositeAuthorizationError("LKG anchor is absent")
    source_attestation = anchor.get("source_attestation")
    publication_receipt = anchor.get("publication_receipt")
    if not isinstance(source_attestation, dict) or not isinstance(
        publication_receipt, dict
    ):
        raise CompositeAuthorizationError("LKG proof chain is incomplete")
    if (
        receipt.get("schema") != PUBLISHED_RECEIPT_SCHEMA
        or receipt.get("repository") != repository
        or receipt.get("release_commit_sha") != anchor.get("release_commit_sha")
        or receipt.get("release_id") != anchor.get("release_id")
        or receipt.get("release_tag") != anchor.get("release_tag")
        or receipt.get("candidate_source_sha")
        != source_attestation.get("source_sha")
        or receipt.get("archive_sha256")
        != anchor.get("archive_asset", {}).get("sha256")
        or receipt.get("checksum_sha256")
        != anchor.get("checksum_asset", {}).get("sha256")
        or receipt.get("category_count") != lkg_binding.get("category_count")
        or receipt_sha256 != publication_receipt.get("receipt_sha256")
    ):
        raise CompositeAuthorizationError("live LKG proof differs from embedded binding")
    archive_sha256 = verifier.sha256_file(archive_path)
    if archive_sha256 != source_attestation.get("subject_sha256"):
        raise CompositeAuthorizationError("LKG archive differs from source attestation")
    try:
        verifier.validate_attestation(
            attestation_path.read_bytes(),
            label="LKG source attestation",
            repository=repository,
            workflow_path=".github/workflows/source-discovery.yml",
            source_sha=str(source_attestation.get("source_sha", "")),
            run_id=verifier.require_positive_int(
                source_attestation.get("run_id"), "LKG source run ID"
            ),
            run_attempt=verifier.require_positive_int(
                source_attestation.get("run_attempt"), "LKG source run attempt"
            ),
            subject_sha256=archive_sha256,
        )
    except (OSError, verifier.CompositeVerificationError) as exc:
        raise CompositeAuthorizationError(f"LKG source attestation is invalid: {exc}") from exc
    return receipt_sha256


def write_output_dist(dist_files: dict[str, bytes], destination: pathlib.Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or not destination.is_dir():
        raise CompositeAuthorizationError("authorized output directory is unsafe")
    if any(destination.iterdir()):
        raise CompositeAuthorizationError("authorized output directory must be empty")
    for relative, payload in dist_files.items():
        path = pathlib.PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts:
            raise CompositeAuthorizationError("unsafe authorized dist path")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate an independent positive promotion decision for a previously "
            "verified upstream-isolation composite pair."
        )
    )
    parser.add_argument("--pair-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--prepared-dir", type=pathlib.Path, required=True)
    parser.add_argument("--baseline-dist", type=pathlib.Path, required=True)
    parser.add_argument("--source-config", type=pathlib.Path, required=True)
    parser.add_argument("--source-registry", type=pathlib.Path, required=True)
    parser.add_argument("--policy", type=pathlib.Path, required=True)
    parser.add_argument("--category-contracts", type=pathlib.Path, required=True)
    parser.add_argument("--lkg-verified-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--lkg-attestation", type=pathlib.Path, required=True)
    parser.add_argument("--lkg-archive", type=pathlib.Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-main-sha", required=True)
    parser.add_argument("--output-decision", type=pathlib.Path, required=True)
    parser.add_argument("--output-dist", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not verifier.SHA1_RE.fullmatch(args.expected_main_sha):
            raise CompositeAuthorizationError("expected main SHA is invalid")
        pair = read_json(args.pair_receipt, "pair receipt")
        pair_receipt_sha256 = validate_pair_receipt(
            pair,
            repository=args.repository,
            expected_main_sha=args.expected_main_sha,
        )
        dist_files, identity, review, plan, lkg_binding = validate_prepared(
            args.prepared_dir,
            pair,
            expected_main_sha=args.expected_main_sha,
        )
        source_config = read_json(args.source_config, "source config")
        source_registry = read_json(args.source_registry, "source registry")
        policy = read_json(args.policy, "policy")
        contracts = read_json(args.category_contracts, "category contracts")
        validate_current_contracts(
            identity=identity,
            source_config=source_config,
            source_registry=source_registry,
            policy=policy,
            contracts=contracts,
        )
        changed_categories, selected_candidate_categories = validate_category_delta(
            baseline_dist=args.baseline_dist,
            dist_files=dist_files,
            identity=identity,
            review=review,
            plan=plan,
        )
        observed_source_count, licensed_source_count = validate_selected_provenance(
            dist_files=dist_files,
            identity=identity,
            source_registry=source_registry,
            selected_candidate_categories=selected_candidate_categories,
        )
        lkg_receipt = read_json(
            args.lkg_verified_receipt, "live LKG verification receipt"
        )
        lkg_receipt_sha256 = validate_lkg_remote(
            lkg_binding=lkg_binding,
            receipt=lkg_receipt,
            attestation_path=args.lkg_attestation,
            archive_path=args.lkg_archive,
            repository=args.repository,
        )
        candidate_manifest = verifier.read_json_bytes(
            dist_files["candidate_manifest.json"], "composite candidate manifest"
        )
        if (
            candidate_manifest.get("changed") is not True
            or candidate_manifest.get("changed_categories") != changed_categories
            or candidate_manifest.get("fallback_cache_count") != 0
            or candidate_manifest.get("cache_blocked_source_ids") != []
            or candidate_manifest.get("budget_exceeded") != []
        ):
            raise CompositeAuthorizationError("composite manifest is not publishable")
        decision: dict[str, Any] = {
            "schema": DECISION_SCHEMA,
            "authorization_policy": AUTHORIZATION_POLICY,
            "eligible": True,
            "publication_authority": True,
            "source_sha": args.expected_main_sha,
            "pair_receipt_sha256": pair_receipt_sha256,
            "composite_content_identity": pair["composite_content_identity"],
            "stable_payload_sha256": pair["stable_payload_sha256"],
            "containment_boundary_sha256": pair["containment_boundary_sha256"],
            "stable_selection_fingerprint": pair[
                "stable_selection_fingerprint"
            ],
            "category_lkg_anchor_sha256": pair["category_lkg_anchor_sha256"],
            "selected_source_lock_sha256": pair["selected_source_lock_sha256"],
            "semantic_digest": pair["semantic_digest"],
            "changed_categories": changed_categories,
            "changed_category_count": len(changed_categories),
            "selected_candidate_categories": selected_candidate_categories,
            "observed_candidate_source_count": observed_source_count,
            "licensed_candidate_source_count": licensed_source_count,
            "complete_blocker_mapping": True,
            "unscoped_blocker_count": 0,
            "lkg_verified_receipt_sha256": lkg_receipt_sha256,
            "current": pair["current"],
            "previous": pair["previous"],
        }
        decision["decision_sha256"] = verifier.digest_payload(decision)
        write_output_dist(dist_files, args.output_dist)
        args.output_decision.parent.mkdir(parents=True, exist_ok=True)
        args.output_decision.write_bytes(verifier.canonical_bytes(decision))
        print(
            "[upstream-composite-authorize] "
            f"eligible=true changed={len(changed_categories)} "
            f"sources={observed_source_count} "
            f"decision={decision['decision_sha256']}"
        )
        return 0
    except (
        CompositeAuthorizationError,
        verifier.CompositeVerificationError,
        OSError,
    ) as exc:
        print(f"[upstream-composite-authorize] error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
