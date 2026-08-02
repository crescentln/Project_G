#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import tarfile
from typing import Any

try:
    from ruleset.scripts.check_automated_review import (
        AutomatedReviewError,
        canonical_bytes,
        digest_payload,
        source_lock_identity,
    )
except ModuleNotFoundError:
    from check_automated_review import (  # type: ignore[no-redef]
        AutomatedReviewError,
        canonical_bytes,
        digest_payload,
        source_lock_identity,
    )


BINDING_SCHEMA = "project-g-category-lkg-binding-v1"
BINDING_POLICY = "immutable-release-category-output-bundle-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_URL_RE = re.compile(
    r"^https://github\.com/([^/]+/[^/]+)/actions/runs/([0-9]+)(?:/attempts/([0-9]+))?$"
)
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 1024 * 1024 * 1024
CATEGORY_OUTPUT_ROOTS = (
    pathlib.PurePosixPath("openclash"),
    pathlib.PurePosixPath("stash"),
    pathlib.PurePosixPath("surge"),
    pathlib.PurePosixPath("compat/Clash"),
    pathlib.PurePosixPath("compat/List"),
    pathlib.PurePosixPath("meta"),
)
CATEGORY_OUTPUT_PATH_TEMPLATES = {
    "compat_clash_domainset_path": "compat/Clash/domainset/{category}.txt",
    "compat_clash_ip_path": "compat/Clash/ip/{category}.txt",
    "compat_clash_non_ip_path": "compat/Clash/non_ip/{category}.txt",
    "compat_list_domainset_path": "compat/List/domainset/{category}.conf",
    "compat_list_ip_path": "compat/List/ip/{category}.conf",
    "compat_list_non_ip_path": "compat/List/non_ip/{category}.conf",
    "openclash_domainset_path": "openclash/domainset/{category}.txt",
    "openclash_ip_path": "openclash/ip/{category}.yaml",
    "openclash_ipcidr_path": "openclash/ipcidr/{category}.txt",
    "openclash_non_ip_path": "openclash/non_ip/{category}.yaml",
    "openclash_path": "openclash/{category}.yaml",
    "stash_classical_path": "stash/classical/{category}.list",
    "stash_domainset_path": "stash/domainset/{category}.txt",
    "stash_ipcidr_path": "stash/ipcidr/{category}.txt",
    "stash_path": "stash/{category}.list",
    "surge_domainset_path": "surge/domainset/{category}.conf",
    "surge_ip_path": "surge/ip/{category}.list",
    "surge_non_ip_path": "surge/non_ip/{category}.list",
    "surge_path": "surge/{category}.list",
}
CATEGORY_OUTPUT_PATH_FIELDS = tuple(CATEGORY_OUTPUT_PATH_TEMPLATES)


class CategoryLkgBindingError(RuntimeError):
    pass


def read_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CategoryLkgBindingError(f"invalid JSON: {path}: {exc}") from exc


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative_path(raw: str, label: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or raw != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CategoryLkgBindingError(f"unsafe {label} path: {raw!r}")
    return path


def directory_manifest(root: pathlib.Path) -> list[dict[str, Any]]:
    if not root.is_dir():
        raise CategoryLkgBindingError(f"dist directory is absent: {root}")
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise CategoryLkgBindingError(f"dist tree contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise CategoryLkgBindingError(f"dist tree contains a special file: {path}")
        relative = path.relative_to(root).as_posix()
        safe_relative_path(relative, "dist")
        payload = path.read_bytes()
        rows.append(
            {
                "path": relative,
                "size": len(payload),
                "sha256": sha256_bytes(payload),
            }
        )
    if not rows:
        raise CategoryLkgBindingError("dist tree is empty")
    return rows


def archive_manifest(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    observed: set[str] = set()
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise CategoryLkgBindingError("release archive has too many members")
            total_bytes = 0
            for member in members:
                raw_name = member.name.removeprefix("./")
                member_path = safe_relative_path(raw_name, "archive member")
                if not member_path.parts or member_path.parts[0] != "dist":
                    raise CategoryLkgBindingError(
                        f"archive member is outside dist/: {raw_name}"
                    )
                if member.isdir():
                    continue
                if not member.isfile():
                    raise CategoryLkgBindingError(
                        f"archive contains a link or special file: {raw_name}"
                    )
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise CategoryLkgBindingError(
                        f"archive member exceeds the size limit: {raw_name}"
                    )
                total_bytes += member.size
                if total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                    raise CategoryLkgBindingError(
                        "release archive exceeds the total size limit"
                    )
                relative = pathlib.PurePosixPath(*member_path.parts[1:]).as_posix()
                safe_relative_path(relative, "archive dist")
                if relative in observed:
                    raise CategoryLkgBindingError(
                        f"archive contains duplicate path: {relative}"
                    )
                observed.add(relative)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise CategoryLkgBindingError(
                        f"archive member cannot be read: {raw_name}"
                    )
                payload = extracted.read()
                if len(payload) != member.size:
                    raise CategoryLkgBindingError(
                        f"archive member size is inconsistent: {raw_name}"
                    )
                rows.append(
                    {
                        "path": relative,
                        "size": len(payload),
                        "sha256": sha256_bytes(payload),
                    }
                )
    except (tarfile.TarError, OSError) as exc:
        raise CategoryLkgBindingError(f"invalid release archive: {exc}") from exc
    if not rows:
        raise CategoryLkgBindingError("release archive contains no dist files")
    return sorted(rows, key=lambda item: str(item["path"]))


def archive_json(path: pathlib.Path, relative_path: str) -> dict[str, Any]:
    expected = f"dist/{safe_relative_path(relative_path, 'archive JSON').as_posix()}"
    matches: list[bytes] = []
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                name = member.name.removeprefix("./")
                if name != expected:
                    continue
                if not member.isfile() or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise CategoryLkgBindingError(
                        f"archive JSON member is unsafe: {expected}"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise CategoryLkgBindingError(
                        f"archive JSON member cannot be read: {expected}"
                    )
                matches.append(extracted.read())
    except (tarfile.TarError, OSError) as exc:
        raise CategoryLkgBindingError(f"invalid release archive: {exc}") from exc
    if len(matches) != 1:
        raise CategoryLkgBindingError(
            f"release archive must contain one {expected}"
        )
    try:
        payload = json.loads(matches[0].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CategoryLkgBindingError(
            f"archive JSON member is invalid: {expected}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise CategoryLkgBindingError(
            f"archive JSON member root must be an object: {expected}"
        )
    return payload


def normalized_rules(path: pathlib.Path) -> list[str]:
    try:
        rows = [
            raw.strip()
            for raw in path.read_text(encoding="utf-8").splitlines()
            if raw.strip() and not raw.lstrip().startswith("#")
        ]
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        raise CategoryLkgBindingError(f"invalid category rule file: {path}: {exc}") from exc
    if len(rows) != len(set(rows)):
        raise CategoryLkgBindingError(f"category rules contain duplicates: {path}")
    return sorted(rows)


def validate_source_provenance(
    payload: dict[str, Any],
    source_lock_sha256: str,
    source_lock_repositories: dict[str, Any],
) -> None:
    raw_sources = payload.get("sources")
    source_count = payload.get("source_count")
    if (
        not isinstance(raw_sources, list)
        or any(not isinstance(item, dict) for item in raw_sources)
        or isinstance(source_count, bool)
        or not isinstance(source_count, int)
        or source_count != len(raw_sources)
        or payload.get("source_lock_sha256") != source_lock_sha256
    ):
        raise CategoryLkgBindingError(
            "baseline source provenance identity is inconsistent"
        )
    source_ids = [str(item.get("source_id", "")) for item in raw_sources]
    if any(not source_id for source_id in source_ids) or len(source_ids) != len(
        set(source_ids)
    ):
        raise CategoryLkgBindingError(
            "baseline source provenance IDs must be unique and named"
        )
    rows_by_repository: dict[str, list[dict[str, Any]]] = {}
    for raw in raw_sources:
        repository = str(raw.get("repository", "")).strip()
        if repository:
            rows_by_repository.setdefault(repository, []).append(raw)
    for repository, raw_lock in sorted(source_lock_repositories.items()):
        if not isinstance(raw_lock, dict):
            raise CategoryLkgBindingError(
                f"baseline source lock entry is malformed: {repository}"
            )
        rows = rows_by_repository.get(repository, [])
        binding_count = raw_lock.get("binding_count")
        if (
            isinstance(binding_count, bool)
            or not isinstance(binding_count, int)
            or binding_count <= 0
            or binding_count != len(rows)
        ):
            raise CategoryLkgBindingError(
                f"baseline source lock binding count is inconsistent: {repository}"
            )
        for row in rows:
            if (
                row.get("requested_ref") != raw_lock.get("requested_ref")
                or row.get("resolved_revision")
                != raw_lock.get("resolved_revision")
            ):
                raise CategoryLkgBindingError(
                    f"baseline source provenance lock identity is inconsistent: {repository}"
                )


def category_output_identities(
    dist_dir: pathlib.Path, index: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    raw_categories = index.get("categories")
    if not isinstance(raw_categories, list) or not raw_categories:
        raise CategoryLkgBindingError("index categories must be a non-empty array")
    identities: dict[str, dict[str, Any]] = {}
    path_owners: dict[str, str] = {}
    for raw in raw_categories:
        if not isinstance(raw, dict):
            raise CategoryLkgBindingError("index category rows must be objects")
        category = str(raw.get("id", ""))
        if not category or category in identities:
            raise CategoryLkgBindingError(
                "index categories must be unique and named"
            )
        observed_path_fields = {
            str(key) for key in raw if str(key).endswith("_path")
        }
        if observed_path_fields != set(CATEGORY_OUTPUT_PATH_FIELDS):
            raise CategoryLkgBindingError(
                f"category {category} output path fields are not exact"
            )
        configured_paths: list[str] = []
        for field, template in CATEGORY_OUTPUT_PATH_TEMPLATES.items():
            expected_path = template.format(category=category)
            if raw.get(field) != expected_path:
                raise CategoryLkgBindingError(
                    f"category {category} output path is noncanonical: {field}"
                )
            configured_paths.append(expected_path)
        path_values = set(configured_paths)
        path_values.add(f"meta/{category}.json")
        files: list[dict[str, Any]] = []
        for raw_path in sorted(path_values):
            relative = safe_relative_path(raw_path, f"category {category}")
            if not any(
                relative == root or root in relative.parents
                for root in CATEGORY_OUTPUT_ROOTS
            ):
                raise CategoryLkgBindingError(
                    f"category {category} output is outside a category root: {raw_path}"
                )
            owner = path_owners.get(relative.as_posix())
            if owner is not None:
                raise CategoryLkgBindingError(
                    f"category output has multiple owners: {raw_path}: {owner}, {category}"
                )
            path_owners[relative.as_posix()] = category
            path = dist_dir.joinpath(*relative.parts)
            if path.is_symlink() or not path.is_file():
                raise CategoryLkgBindingError(
                    f"category {category} output is absent or unsafe: {raw_path}"
                )
            payload = path.read_bytes()
            files.append(
                {
                    "path": relative.as_posix(),
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                }
            )

        stash_relative = safe_relative_path(
            str(raw["stash_path"]), f"category {category} Stash"
        )
        rules = normalized_rules(dist_dir.joinpath(*stash_relative.parts))
        declared_count = raw.get("rule_count")
        if (
            isinstance(declared_count, bool)
            or not isinstance(declared_count, int)
            or declared_count != len(rules)
        ):
            raise CategoryLkgBindingError(
                f"category {category} rule count does not match its Stash snapshot"
            )
        raw_action = raw.get("recommended_action")
        action = raw_action.strip() if isinstance(raw_action, str) else ""
        priority = raw.get("recommended_priority")
        contract = raw.get("contract")
        if (
            not action
            or isinstance(priority, bool)
            or not isinstance(priority, int)
            or not isinstance(contract, dict)
        ):
            raise CategoryLkgBindingError(
                f"category {category} policy metadata is malformed"
            )
        identity: dict[str, Any] = {
            "category": category,
            "rule_count": len(rules),
            "normalized_rules_sha256": digest_payload(rules),
            "recommended_action": action,
            "recommended_priority": priority,
            "contract_sha256": digest_payload(contract),
            "files": files,
            "output_bundle_sha256": digest_payload(files),
        }
        identity["snapshot_sha256"] = digest_payload(identity)
        identities[category] = identity

    actual_paths: set[str] = set()
    for relative_root in CATEGORY_OUTPUT_ROOTS:
        root = dist_dir.joinpath(*relative_root.parts)
        if root.is_symlink():
            raise CategoryLkgBindingError(
                f"category output root is a symlink: {relative_root.as_posix()}"
            )
        if not root.exists():
            continue
        if not root.is_dir():
            raise CategoryLkgBindingError(
                f"category output root is not a directory: {relative_root.as_posix()}"
            )
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(dist_dir).as_posix()
            if path.is_symlink():
                raise CategoryLkgBindingError(
                    f"category output contains a symlink: {relative}"
                )
            if path.is_dir():
                continue
            if not path.is_file():
                raise CategoryLkgBindingError(
                    f"category output contains a special file: {relative}"
                )
            actual_paths.add(relative)
    declared_paths = set(path_owners)
    if actual_paths != declared_paths:
        unowned = sorted(actual_paths - declared_paths)
        absent = sorted(declared_paths - actual_paths)
        details: list[str] = []
        if unowned:
            details.append("unowned=" + ",".join(unowned[:5]))
        if absent:
            details.append("absent=" + ",".join(absent[:5]))
        raise CategoryLkgBindingError(
            "category output ownership is not exact: " + "; ".join(details)
        )
    return identities


def release_asset(
    release: dict[str, Any],
    name: str,
    expected_digest: str,
    actual_digest: str,
    actual_size: int,
) -> dict[str, Any]:
    raw_assets = release.get("assets")
    if not isinstance(raw_assets, list):
        raise CategoryLkgBindingError("release assets must be an array")
    matches = [
        item
        for item in raw_assets
        if isinstance(item, dict) and str(item.get("name", "")) == name
    ]
    if len(matches) != 1:
        raise CategoryLkgBindingError(f"release must contain one {name} asset")
    asset = matches[0]
    digest = str(asset.get("digest", "")).lower()
    if digest != f"sha256:{expected_digest}" or actual_digest != expected_digest:
        raise CategoryLkgBindingError(f"release {name} digest is inconsistent")
    asset_id = asset.get("id")
    size = asset.get("size")
    if (
        isinstance(asset_id, bool)
        or not isinstance(asset_id, int)
        or asset_id <= 0
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or size != actual_size
    ):
        raise CategoryLkgBindingError(f"release {name} identity is invalid")
    return {
        "id": asset_id,
        "name": name,
        "size": size,
        "sha256": expected_digest,
    }


def checksum_archive_digest(path: pathlib.Path) -> str:
    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        raise CategoryLkgBindingError(f"invalid release checksum: {exc}") from exc
    if len(lines) != 1:
        raise CategoryLkgBindingError("release checksum must contain one line")
    match = re.fullmatch(
        r"([0-9a-f]{64})\s+\*?ruleset-dist\.tar\.gz", lines[0]
    )
    if match is None:
        raise CategoryLkgBindingError("release checksum line is malformed")
    return match.group(1)


def verified_attestation(
    payload: Any,
    repository: str,
    archive_sha256: str,
    expected_source_sha: str,
) -> dict[str, Any]:
    if not isinstance(payload, list):
        raise CategoryLkgBindingError("verified attestation payload must be an array")
    expected_repository = f"https://github.com/{repository}"
    expected_workflow_path = ".github/workflows/source-discovery.yml"
    expected_signer = f"{expected_repository}/{expected_workflow_path}@refs/heads/main"
    matches: list[dict[str, Any]] = []
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        result = raw.get("verificationResult")
        if not isinstance(result, dict):
            continue
        statement = result.get("statement")
        signature = result.get("signature")
        if not isinstance(statement, dict) or not isinstance(signature, dict):
            continue
        certificate = signature.get("certificate")
        predicate = statement.get("predicate")
        if not isinstance(certificate, dict) or not isinstance(predicate, dict):
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        subject_matches = [
            item
            for item in subjects
            if isinstance(item, dict)
            and item.get("name") == "ruleset-dist.tar.gz"
            and isinstance(item.get("digest"), dict)
            and item["digest"].get("sha256") == archive_sha256
        ]
        build_definition = predicate.get("buildDefinition")
        run_details = predicate.get("runDetails")
        if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
            continue
        external = build_definition.get("externalParameters")
        dependencies = build_definition.get("resolvedDependencies")
        metadata = run_details.get("metadata")
        if (
            not isinstance(external, dict)
            or not isinstance(dependencies, list)
            or not isinstance(metadata, dict)
        ):
            continue
        workflow = external.get("workflow")
        if not isinstance(workflow, dict):
            continue
        source_sha = str(certificate.get("sourceRepositoryDigest", ""))
        invocation = str(metadata.get("invocationId", ""))
        invocation_match = RUN_URL_RE.fullmatch(invocation)
        dependency_matches = [
            item
            for item in dependencies
            if isinstance(item, dict)
            and item.get("uri") == f"git+{expected_repository}@refs/heads/main"
            and isinstance(item.get("digest"), dict)
            and item["digest"].get("gitCommit") == source_sha
        ]
        if (
            len(subject_matches) != 1
            or statement.get("predicateType") != "https://slsa.dev/provenance/v1"
            or workflow.get("path") != expected_workflow_path
            or workflow.get("ref") != "refs/heads/main"
            or workflow.get("repository") != expected_repository
            or certificate.get("issuer") != "https://token.actions.githubusercontent.com"
            or certificate.get("subjectAlternativeName") != expected_signer
            or certificate.get("githubWorkflowRepository") != repository
            or certificate.get("githubWorkflowRef") != "refs/heads/main"
            or certificate.get("sourceRepositoryURI") != expected_repository
            or certificate.get("sourceRepositoryRef") != "refs/heads/main"
            or source_sha != expected_source_sha
            or len(dependency_matches) != 1
            or invocation_match is None
            or invocation_match.group(1) != repository
        ):
            continue
        run_id = int(invocation_match.group(2))
        run_attempt = int(invocation_match.group(3) or "1")
        matches.append(
            {
                "workflow": f"{repository}/{expected_workflow_path}",
                "source_sha": source_sha,
                "run_id": run_id,
                "run_attempt": run_attempt,
                "subject_sha256": archive_sha256,
            }
        )
    if not matches:
        raise CategoryLkgBindingError(
            "no verified Source Discovery attestation matches the release archive"
        )
    return min(matches, key=lambda item: (item["run_id"], item["run_attempt"]))


def published_status(payload: Any, repository: str, release_commit: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("sha") != release_commit:
        raise CategoryLkgBindingError("published status is not bound to the release commit")
    raw_statuses = payload.get("statuses")
    if not isinstance(raw_statuses, list):
        raise CategoryLkgBindingError("published statuses must be an array")
    matches = [
        item
        for item in raw_statuses
        if isinstance(item, dict) and item.get("context") == "ruleset/published"
    ]
    status = max(
        matches,
        key=lambda item: (
            str(item.get("updated_at") or item.get("created_at") or ""),
            int(item.get("id", 0)),
        ),
        default=None,
    )
    if not isinstance(status, dict) or status.get("state") != "success":
        raise CategoryLkgBindingError("latest ruleset/published status is not successful")
    target_url = str(status.get("target_url", ""))
    match = RUN_URL_RE.fullmatch(target_url)
    status_id = status.get("id")
    description = str(status.get("description", ""))
    avatar_url = str(status.get("avatar_url", ""))
    if (
        match is None
        or match.group(1) != repository
        or isinstance(status_id, bool)
        or not isinstance(status_id, int)
        or status_id <= 0
        or description
        != "Candidate, tag, release, attestation, raw index, and README verified"
        or re.fullmatch(
            r"https://avatars\.githubusercontent\.com/in/15368(?:\?.*)?",
            avatar_url,
        )
        is None
    ):
        raise CategoryLkgBindingError("ruleset/published status identity is malformed")
    return {
        "id": status_id,
        "run_id": int(match.group(2)),
        "state": "success",
        "context": "ruleset/published",
        "description": description,
        "github_actions_app_id": 15368,
        "updated_at": str(status.get("updated_at", "")),
    }


def build_binding(args: argparse.Namespace) -> dict[str, Any]:
    if not REPOSITORY_RE.fullmatch(args.repository):
        raise CategoryLkgBindingError("repository must be owner/name")
    for label, value in (
        ("main SHA", args.main_sha),
        ("release commit", args.release_commit_sha),
        ("release dist tree", args.release_dist_tree_oid),
        ("main dist tree", args.main_dist_tree_oid),
    ):
        if not SHA1_RE.fullmatch(value):
            raise CategoryLkgBindingError(f"{label} must be a lowercase Git SHA")
    if args.release_dist_tree_oid != args.main_dist_tree_oid:
        raise CategoryLkgBindingError(
            "current main dist tree does not match the immutable release"
        )

    release = read_json(args.release_json)
    if not isinstance(release, dict):
        raise CategoryLkgBindingError("release JSON root must be an object")
    if (
        release.get("immutable") is not True
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        raise CategoryLkgBindingError("release is not immutable and final")
    release_id = release.get("id")
    tag = str(release.get("tag_name", ""))
    if (
        isinstance(release_id, bool)
        or not isinstance(release_id, int)
        or release_id <= 0
        or not re.fullmatch(r"ruleset-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}", tag)
        or not args.release_commit_sha.startswith(tag.rsplit("-", 1)[1])
    ):
        raise CategoryLkgBindingError("release identity is invalid")

    archive_sha256 = sha256_file(args.archive)
    declared_archive_sha256 = checksum_archive_digest(args.checksum)
    if archive_sha256 != declared_archive_sha256:
        raise CategoryLkgBindingError("release archive does not match its checksum")
    archive_asset = release_asset(
        release,
        "ruleset-dist.tar.gz",
        archive_sha256,
        declared_archive_sha256,
        args.archive.stat().st_size,
    )
    checksum_sha256 = sha256_file(args.checksum)
    checksum_asset = release_asset(
        release,
        "ruleset-dist.sha256",
        checksum_sha256,
        checksum_sha256,
        args.checksum.stat().st_size,
    )

    baseline_manifest = directory_manifest(args.baseline_dist)
    archived_manifest = archive_manifest(args.archive)
    if baseline_manifest != archived_manifest:
        raise CategoryLkgBindingError(
            "current baseline dist files do not match the immutable release archive"
        )
    index = read_json(args.baseline_dist / "index.json")
    provenance = read_json(args.baseline_dist / "source_provenance.json")
    source_lock = read_json(args.baseline_dist / "sources.lock.json")
    if not all(isinstance(item, dict) for item in (index, provenance, source_lock)):
        raise CategoryLkgBindingError("baseline identity files must be objects")
    try:
        source_lock_sha256, source_lock_repositories = source_lock_identity(
            source_lock, "published category LKG"
        )
    except AutomatedReviewError as exc:
        raise CategoryLkgBindingError(str(exc)) from exc
    validate_source_provenance(
        provenance, source_lock_sha256, source_lock_repositories
    )
    baseline_candidate_manifest = read_json(
        args.baseline_dist / "candidate_manifest.json"
    )
    archived_candidate_manifest = archive_json(
        args.archive, "candidate_manifest.json"
    )
    if (
        not isinstance(baseline_candidate_manifest, dict)
        or baseline_candidate_manifest != archived_candidate_manifest
    ):
        raise CategoryLkgBindingError(
            "baseline candidate manifest does not match the release archive"
        )
    candidate_source_sha = str(
        archived_candidate_manifest.get("source_commit_sha", "")
    )
    if (
        not SHA1_RE.fullmatch(candidate_source_sha)
        or not SHA256_RE.fullmatch(
            str(archived_candidate_manifest.get("semantic_digest", ""))
        )
        or archived_candidate_manifest.get("source_lock_sha256")
        != source_lock_sha256
    ):
        raise CategoryLkgBindingError(
            "release candidate manifest identity is inconsistent"
        )
    categories = category_output_identities(args.baseline_dist, index)
    if index.get("category_count") != len(categories):
        raise CategoryLkgBindingError("baseline index category count is inconsistent")

    attestation = verified_attestation(
        read_json(args.attestation_json),
        args.repository,
        archive_sha256,
        candidate_source_sha,
    )
    status = published_status(
        read_json(args.published_status_json),
        args.repository,
        args.release_commit_sha,
    )
    lkg_anchor: dict[str, Any] = {
        "repository": args.repository,
        "release_id": release_id,
        "release_tag": tag,
        "release_commit_sha": args.release_commit_sha,
        "release_dist_tree_oid": args.release_dist_tree_oid,
        "archive_asset": archive_asset,
        "checksum_asset": checksum_asset,
        "published_at": str(release.get("published_at", "")),
        "published_status": status,
        "source_attestation": attestation,
    }
    lkg_anchor["anchor_sha256"] = digest_payload(lkg_anchor)

    payload: dict[str, Any] = {
        "schema": BINDING_SCHEMA,
        "mode": "shadow-bootstrap-only",
        "enforcement_ready": False,
        "binding_policy": BINDING_POLICY,
        "lkg_granularity": "published-category-output-bundle",
        "per_source_lkg_available": False,
        "single_source_snapshot": False,
        "normalized_source_payloads_included": False,
        "licensing_assertions_added": False,
        "exact_main_sha": args.main_sha,
        "main_dist_tree_oid": args.main_dist_tree_oid,
        "lkg_anchor": lkg_anchor,
        "dist_tree_sha256": digest_payload(baseline_manifest),
        "baseline_index_sha256": digest_payload(index),
        "baseline_candidate_manifest_sha256": digest_payload(
            baseline_candidate_manifest
        ),
        "baseline_source_provenance_sha256": digest_payload(provenance),
        "baseline_source_lock_sha256": source_lock_sha256,
        "baseline_source_lock_repositories": sorted(source_lock_repositories),
        "category_count": len(categories),
        "categories": [categories[category] for category in sorted(categories)],
    }
    payload["binding_sha256"] = digest_payload(payload)
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic shadow binding to an immutable published "
            "category-level last-known-good ruleset."
        )
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--release-json", type=pathlib.Path, required=True)
    parser.add_argument("--release-commit-sha", required=True)
    parser.add_argument("--release-dist-tree-oid", required=True)
    parser.add_argument("--main-dist-tree-oid", required=True)
    parser.add_argument("--archive", type=pathlib.Path, required=True)
    parser.add_argument("--checksum", type=pathlib.Path, required=True)
    parser.add_argument("--baseline-dist", type=pathlib.Path, required=True)
    parser.add_argument("--attestation-json", type=pathlib.Path, required=True)
    parser.add_argument("--published-status-json", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        payload = build_binding(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_bytes(payload))
        print(
            "[category-lkg] "
            f"tag={payload['lkg_anchor']['release_tag']} "
            f"categories={payload['category_count']} "
            f"binding_sha256={payload['binding_sha256']} "
            "enforcement_ready=false"
        )
        return 0
    except (CategoryLkgBindingError, OSError, TypeError, ValueError) as exc:
        print(f"[category-lkg] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
