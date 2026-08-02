#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import io
import json
import pathlib
import re
import stat
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from typing import Any

try:
    from ruleset.scripts.build_category_lkg_binding import (
        CategoryLkgBindingError,
        category_output_identities,
    )
except ModuleNotFoundError:
    from build_category_lkg_binding import (  # type: ignore[no-redef]
        CategoryLkgBindingError,
        category_output_identities,
    )


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ARTIFACT_RE = re.compile(
    r"^ruleset-isolation-composite-v2-"
    r"(?P<source>[0-9a-f]{40})-"
    r"(?P<content>[0-9a-f]{64})-"
    r"(?P<evidence>[0-9a-f]{64})$"
)
CYCLE_FILES = {
    "artifact.zip",
    "inner-attestation.json",
    "metadata.json",
    "outer-attestation.json",
}
ARTIFACT_FILES = {
    "upstream-isolation-composite-evidence.tar",
    "upstream-isolation-composite-evidence.sha256",
}
EVIDENCE_FILES = {
    "automated-review.json",
    "category-lkg-binding.json",
    "composite-evidence-checksums.sha256",
    "composite-gate-receipt.json",
    "composite-identity.json",
    "composite-review.json",
    "gitleaks-composite.sarif",
    "isolation-evidence.json",
    "ruleset-composite-dist.sha256",
    "ruleset-composite-dist.tar.gz",
    "upstream-isolation-plan.json",
}
CHECKSUM_TARGETS = EVIDENCE_FILES - {"composite-evidence-checksums.sha256"}
VOLATILE_DIST_FILES = {"fetch_report.json", "source_health.json"}
MAX_ARTIFACT_ZIP_BYTES = 768 * 1024 * 1024
MAX_EVIDENCE_MEMBERS = 16
MAX_DIST_MEMBERS = 5000
MAX_EVIDENCE_BYTES = 512 * 1024 * 1024
MAX_DIST_BYTES = 512 * 1024 * 1024
COMPOSITE_SCHEMA = "project-g-upstream-isolation-composite-v1"
REVIEW_SCHEMA = "project-g-upstream-isolation-composite-review-v1"
GATE_SCHEMA = "project-g-upstream-isolation-composite-gate-v1"
PAIR_SCHEMA = "project-g-upstream-isolation-pair-v1"
CYCLE_METADATA_SCHEMA = "project-g-upstream-isolation-cycle-metadata-v1"
PLAN_SCHEMA = "project-g-upstream-isolation-plan-v2"
SELECTION_SCHEMA = "project-g-upstream-isolation-selection-v1"
ISOLATION_ARTIFACT_SCHEMA = "project-g-isolation-evidence-artifact-v1"
ISOLATION_EVIDENCE_SCHEMA = "project-g-isolation-evidence-v1"
LKG_BINDING_SCHEMA = "project-g-category-lkg-binding-v2"
LKG_BINDING_POLICY = "immutable-release-category-output-bundle-v2"
MATERIALIZER_POLICY = "atomic-repository-complete-category-lkg-v1"
PLANNER_POLICY = "atomic-repository-category-lkg-shadow-v2"
COMPLETED_GATES = [
    "validate-rulesets",
    "smoke-probes",
    "allowlist-effective",
    "quality-gates",
]
ALLOWED_EVENTS = {"push", "schedule", "workflow_dispatch"}


class CompositeVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArtifactIdentity:
    name: str
    source_sha: str
    content_identity: str
    evidence_sha256: str


@dataclass(frozen=True)
class RemoteIdentity:
    repository: str
    workflow_path: str
    run_id: int
    run_attempt: int
    run_started_at: str
    run_started_epoch: int
    artifact_id: int
    artifact_api_digest: str
    artifact_size: int
    artifact_zip_sha256: str
    inner_tlog_timestamp: str
    outer_tlog_timestamp: str


@dataclass
class CycleEvidence:
    artifact: ArtifactIdentity
    remote: RemoteIdentity
    cycle_dir: pathlib.Path
    evidence_sha256: str
    dist_archive_sha256: str
    evidence_files: dict[str, bytes]
    identity: dict[str, Any]
    review: dict[str, Any]
    gate: dict[str, Any]
    automated_review: dict[str, Any]
    isolation_artifact: dict[str, Any]
    plan: dict[str, Any]
    lkg_binding: dict[str, Any]
    containment_boundary_sha256: str
    stable_payload_sha256: str
    dist_files: dict[str, bytes]
    dist_manifest: list[dict[str, Any]]
    candidate_manifest: dict[str, Any]
    fetch_report: dict[str, Any]
    source_health: dict[str, Any]


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


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise CompositeVerificationError(f"cannot read {path}: {exc}") from exc
    return digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CompositeVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompositeVerificationError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CompositeVerificationError(f"JSON root must be an object in {label}")
    return value


def read_json_value(payload: bytes, label: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompositeVerificationError(f"invalid JSON in {label}: {exc}") from exc


def require_sha256(value: object, label: str) -> str:
    text = str(value)
    if not SHA256_RE.fullmatch(text):
        raise CompositeVerificationError(f"{label} is not a lowercase SHA-256")
    return text


def require_positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CompositeVerificationError(f"{label} must be a positive integer")
    return value


def require_nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CompositeVerificationError(f"{label} must be a non-negative integer")
    return value


def require_sorted_strings(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        raise CompositeVerificationError(f"{label} must be sorted unique strings")
    return value


def parse_timestamp(value: object, label: str) -> tuple[str, int]:
    text = str(value)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CompositeVerificationError(f"{label} is not an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise CompositeVerificationError(f"{label} lacks a timezone")
    return text, int(parsed.timestamp())


def verify_self_digest(payload: dict[str, Any], field: str, label: str) -> str:
    expected = require_sha256(payload.get(field), f"{label} {field}")
    unsigned = dict(payload)
    unsigned.pop(field, None)
    if digest_payload(unsigned) != expected:
        raise CompositeVerificationError(f"{label} digest is invalid")
    return expected


def parse_artifact_name(name: str) -> ArtifactIdentity:
    match = ARTIFACT_RE.fullmatch(name)
    if match is None:
        raise CompositeVerificationError(f"invalid composite artifact name: {name}")
    return ArtifactIdentity(
        name=name,
        source_sha=match.group("source"),
        content_identity=match.group("content"),
        evidence_sha256=match.group("evidence"),
    )


def validate_exact_directory(path: pathlib.Path, expected: set[str], label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise CompositeVerificationError(f"{label} directory is invalid: {path}")
    observed: set[str] = set()
    for child in path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise CompositeVerificationError(
                f"{label} contains a non-regular entry: {child.name}"
            )
        observed.add(child.name)
    if observed != expected:
        raise CompositeVerificationError(
            f"{label} file set is not exact: "
            f"missing={sorted(expected - observed)} extra={sorted(observed - expected)}"
        )


def parse_checksum_bytes(
    payload: bytes,
    *,
    expected_names: set[str],
    label: str,
) -> dict[str, str]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CompositeVerificationError(f"{label} is not UTF-8") from exc
    rows: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            raise CompositeVerificationError(f"malformed checksum row in {label}")
        digest = parts[0].lower()
        name = parts[1].lstrip("*")
        if not SHA256_RE.fullmatch(digest):
            raise CompositeVerificationError(f"invalid checksum digest in {label}")
        if name in rows:
            raise CompositeVerificationError(f"duplicate checksum target in {label}: {name}")
        rows[name] = digest
    if set(rows) != expected_names:
        raise CompositeVerificationError(
            f"checksum target set is not exact in {label}: "
            f"missing={sorted(expected_names - set(rows))} "
            f"extra={sorted(set(rows) - expected_names)}"
        )
    return rows


def safe_member_path(raw: str, label: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
        or raw.rstrip("/") != path.as_posix()
        or "\\" in raw
    ):
        raise CompositeVerificationError(f"unsafe {label} member: {raw!r}")
    return path


def read_artifact_zip(
    path: pathlib.Path,
    *,
    expected_digest: str,
    expected_size: int,
) -> tuple[dict[str, bytes], str]:
    if path.is_symlink() or not path.is_file():
        raise CompositeVerificationError("artifact ZIP is absent or unsafe")
    actual_size = path.stat().st_size
    if actual_size != expected_size or actual_size <= 0 or actual_size > MAX_ARTIFACT_ZIP_BYTES:
        raise CompositeVerificationError("artifact ZIP size differs from API metadata")
    if not expected_digest.startswith("sha256:"):
        raise CompositeVerificationError("artifact API digest is not SHA-256")
    expected_sha256 = require_sha256(
        expected_digest.removeprefix("sha256:"), "artifact API digest"
    )
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise CompositeVerificationError("artifact ZIP digest differs from API metadata")
    files: dict[str, bytes] = {}
    casefolded: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if len(entries) != len(ARTIFACT_FILES):
                raise CompositeVerificationError("artifact ZIP member count is not exact")
            for entry in entries:
                member_path = safe_member_path(entry.filename, "artifact ZIP")
                name = member_path.as_posix()
                unix_mode = (entry.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                if (
                    entry.is_dir()
                    or name not in ARTIFACT_FILES
                    or name in files
                    or name.casefold() in casefolded
                    or entry.flag_bits & 0x1
                    or entry.compress_type
                    not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or (entry.create_system == 3 and file_type not in {0, stat.S_IFREG})
                ):
                    raise CompositeVerificationError(
                        f"invalid artifact ZIP member: {entry.filename}"
                    )
                if entry.file_size < 0 or total + entry.file_size > MAX_EVIDENCE_BYTES:
                    raise CompositeVerificationError("artifact ZIP expands beyond the size limit")
                with archive.open(entry, "r") as handle:
                    payload = handle.read(MAX_EVIDENCE_BYTES + 1)
                if len(payload) != entry.file_size:
                    raise CompositeVerificationError(
                        f"artifact ZIP member is truncated: {entry.filename}"
                    )
                files[name] = payload
                casefolded.add(name.casefold())
                total += len(payload)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise CompositeVerificationError(f"invalid artifact ZIP: {exc}") from exc
    if set(files) != ARTIFACT_FILES:
        raise CompositeVerificationError("artifact ZIP file set is not exact")
    return files, actual_sha256


def read_exact_evidence_tar(payload: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_EVIDENCE_MEMBERS:
                raise CompositeVerificationError("evidence tar has too many members")
            for member in members:
                member_path = safe_member_path(member.name, "evidence")
                name = member_path.as_posix()
                if (
                    member.issym()
                    or member.islnk()
                    or not member.isfile()
                    or name not in EVIDENCE_FILES
                    or name in files
                ):
                    raise CompositeVerificationError(
                        f"invalid evidence tar member: {member.name}"
                    )
                if member.size < 0 or total + member.size > MAX_EVIDENCE_BYTES:
                    raise CompositeVerificationError("evidence tar exceeds the size limit")
                handle = archive.extractfile(member)
                if handle is None:
                    raise CompositeVerificationError(
                        f"cannot read evidence tar member: {member.name}"
                    )
                member_payload = handle.read(MAX_EVIDENCE_BYTES + 1)
                if len(member_payload) != member.size:
                    raise CompositeVerificationError(
                        f"truncated evidence tar member: {member.name}"
                    )
                files[name] = member_payload
                total += len(member_payload)
    except (tarfile.TarError, OSError) as exc:
        raise CompositeVerificationError(f"invalid evidence tar: {exc}") from exc
    if set(files) != EVIDENCE_FILES:
        raise CompositeVerificationError(
            "evidence tar file set is not exact: "
            f"missing={sorted(EVIDENCE_FILES - set(files))} "
            f"extra={sorted(set(files) - EVIDENCE_FILES)}"
        )
    return files


def read_dist_tar(payload: bytes) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_DIST_MEMBERS:
                raise CompositeVerificationError("dist archive has too many members")
            for member in members:
                member_path = safe_member_path(member.name, "dist")
                if not member_path.parts or member_path.parts[0] != "dist":
                    raise CompositeVerificationError(
                        f"dist archive member is outside dist/: {member.name}"
                    )
                if member.issym() or member.islnk() or not (
                    member.isfile() or member.isdir()
                ):
                    raise CompositeVerificationError(
                        f"invalid dist archive member: {member.name}"
                    )
                if member.isdir():
                    continue
                relative_path = pathlib.PurePosixPath(*member_path.parts[1:])
                relative = relative_path.as_posix()
                if not relative or relative in files:
                    raise CompositeVerificationError(
                        f"duplicate or empty dist archive member: {member.name}"
                    )
                if member.size < 0 or total + member.size > MAX_DIST_BYTES:
                    raise CompositeVerificationError("dist archive exceeds the size limit")
                handle = archive.extractfile(member)
                if handle is None:
                    raise CompositeVerificationError(
                        f"cannot read dist archive member: {member.name}"
                    )
                data = handle.read(MAX_DIST_BYTES + 1)
                if len(data) != member.size:
                    raise CompositeVerificationError(
                        f"truncated dist archive member: {member.name}"
                    )
                files[relative] = data
                total += len(data)
    except (tarfile.TarError, OSError) as exc:
        raise CompositeVerificationError(f"invalid dist archive: {exc}") from exc
    if not files:
        raise CompositeVerificationError("dist archive contains no files")
    manifest = [
        {"path": name, "size": len(files[name]), "sha256": sha256_bytes(files[name])}
        for name in sorted(files)
    ]
    return files, manifest


def validate_attestation(
    payload: bytes,
    *,
    label: str,
    repository: str,
    workflow_path: str,
    source_sha: str,
    run_id: int,
    run_attempt: int,
    subject_sha256: str,
) -> str:
    value = read_json_value(payload, label)
    if not isinstance(value, list) or not value:
        raise CompositeVerificationError(f"{label} has no verified attestations")
    expected_invocation = (
        f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    )
    expected_identity = (
        f"https://github.com/{repository}/{workflow_path}@refs/heads/main"
    )
    matches: list[str] = []
    for raw in value:
        if not isinstance(raw, dict):
            continue
        result = raw.get("verificationResult")
        if not isinstance(result, dict):
            continue
        signature = result.get("signature")
        certificate = signature.get("certificate") if isinstance(signature, dict) else None
        statement = result.get("statement")
        timestamps = result.get("verifiedTimestamps")
        if (
            not isinstance(certificate, dict)
            or not isinstance(statement, dict)
            or not isinstance(timestamps, list)
        ):
            continue
        subjects = statement.get("subject")
        subject_match = False
        if isinstance(subjects, list):
            for subject in subjects:
                digest = subject.get("digest") if isinstance(subject, dict) else None
                if isinstance(digest, dict) and digest.get("sha256") == subject_sha256:
                    subject_match = True
        if not subject_match:
            continue
        tlog_rows = [
            row
            for row in timestamps
            if isinstance(row, dict)
            and row.get("type") == "Tlog"
            and isinstance(row.get("timestamp"), str)
        ]
        if not tlog_rows:
            continue
        if (
            certificate.get("subjectAlternativeName") != expected_identity
            or certificate.get("githubWorkflowSHA") != source_sha
            or certificate.get("githubWorkflowRepository") != repository
            or certificate.get("githubWorkflowRef") != "refs/heads/main"
            or certificate.get("buildSignerDigest") != source_sha
            or certificate.get("runnerEnvironment") != "github-hosted"
            or certificate.get("sourceRepositoryDigest") != source_sha
            or certificate.get("sourceRepositoryRef") != "refs/heads/main"
            or certificate.get("runInvocationURI") != expected_invocation
        ):
            continue
        timestamp, _epoch = parse_timestamp(
            tlog_rows[0]["timestamp"], f"{label} TLog timestamp"
        )
        matches.append(timestamp)
    if len(matches) != 1:
        raise CompositeVerificationError(
            f"{label} does not have one exact run-bound GitHub-hosted attestation"
        )
    return matches[0]


def validate_remote_identity(
    cycle_dir: pathlib.Path,
    *,
    repository: str,
    workflow_path: str,
    expected_main_sha: str,
) -> tuple[ArtifactIdentity, RemoteIdentity, dict[str, bytes]]:
    validate_exact_directory(cycle_dir, CYCLE_FILES, "cycle")
    metadata = read_json_bytes(
        (cycle_dir / "metadata.json").read_bytes(), "cycle metadata"
    )
    if (
        metadata.get("schema") != CYCLE_METADATA_SCHEMA
        or metadata.get("repository") != repository
        or metadata.get("workflow_path") != workflow_path
    ):
        raise CompositeVerificationError("cycle metadata envelope is invalid")
    run = metadata.get("run")
    artifact_row = metadata.get("artifact")
    if not isinstance(run, dict) or not isinstance(artifact_row, dict):
        raise CompositeVerificationError("cycle run or artifact metadata is absent")
    run_id = require_positive_int(run.get("id"), "run ID")
    run_attempt = require_positive_int(run.get("run_attempt"), "run attempt")
    if (
        run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != expected_main_sha
        or run.get("head_repository") != repository
        or run.get("path") != workflow_path
        or run.get("event") not in ALLOWED_EVENTS
    ):
        raise CompositeVerificationError("cycle run identity is invalid")
    run_started_at, run_started_epoch = parse_timestamp(
        run.get("run_started_at"), "run start"
    )
    parse_timestamp(run.get("created_at"), "run creation")
    parse_timestamp(run.get("updated_at"), "run completion")
    artifact_id = require_positive_int(artifact_row.get("id"), "artifact ID")
    artifact_size = require_positive_int(
        artifact_row.get("size_in_bytes"), "artifact size"
    )
    artifact_name = str(artifact_row.get("name", ""))
    artifact = parse_artifact_name(artifact_name)
    if artifact.source_sha != expected_main_sha:
        raise CompositeVerificationError("artifact source does not match expected main")
    artifact_api_digest = str(artifact_row.get("digest", ""))
    if (
        artifact_row.get("expired") is not False
        or artifact_row.get("workflow_run_id") != run_id
    ):
        raise CompositeVerificationError("artifact API identity is invalid")
    artifact_files, zip_sha256 = read_artifact_zip(
        cycle_dir / "artifact.zip",
        expected_digest=artifact_api_digest,
        expected_size=artifact_size,
    )
    evidence_payload = artifact_files["upstream-isolation-composite-evidence.tar"]
    evidence_sha256 = sha256_bytes(evidence_payload)
    if evidence_sha256 != artifact.evidence_sha256:
        raise CompositeVerificationError("artifact name does not bind outer evidence")
    evidence_files = read_exact_evidence_tar(evidence_payload)
    inner_sha256 = sha256_bytes(evidence_files["ruleset-composite-dist.tar.gz"])
    inner_tlog = validate_attestation(
        (cycle_dir / "inner-attestation.json").read_bytes(),
        label="inner attestation",
        repository=repository,
        workflow_path=workflow_path,
        source_sha=expected_main_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        subject_sha256=inner_sha256,
    )
    outer_tlog = validate_attestation(
        (cycle_dir / "outer-attestation.json").read_bytes(),
        label="outer attestation",
        repository=repository,
        workflow_path=workflow_path,
        source_sha=expected_main_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        subject_sha256=evidence_sha256,
    )
    remote = RemoteIdentity(
        repository=repository,
        workflow_path=workflow_path,
        run_id=run_id,
        run_attempt=run_attempt,
        run_started_at=run_started_at,
        run_started_epoch=run_started_epoch,
        artifact_id=artifact_id,
        artifact_api_digest=artifact_api_digest,
        artifact_size=artifact_size,
        artifact_zip_sha256=zip_sha256,
        inner_tlog_timestamp=inner_tlog,
        outer_tlog_timestamp=outer_tlog,
    )
    return artifact, remote, artifact_files


def validate_observation_summary(payload: object, label: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise CompositeVerificationError(f"{label} observation summary is invalid")
    summary = copy.deepcopy(payload)
    expected = verify_self_digest(summary, "summary_sha256", f"{label} summary")
    if summary.get("schema") != "project-g-upstream-isolation-observation-summary-v1":
        raise CompositeVerificationError(f"{label} observation summary schema is invalid")
    if summary.get("complete_blocker_mapping") is not True:
        raise CompositeVerificationError(f"{label} blocker mapping is incomplete")
    if require_nonnegative_int(
        summary.get("unscoped_blocker_count"), f"{label} unscoped blocker count"
    ) != 0:
        raise CompositeVerificationError(f"{label} has unscoped blockers")
    blocker_count = require_nonnegative_int(
        summary.get("blocker_count"), f"{label} blocker count"
    )
    finding_count = require_nonnegative_int(
        summary.get("finding_count"), f"{label} finding count"
    )
    if finding_count < blocker_count:
        raise CompositeVerificationError(f"{label} finding count is inconsistent")
    for field in (
        "finding_categories",
        "finding_codes",
        "isolated_source_ids",
        "quarantined_categories",
        "held_categories",
    ):
        require_sorted_strings(summary.get(field), f"{label} {field}")
    summary["summary_sha256"] = expected
    return summary


def validate_category_selections(identity: dict[str, Any]) -> list[dict[str, Any]]:
    rows = identity.get("category_selections")
    if not isinstance(rows, list) or not rows:
        raise CompositeVerificationError("composite category selections are absent")
    categories: list[str] = []
    allowed_selections = {
        "candidate-category",
        "candidate-equivalent-category",
        "published-category-lkg",
        "derived-recompute-required",
    }
    allowed_origins = {"observed-candidate", "published-lkg", "derived-composite"}
    for row in rows:
        if not isinstance(row, dict):
            raise CompositeVerificationError("composite category selection row is invalid")
        category = str(row.get("category", ""))
        if not category or category in categories:
            raise CompositeVerificationError("composite category selections are not unique")
        categories.append(category)
        if row.get("selection") not in allowed_selections:
            raise CompositeVerificationError(f"invalid selection for category {category}")
        if row.get("snapshot_origin") not in allowed_origins:
            raise CompositeVerificationError(f"invalid snapshot origin for category {category}")
        for field in (
            "contract_sha256",
            "normalized_rules_sha256",
            "output_bundle_sha256",
            "snapshot_sha256",
        ):
            require_sha256(row.get(field), f"category {category} {field}")
        require_nonnegative_int(row.get("rule_count"), f"category {category} rule count")
        priority = row.get("recommended_priority")
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise CompositeVerificationError(
                f"category {category} recommended priority is invalid"
            )
        if not isinstance(row.get("recommended_action"), str) or not row.get(
            "recommended_action"
        ):
            raise CompositeVerificationError(
                f"category {category} recommended action is invalid"
            )
    if categories != sorted(categories):
        raise CompositeVerificationError("composite category selections are not sorted")
    return rows


def validate_automated_and_containment(
    *,
    automated_review: dict[str, Any],
    isolation_artifact: dict[str, Any],
    plan: dict[str, Any],
    lkg_binding: dict[str, Any],
    identity: dict[str, Any],
    review: dict[str, Any],
    expected_main_sha: str,
) -> str:
    if (
        automated_review.get("schema") != "project-g-automated-review-v2"
        or automated_review.get("review_policy") != "unattended-evidence-gated-v2"
        or automated_review.get("required_stable_cycles") != 2
        or automated_review.get("minimum_cycle_separation_seconds") != 300
        or not isinstance(automated_review.get("eligible"), bool)
    ):
        raise CompositeVerificationError("automated review envelope is invalid")
    blockers = automated_review.get("blockers")
    if not isinstance(blockers, list) or any(not isinstance(item, str) for item in blockers):
        raise CompositeVerificationError("automated review blockers are invalid")
    for field in (
        "baseline_index_sha256",
        "baseline_source_lock_sha256",
        "current_index_sha256",
        "current_source_lock_sha256",
        "protected_domain_roots_sha256",
        "public_suffix_list_sha256",
        "source_config_sha256",
    ):
        require_sha256(automated_review.get(field), f"automated review {field}")
    require_sorted_strings(
        automated_review.get("changed_categories"), "automated review changed categories"
    )

    if (
        isolation_artifact.get("schema") != ISOLATION_ARTIFACT_SCHEMA
        or isolation_artifact.get("mode") != "shadow-only"
    ):
        raise CompositeVerificationError("isolation evidence artifact is invalid")
    verify_self_digest(isolation_artifact, "artifact_sha256", "isolation artifact")
    if isolation_artifact.get("automated_review_sha256") != digest_payload(
        automated_review
    ):
        raise CompositeVerificationError("isolation artifact review binding is invalid")
    for artifact_field, review_field in (
        ("baseline_index_sha256", "baseline_index_sha256"),
        ("candidate_index_sha256", "current_index_sha256"),
        ("source_config_sha256", "source_config_sha256"),
    ):
        if isolation_artifact.get(artifact_field) != automated_review.get(review_field):
            raise CompositeVerificationError(
                f"isolation artifact {artifact_field} binding is invalid"
            )
    isolation = isolation_artifact.get("isolation_evidence")
    if (
        not isinstance(isolation, dict)
        or isolation.get("schema") != ISOLATION_EVIDENCE_SCHEMA
        or isolation.get("mode") != "shadow-only"
    ):
        raise CompositeVerificationError("nested isolation evidence is invalid")
    isolation_digest = verify_self_digest(
        isolation, "evidence_sha256", "nested isolation evidence"
    )
    findings = isolation.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise CompositeVerificationError("isolation findings are invalid")
    if isolation.get("findings_sha256") != digest_payload(findings):
        raise CompositeVerificationError("isolation findings digest is invalid")
    for finding in findings:
        verify_self_digest(finding, "evidence_digest", "isolation finding")
        require_sorted_strings(finding.get("source_ids"), "finding source IDs")
        require_sorted_strings(
            finding.get("repository_bindings"), "finding repository bindings"
        )
        require_sorted_strings(
            finding.get("dependency_closure"), "finding dependency closure"
        )
    blocker_count = require_nonnegative_int(
        isolation.get("blocker_count"), "isolation blocker count"
    )
    mapped_count = require_nonnegative_int(
        isolation.get("mapped_blocker_count"), "mapped blocker count"
    )
    derived_count = require_nonnegative_int(
        isolation.get("derived_blocker_count"), "derived blocker count"
    )
    derived_digests = require_sorted_strings(
        isolation.get("derived_blocker_sha256s"), "derived blocker digests"
    )
    for digest in derived_digests:
        require_sha256(digest, "derived blocker digest")
    if (
        isolation.get("complete_blocker_mapping") is not True
        or require_sorted_strings(
            isolation.get("unscoped_blockers"), "unscoped blockers"
        )
        or blocker_count != mapped_count + derived_count
        or derived_count != len(derived_digests)
    ):
        raise CompositeVerificationError("isolation blocker mapping is incomplete")

    if (
        lkg_binding.get("schema") != LKG_BINDING_SCHEMA
        or lkg_binding.get("mode") != "shadow-bootstrap-only"
        or lkg_binding.get("binding_policy") != LKG_BINDING_POLICY
        or lkg_binding.get("exact_main_sha") != expected_main_sha
        or lkg_binding.get("enforcement_ready") is not False
        or lkg_binding.get("licensing_assertions_added") is not False
    ):
        raise CompositeVerificationError("category LKG binding safety mode is invalid")
    binding_digest = verify_self_digest(
        lkg_binding, "binding_sha256", "category LKG binding"
    )
    lkg_anchor = lkg_binding.get("lkg_anchor")
    if not isinstance(lkg_anchor, dict):
        raise CompositeVerificationError("category LKG anchor is absent")
    lkg_anchor_digest = verify_self_digest(lkg_anchor, "anchor_sha256", "LKG anchor")
    lkg_categories = lkg_binding.get("categories")
    if (
        not isinstance(lkg_categories, list)
        or len(lkg_categories)
        != require_positive_int(lkg_binding.get("category_count"), "LKG category count")
    ):
        raise CompositeVerificationError("category LKG coverage is invalid")
    lkg_by_category: dict[str, dict[str, Any]] = {}
    for row in lkg_categories:
        if not isinstance(row, dict):
            raise CompositeVerificationError("category LKG row is invalid")
        category = str(row.get("category", ""))
        if not category or category in lkg_by_category:
            raise CompositeVerificationError("category LKG IDs are invalid")
        lkg_by_category[category] = row
        for field in (
            "contract_sha256",
            "normalized_rules_sha256",
            "output_bundle_sha256",
            "snapshot_sha256",
        ):
            require_sha256(row.get(field), f"LKG category {category} {field}")
    if list(lkg_by_category) != sorted(lkg_by_category):
        raise CompositeVerificationError("category LKG rows are not sorted")

    if (
        plan.get("schema") != PLAN_SCHEMA
        or plan.get("mode") != "shadow-only"
        or plan.get("planner_policy") != PLANNER_POLICY
        or plan.get("enforcement_ready") is not False
        or plan.get("two_cycle_enforcement_eligible") is not False
        or plan.get("exact_main_sha") != expected_main_sha
    ):
        raise CompositeVerificationError("isolation plan safety mode is invalid")
    verify_self_digest(plan, "plan_fingerprint", "isolation plan")
    stable_selection = plan.get("stable_selection")
    if (
        not isinstance(stable_selection, dict)
        or stable_selection.get("schema") != SELECTION_SCHEMA
        or stable_selection.get("planner_policy") != PLANNER_POLICY
        or stable_selection.get("exact_main_sha") != expected_main_sha
        or stable_selection.get("composite_identity_ready") is not False
        or stable_selection.get("two_cycle_enforcement_eligible") is not False
        or digest_payload(stable_selection) != plan.get("stable_selection_fingerprint")
    ):
        raise CompositeVerificationError("stable isolation selection is invalid")
    if (
        plan.get("automated_review_sha256") != digest_payload(automated_review)
        or plan.get("isolation_evidence_sha256") != isolation_digest
        or plan.get("category_lkg_binding_sha256") != binding_digest
        or plan.get("category_lkg_anchor_sha256") != lkg_anchor_digest
        or plan.get("source_config_sha256") != automated_review.get("source_config_sha256")
        or plan.get("baseline_index_sha256")
        != automated_review.get("baseline_index_sha256")
        or plan.get("candidate_index_sha256")
        != automated_review.get("current_index_sha256")
        or plan.get("observed_candidate_source_lock_sha256")
        != automated_review.get("current_source_lock_sha256")
    ):
        raise CompositeVerificationError("isolation plan evidence binding is invalid")
    changed = require_sorted_strings(plan.get("changed_categories"), "plan changed categories")
    accepted = require_sorted_strings(
        plan.get("accepted_candidate_categories"), "accepted candidate categories"
    )
    quarantined = require_sorted_strings(
        plan.get("quarantined_categories"), "quarantined categories"
    )
    held = require_sorted_strings(plan.get("held_categories"), "held categories")
    unscoped = require_sorted_strings(plan.get("unscoped_blockers"), "plan unscoped blockers")
    if (
        changed != automated_review.get("changed_categories")
        or plan.get("global_hold") is not False
        or unscoped
        or set(accepted) & (set(quarantined) | set(held))
        or plan.get("safe_slice_changed") != bool(accepted)
    ):
        raise CompositeVerificationError("isolation plan containment is invalid")
    require_nonnegative_int(
        plan.get("planned_safe_delta_count"), "planned safe delta count"
    )
    if require_nonnegative_int(
        plan.get("publishable_safe_delta_count"), "publishable safe delta count"
    ) != 0:
        raise CompositeVerificationError("shadow plan cannot embed publication authority")

    if (
        identity.get("stable_selection_fingerprint")
        != plan.get("stable_selection_fingerprint")
        or identity.get("category_lkg_anchor_sha256") != lkg_anchor_digest
        or review.get("stable_selection_fingerprint")
        != plan.get("stable_selection_fingerprint")
        or review.get("category_lkg_anchor_sha256") != lkg_anchor_digest
    ):
        raise CompositeVerificationError("composite containment binding is invalid")
    selections = identity.get("category_selections")
    if not isinstance(selections, list):
        raise CompositeVerificationError("composite selections are invalid")
    for row in selections:
        if not isinstance(row, dict):
            raise CompositeVerificationError("composite selection row is invalid")
        if row.get("snapshot_origin") != "published-lkg":
            continue
        category = str(row.get("category", ""))
        lkg_row = lkg_by_category.get(category)
        if not isinstance(lkg_row, dict):
            raise CompositeVerificationError(f"selected LKG category is unbound: {category}")
        for field in (
            "contract_sha256",
            "normalized_rules_sha256",
            "output_bundle_sha256",
            "snapshot_sha256",
            "rule_count",
            "recommended_action",
            "recommended_priority",
        ):
            if row.get(field) != lkg_row.get(field):
                raise CompositeVerificationError(
                    f"selected LKG category differs from binding: {category}/{field}"
                )

    boundary = {
        "schema": "project-g-upstream-isolation-containment-boundary-v1",
        "exact_main_sha": expected_main_sha,
        "source_config_sha256": plan.get("source_config_sha256"),
        "source_registry_sha256": plan.get("source_registry_sha256"),
        "category_lkg_binding_sha256": binding_digest,
        "category_lkg_anchor_sha256": lkg_anchor_digest,
        "stable_selection_fingerprint": plan.get("stable_selection_fingerprint"),
        "stable_selection": stable_selection,
        "accepted_candidate_categories": accepted,
        "quarantined_categories": quarantined,
        "held_categories": held,
        "isolated_source_ids": review.get("isolated_source_ids"),
        "category_selections": selections,
    }
    return digest_payload(boundary)


def validate_category_outputs(
    dist_files: dict[str, bytes], index: dict[str, Any], selections: list[dict[str, Any]]
) -> None:
    with tempfile.TemporaryDirectory(prefix="project-g-composite-dist.") as raw_dir:
        dist_dir = pathlib.Path(raw_dir)
        for relative, payload in dist_files.items():
            path = pathlib.PurePosixPath(relative)
            if path.is_absolute() or ".." in path.parts:
                raise CompositeVerificationError("unsafe in-memory dist path")
            target = dist_dir.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        try:
            actual = category_output_identities(dist_dir, index)
        except CategoryLkgBindingError as exc:
            raise CompositeVerificationError(
                f"composite category outputs are invalid: {exc}"
            ) from exc
    expected = {str(row["category"]): row for row in selections}
    if set(actual) != set(expected):
        raise CompositeVerificationError("category output identity coverage is not exact")
    for category, actual_row in actual.items():
        expected_row = expected[category]
        for field in (
            "contract_sha256",
            "normalized_rules_sha256",
            "output_bundle_sha256",
            "snapshot_sha256",
            "rule_count",
            "recommended_action",
            "recommended_priority",
        ):
            if actual_row.get(field) != expected_row.get(field):
                raise CompositeVerificationError(
                    f"category output identity did not reproduce: {category}/{field}"
                )


def stable_payload_digest(
    dist_files: dict[str, bytes],
    fetch_report: dict[str, Any],
    source_health: dict[str, Any],
) -> str:
    rows: list[dict[str, Any]] = []
    for name in sorted(dist_files):
        payload = dist_files[name]
        if name == "fetch_report.json":
            normalized = copy.deepcopy(fetch_report)
            normalized.pop("upstream_observation", None)
            payload = canonical_bytes(normalized)
        elif name == "source_health.json":
            normalized = copy.deepcopy(source_health)
            normalized.pop("upstream_observation", None)
            payload = canonical_bytes(normalized)
        rows.append({"path": name, "size": len(payload), "sha256": sha256_bytes(payload)})
    return digest_payload(rows)


def validate_cycle(
    cycle_dir: pathlib.Path,
    *,
    repository: str,
    workflow_path: str,
    expected_main_sha: str,
) -> CycleEvidence:
    artifact, remote, artifact_files = validate_remote_identity(
        cycle_dir,
        repository=repository,
        workflow_path=workflow_path,
        expected_main_sha=expected_main_sha,
    )
    evidence_payload = artifact_files["upstream-isolation-composite-evidence.tar"]
    evidence_sha256 = sha256_bytes(evidence_payload)
    outer_rows = parse_checksum_bytes(
        artifact_files["upstream-isolation-composite-evidence.sha256"],
        expected_names={"upstream-isolation-composite-evidence.tar"},
        label="outer evidence checksum",
    )
    if outer_rows["upstream-isolation-composite-evidence.tar"] != evidence_sha256:
        raise CompositeVerificationError("outer evidence checksum does not match")
    evidence_files = read_exact_evidence_tar(evidence_payload)
    evidence_rows = parse_checksum_bytes(
        evidence_files["composite-evidence-checksums.sha256"],
        expected_names=CHECKSUM_TARGETS,
        label="evidence payload checksums",
    )
    for name, expected in evidence_rows.items():
        if sha256_bytes(evidence_files[name]) != expected:
            raise CompositeVerificationError(
                f"evidence payload checksum does not match: {name}"
            )
    inner_rows = parse_checksum_bytes(
        evidence_files["ruleset-composite-dist.sha256"],
        expected_names={"ruleset-composite-dist.tar.gz"},
        label="inner dist checksum",
    )
    inner_sha256 = sha256_bytes(evidence_files["ruleset-composite-dist.tar.gz"])
    if inner_rows["ruleset-composite-dist.tar.gz"] != inner_sha256:
        raise CompositeVerificationError("inner dist checksum does not match")

    identity = read_json_bytes(evidence_files["composite-identity.json"], "composite identity")
    review = read_json_bytes(evidence_files["composite-review.json"], "composite review")
    gate = read_json_bytes(
        evidence_files["composite-gate-receipt.json"], "composite gate receipt"
    )
    automated_review = read_json_bytes(
        evidence_files["automated-review.json"], "automated review"
    )
    isolation_artifact = read_json_bytes(
        evidence_files["isolation-evidence.json"], "isolation evidence artifact"
    )
    plan = read_json_bytes(
        evidence_files["upstream-isolation-plan.json"], "upstream isolation plan"
    )
    lkg_binding = read_json_bytes(
        evidence_files["category-lkg-binding.json"], "category LKG binding"
    )
    sarif = read_json_bytes(
        evidence_files["gitleaks-composite.sarif"], "composite gitleaks SARIF"
    )
    if sarif.get("version") != "2.1.0" or not isinstance(sarif.get("runs"), list):
        raise CompositeVerificationError("composite gitleaks SARIF is malformed")
    if any(
        not isinstance(run, dict)
        or not isinstance(run.get("results", []), list)
        or run.get("results", [])
        for run in sarif["runs"]
    ):
        raise CompositeVerificationError("composite gitleaks SARIF contains findings")

    required_identity = {
        "schema": COMPOSITE_SCHEMA,
        "mode": "shadow-only",
        "enforcement_ready": False,
        "two_cycle_enforcement_eligible": False,
        "source_health_complete": False,
        "licensing_assertions_complete": False,
        "materializer_policy": MATERIALIZER_POLICY,
        "content_identity_schema": "project-g-upstream-isolation-content-identity-v1",
        "content_identity_kind": "selected-complete-category-output-v1",
        "observation_identity_schema": "project-g-upstream-isolation-observation-identity-v1",
        "observation_identity_kind": "exact-shadow-observation-v1",
        "exact_main_sha": expected_main_sha,
    }
    for field, expected in required_identity.items():
        if identity.get(field) != expected:
            raise CompositeVerificationError(f"composite identity {field} is invalid")
    content_identity = require_sha256(
        identity.get("composite_content_identity"), "composite content identity"
    )
    if content_identity != artifact.content_identity:
        raise CompositeVerificationError("artifact name does not bind content identity")
    for field in (
        "category_lkg_anchor_sha256",
        "category_contracts_sha256",
        "dist_tree_sha256",
        "isolation_observation_summary_sha256",
        "observation_evidence_identity",
        "policy_sha256",
        "review_sha256",
        "selected_source_lock_sha256",
        "selected_source_provenance_sha256",
        "semantic_digest",
        "source_config_sha256",
        "source_registry_sha256",
        "stable_selection_fingerprint",
    ):
        require_sha256(identity.get(field), f"composite identity {field}")
    selections = validate_category_selections(identity)
    content_payload = {
        "schema": identity["content_identity_schema"],
        "identity_kind": identity["content_identity_kind"],
        "materializer_policy": identity["materializer_policy"],
        "source_config_sha256": identity["source_config_sha256"],
        "policy_sha256": identity["policy_sha256"],
        "category_contracts_sha256": identity["category_contracts_sha256"],
        "source_registry_sha256": identity["source_registry_sha256"],
        "selected_source_lock_sha256": identity["selected_source_lock_sha256"],
        "category_selections": selections,
        "semantic_digest": identity["semantic_digest"],
    }
    if digest_payload(content_payload) != content_identity:
        raise CompositeVerificationError("composite content identity is not reproducible")

    review_digest = verify_self_digest(review, "review_sha256", "composite review")
    required_review = {
        "schema": REVIEW_SCHEMA,
        "mode": "shadow-only",
        "materialization_valid": True,
        "validation_complete": False,
        "publishable": False,
        "enforcement_ready": False,
        "materializer_policy": MATERIALIZER_POLICY,
        "exact_main_sha": expected_main_sha,
        "complete_category_bundles": True,
        "repository_atomicity_preserved": True,
        "category_removals_allowed": False,
        "fallback_cache_count": 0,
        "source_health_status": "unknown",
        "source_health_complete": False,
        "licensing_assertions_complete": False,
        "cross_action_conflict_count": 0,
        "high_severity_conflict_count": 0,
    }
    for field, expected in required_review.items():
        if review.get(field) != expected:
            raise CompositeVerificationError(f"composite review {field} is invalid")
    if review_digest != identity["review_sha256"]:
        raise CompositeVerificationError("identity review digest binding is invalid")
    if review.get("dist_tree_sha256") != identity["dist_tree_sha256"]:
        raise CompositeVerificationError("review dist tree binding is invalid")
    category_count = require_positive_int(review.get("category_count"), "review category count")
    if category_count != len(selections):
        raise CompositeVerificationError("review category count is inconsistent")
    origin_counts = {
        "observed-candidate": require_nonnegative_int(
            review.get("candidate_category_count"), "candidate category count"
        ),
        "published-lkg": require_nonnegative_int(
            review.get("published_lkg_category_count"), "published LKG category count"
        ),
        "derived-composite": require_nonnegative_int(
            review.get("derived_category_count"), "derived category count"
        ),
    }
    for origin, expected_count in origin_counts.items():
        if sum(1 for row in selections if row["snapshot_origin"] == origin) != expected_count:
            raise CompositeVerificationError(f"review {origin} count is inconsistent")
    changed_categories = require_sorted_strings(
        review.get("changed_categories"), "review changed categories"
    )

    required_gate = {
        "schema": GATE_SCHEMA,
        "mode": "shadow-only",
        "valid": True,
        "publishable": False,
        "source_health_complete": False,
        "licensing_assertions_complete": False,
        "exact_main_sha": expected_main_sha,
        "completed_gates": COMPLETED_GATES,
    }
    for field, expected in required_gate.items():
        if gate.get(field) != expected:
            raise CompositeVerificationError(f"composite gate {field} is invalid")
    verify_self_digest(gate, "receipt_sha256", "composite gate receipt")
    if (
        gate.get("composite_content_identity") != content_identity
        or gate.get("observation_evidence_identity")
        != identity["observation_evidence_identity"]
        or gate.get("dist_tree_sha256") != identity["dist_tree_sha256"]
        or gate.get("identity_file_sha256")
        != sha256_bytes(evidence_files["composite-identity.json"])
        or gate.get("review_file_sha256")
        != sha256_bytes(evidence_files["composite-review.json"])
    ):
        raise CompositeVerificationError("composite gate evidence binding is invalid")

    dist_files, dist_manifest = read_dist_tar(
        evidence_files["ruleset-composite-dist.tar.gz"]
    )
    if require_positive_int(identity.get("dist_file_count"), "dist file count") != len(
        dist_manifest
    ):
        raise CompositeVerificationError("identity dist file count is inconsistent")
    if digest_payload(dist_manifest) != identity["dist_tree_sha256"]:
        raise CompositeVerificationError("identity dist tree digest is not reproducible")
    required_dist_files = {
        "candidate_manifest.json",
        "fetch_report.json",
        "index.json",
        "rule_delta.json",
        "source_health.json",
    }
    if not required_dist_files.issubset(dist_files):
        raise CompositeVerificationError(
            f"composite dist lacks required files: {sorted(required_dist_files - set(dist_files))}"
        )
    candidate_manifest = read_json_bytes(
        dist_files["candidate_manifest.json"], "dist candidate manifest"
    )
    if (
        candidate_manifest.get("source_commit_sha") != expected_main_sha
        or candidate_manifest.get("materialization_mode")
        != "upstream-isolation-composite"
        or candidate_manifest.get("materializer_policy") != MATERIALIZER_POLICY
        or candidate_manifest.get("stable_selection_fingerprint")
        != identity["stable_selection_fingerprint"]
        or candidate_manifest.get("category_lkg_anchor_sha256")
        != identity["category_lkg_anchor_sha256"]
        or candidate_manifest.get("semantic_digest") != identity["semantic_digest"]
        or candidate_manifest.get("source_lock_sha256")
        != identity["selected_source_lock_sha256"]
    ):
        raise CompositeVerificationError("candidate manifest composite binding is invalid")

    index = read_json_bytes(dist_files["index.json"], "dist index")
    index_categories = index.get("categories")
    if not isinstance(index_categories, list):
        raise CompositeVerificationError("dist index categories are invalid")
    index_ids = [
        str(item.get("id", "")) if isinstance(item, dict) else ""
        for item in index_categories
    ]
    selection_ids = [str(item["category"]) for item in selections]
    if (
        any(not item for item in index_ids)
        or len(index_ids) != len(set(index_ids))
        or set(index_ids) != set(selection_ids)
        or index.get("category_count") != category_count
    ):
        raise CompositeVerificationError("dist index does not match category selections")
    validate_category_outputs(dist_files, index, selections)
    rule_delta = read_json_bytes(dist_files["rule_delta.json"], "dist rule delta")
    if (
        rule_delta.get("changed_categories") != changed_categories
        or rule_delta.get("changed") != bool(changed_categories)
        or rule_delta.get("changed_category_count") != len(changed_categories)
    ):
        raise CompositeVerificationError("dist rule delta changed categories are inconsistent")

    fetch_report = read_json_bytes(dist_files["fetch_report.json"], "fetch report")
    source_health = read_json_bytes(dist_files["source_health.json"], "source health")
    if (
        fetch_report.get("source_health_status") != "unknown"
        or fetch_report.get("source_health_complete") is not False
        or fetch_report.get("fallback_cache_count") != 0
        or fetch_report.get("fallback_events") != []
        or fetch_report.get("attempts") != []
        or fetch_report.get("materialization_mode") != "frozen-verified-snapshots"
        or fetch_report.get("source_health_basis")
        != "frozen-composite-snapshots-not-current-live-fetch-health"
        or source_health.get("status") != "unknown"
        or source_health.get("health_complete") is not False
        or source_health.get("health_basis")
        != "frozen-composite-snapshots-not-current-live-fetch-health"
        or source_health.get("fallback_cache_count") != 0
        or source_health.get("cache_blocked_source_ids") != []
    ):
        raise CompositeVerificationError("frozen composite health semantics are invalid")
    fetch_observation = validate_observation_summary(
        fetch_report.get("upstream_observation"), "fetch report"
    )
    health_observation = validate_observation_summary(
        source_health.get("upstream_observation"), "source health"
    )
    if fetch_observation != health_observation:
        raise CompositeVerificationError("frozen observation metadata is inconsistent")
    if (
        fetch_observation["summary_sha256"]
        != identity["isolation_observation_summary_sha256"]
        or review.get("isolation_observation_summary_sha256")
        != fetch_observation["summary_sha256"]
        or review.get("isolation_blocker_count") != fetch_observation["blocker_count"]
    ):
        raise CompositeVerificationError("observation summary binding is inconsistent")
    for review_field, observation_field in (
        ("isolated_source_ids", "isolated_source_ids"),
        ("quarantined_categories", "quarantined_categories"),
        ("held_categories", "held_categories"),
    ):
        if review.get(review_field) != fetch_observation[observation_field]:
            raise CompositeVerificationError(
                f"review {review_field} is inconsistent with observation metadata"
            )

    containment_digest = validate_automated_and_containment(
        automated_review=automated_review,
        isolation_artifact=isolation_artifact,
        plan=plan,
        lkg_binding=lkg_binding,
        identity=identity,
        review=review,
        expected_main_sha=expected_main_sha,
    )
    payload_digest = stable_payload_digest(dist_files, fetch_report, source_health)
    return CycleEvidence(
        artifact=artifact,
        remote=remote,
        cycle_dir=cycle_dir,
        evidence_sha256=evidence_sha256,
        dist_archive_sha256=inner_sha256,
        evidence_files=evidence_files,
        identity=identity,
        review=review,
        gate=gate,
        automated_review=automated_review,
        isolation_artifact=isolation_artifact,
        plan=plan,
        lkg_binding=lkg_binding,
        containment_boundary_sha256=containment_digest,
        stable_payload_sha256=payload_digest,
        dist_files=dist_files,
        dist_manifest=dist_manifest,
        candidate_manifest=candidate_manifest,
        fetch_report=fetch_report,
        source_health=source_health,
    )


def normalized_identity(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(payload)
    for field in (
        "dist_tree_sha256",
        "generated_at_utc",
        "isolation_observation_summary_sha256",
        "observation_evidence_identity",
        "review_sha256",
    ):
        normalized.pop(field, None)
    return normalized


def normalized_review(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(payload)
    for field in (
        "dist_tree_sha256",
        "isolation_blocker_count",
        "isolation_observation_summary_sha256",
        "review_sha256",
    ):
        normalized.pop(field, None)
    return normalized


def validate_pair(current: CycleEvidence, previous: CycleEvidence) -> int:
    if current.remote.run_id == previous.remote.run_id:
        raise CompositeVerificationError("composite cycle run IDs are not distinct")
    if current.remote.artifact_id == previous.remote.artifact_id:
        raise CompositeVerificationError("composite artifact IDs are not distinct")
    separation = current.remote.run_started_epoch - previous.remote.run_started_epoch
    if separation < 300:
        raise CompositeVerificationError("composite cycles are less than 300 seconds apart")
    if current.artifact.source_sha != previous.artifact.source_sha:
        raise CompositeVerificationError("composite cycles use different source commits")
    if current.artifact.content_identity != previous.artifact.content_identity:
        raise CompositeVerificationError("composite content identity is not stable")
    if current.identity["stable_selection_fingerprint"] != previous.identity[
        "stable_selection_fingerprint"
    ]:
        raise CompositeVerificationError("composite selection fingerprint is not stable")
    if current.containment_boundary_sha256 != previous.containment_boundary_sha256:
        raise CompositeVerificationError("composite containment boundary is not stable")
    if current.stable_payload_sha256 != previous.stable_payload_sha256:
        raise CompositeVerificationError("normalized stable composite payload changed")
    if normalized_identity(current.identity) != normalized_identity(previous.identity):
        raise CompositeVerificationError("stable composite identity fields changed")
    if normalized_review(current.review) != normalized_review(previous.review):
        raise CompositeVerificationError("stable composite review fields changed")
    if current.lkg_binding != previous.lkg_binding:
        raise CompositeVerificationError("category LKG binding changed across cycles")
    if current.plan.get("stable_selection") != previous.plan.get("stable_selection"):
        raise CompositeVerificationError("stable isolation selection changed across cycles")
    current_paths = set(current.dist_files)
    previous_paths = set(previous.dist_files)
    if current_paths != previous_paths:
        raise CompositeVerificationError("composite dist file set changed across cycles")
    unexpected_differences = sorted(
        path
        for path in current_paths - VOLATILE_DIST_FILES
        if current.dist_files[path] != previous.dist_files[path]
    )
    if unexpected_differences:
        raise CompositeVerificationError(
            "stable composite payload changed outside observation files: "
            + ", ".join(unexpected_differences[:20])
        )
    for name, current_payload, previous_payload in (
        ("fetch_report.json", current.fetch_report, previous.fetch_report),
        ("source_health.json", current.source_health, previous.source_health),
    ):
        current_normalized = copy.deepcopy(current_payload)
        previous_normalized = copy.deepcopy(previous_payload)
        current_normalized.pop("upstream_observation", None)
        previous_normalized.pop("upstream_observation", None)
        if current_normalized != previous_normalized:
            raise CompositeVerificationError(
                f"{name} changed outside the approved upstream observation object"
            )
    return separation


def prepare_current_artifact(cycle: CycleEvidence, destination: pathlib.Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or not destination.is_dir():
        raise CompositeVerificationError("prepared artifact destination is invalid")
    copies = {
        "automated-review.json": cycle.evidence_files["automated-review.json"],
        "category-lkg-binding.json": cycle.evidence_files["category-lkg-binding.json"],
        "composite-gate-receipt.json": cycle.evidence_files[
            "composite-gate-receipt.json"
        ],
        "composite-identity.json": cycle.evidence_files["composite-identity.json"],
        "composite-review.json": cycle.evidence_files["composite-review.json"],
        "gitleaks-composite.sarif": cycle.evidence_files["gitleaks-composite.sarif"],
        "isolation-evidence.json": cycle.evidence_files["isolation-evidence.json"],
        "ruleset-dist.tar.gz": cycle.evidence_files["ruleset-composite-dist.tar.gz"],
        "upstream-isolation-composite-evidence.tar": (
            read_artifact_zip(
                cycle.cycle_dir / "artifact.zip",
                expected_digest=cycle.remote.artifact_api_digest,
                expected_size=cycle.remote.artifact_size,
            )[0]["upstream-isolation-composite-evidence.tar"]
        ),
        "upstream-isolation-composite-evidence.sha256": (
            read_artifact_zip(
                cycle.cycle_dir / "artifact.zip",
                expected_digest=cycle.remote.artifact_api_digest,
                expected_size=cycle.remote.artifact_size,
            )[0]["upstream-isolation-composite-evidence.sha256"]
        ),
        "upstream-isolation-plan.json": cycle.evidence_files[
            "upstream-isolation-plan.json"
        ],
    }
    expected = set(copies) | {"ruleset-dist.sha256"}
    existing = {path.name for path in destination.iterdir()}
    if existing - expected:
        raise CompositeVerificationError("prepared artifact directory has unexpected files")
    for name, payload in copies.items():
        target = destination / name
        if target.exists() and (target.is_symlink() or not target.is_file()):
            raise CompositeVerificationError(f"refusing prepared unsafe target: {target}")
        target.write_bytes(payload)
    (destination / "ruleset-dist.sha256").write_text(
        f"{cycle.dist_archive_sha256}  ruleset-dist.tar.gz\n",
        encoding="utf-8",
    )


def cycle_receipt(cycle: CycleEvidence) -> dict[str, Any]:
    return {
        "run_id": cycle.remote.run_id,
        "run_attempt": cycle.remote.run_attempt,
        "run_started_at": cycle.remote.run_started_at,
        "artifact_id": cycle.remote.artifact_id,
        "artifact_name": cycle.artifact.name,
        "artifact_api_digest": cycle.remote.artifact_api_digest,
        "artifact_size_in_bytes": cycle.remote.artifact_size,
        "artifact_zip_sha256": cycle.remote.artifact_zip_sha256,
        "outer_evidence_sha256": cycle.evidence_sha256,
        "dist_archive_sha256": cycle.dist_archive_sha256,
        "dist_tree_sha256": cycle.identity["dist_tree_sha256"],
        "observation_evidence_identity": cycle.identity[
            "observation_evidence_identity"
        ],
        "inner_attestation_tlog_timestamp": cycle.remote.inner_tlog_timestamp,
        "outer_attestation_tlog_timestamp": cycle.remote.outer_tlog_timestamp,
    }


def build_pair_receipt(
    *,
    current: CycleEvidence,
    previous: CycleEvidence,
    cycle_separation_seconds: int,
) -> dict[str, Any]:
    changed_categories = list(current.review["changed_categories"])
    decision = (
        "NOOP_NOT_ELIGIBLE"
        if not changed_categories
        else "REQUIRES_PROMOTION_AUTHORIZATION"
    )
    payload = {
        "schema": PAIR_SCHEMA,
        "eligible": False,
        "publication_authority": False,
        "decision": decision,
        "source_sha": current.artifact.source_sha,
        "composite_content_identity": current.artifact.content_identity,
        "stable_selection_fingerprint": current.identity[
            "stable_selection_fingerprint"
        ],
        "stable_payload_sha256": current.stable_payload_sha256,
        "containment_boundary_sha256": current.containment_boundary_sha256,
        "semantic_digest": current.identity["semantic_digest"],
        "selected_source_lock_sha256": current.identity[
            "selected_source_lock_sha256"
        ],
        "category_lkg_anchor_sha256": current.identity[
            "category_lkg_anchor_sha256"
        ],
        "changed_categories": changed_categories,
        "changed_category_count": len(changed_categories),
        "category_count": current.review["category_count"],
        "candidate_category_count": current.review["candidate_category_count"],
        "published_lkg_category_count": current.review[
            "published_lkg_category_count"
        ],
        "derived_category_count": current.review["derived_category_count"],
        "minimum_cycle_separation_seconds": 300,
        "cycle_separation_seconds": cycle_separation_seconds,
        "allowed_cycle_variant_dist_files": sorted(VOLATILE_DIST_FILES),
        "current": cycle_receipt(current),
        "previous": cycle_receipt(previous),
    }
    payload["receipt_sha256"] = digest_payload(payload)
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify two run-bound upstream-isolation composite v2 artifacts and "
            "emit a non-authoritative stability receipt."
        )
    )
    parser.add_argument("--current-cycle-dir", type=pathlib.Path, required=True)
    parser.add_argument("--previous-cycle-dir", type=pathlib.Path, required=True)
    parser.add_argument("--expected-main-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--workflow-path", default=".github/workflows/source-discovery.yml"
    )
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--prepare-current-dir", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not SHA1_RE.fullmatch(args.expected_main_sha):
            raise CompositeVerificationError(
                "expected main must be a 40-character lowercase commit SHA"
            )
        if not REPOSITORY_RE.fullmatch(args.repository):
            raise CompositeVerificationError("repository must be owner/name")
        if args.workflow_path != ".github/workflows/source-discovery.yml":
            raise CompositeVerificationError("unexpected Source Discovery workflow path")
        current = validate_cycle(
            args.current_cycle_dir,
            repository=args.repository,
            workflow_path=args.workflow_path,
            expected_main_sha=args.expected_main_sha,
        )
        previous = validate_cycle(
            args.previous_cycle_dir,
            repository=args.repository,
            workflow_path=args.workflow_path,
            expected_main_sha=args.expected_main_sha,
        )
        separation = validate_pair(current, previous)
        receipt = build_pair_receipt(
            current=current,
            previous=previous,
            cycle_separation_seconds=separation,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_bytes(receipt))
        if args.prepare_current_dir is not None:
            prepare_current_artifact(current, args.prepare_current_dir)
        print(
            "[upstream-composite-verify] "
            f"decision={receipt['decision']} "
            f"identity={receipt['composite_content_identity']} "
            f"changed={receipt['changed_category_count']} "
            f"runs={previous.remote.run_id}..{current.remote.run_id}"
        )
        return 0
    except (CompositeVerificationError, OSError) as exc:
        print(f"[upstream-composite-verify] error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
