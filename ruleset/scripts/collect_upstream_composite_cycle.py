#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

try:
    from ruleset.scripts import verify_upstream_composite as verifier
except ModuleNotFoundError:
    import verify_upstream_composite as verifier  # type: ignore[no-redef]


class CompositeCollectionError(RuntimeError):
    pass


def gh_bytes(*args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["gh", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = ""
        if isinstance(exc, subprocess.CalledProcessError):
            stderr = exc.stderr.decode("utf-8", errors="replace").strip()
        raise CompositeCollectionError(
            f"GitHub CLI command failed: {' '.join(args[:2])}: {stderr}"
        ) from exc
    return completed.stdout


def gh_json(*args: str) -> dict[str, Any]:
    value = verifier.read_json_bytes(gh_bytes(*args), "GitHub API response")
    return value


def verified_attestation(
    *,
    subject: pathlib.Path,
    repository: str,
    workflow_path: str,
    source_sha: str,
) -> bytes:
    return gh_bytes(
        "attestation",
        "verify",
        str(subject),
        "--repo",
        repository,
        "--signer-workflow",
        f"{repository}/{workflow_path}",
        "--signer-digest",
        source_sha,
        "--source-digest",
        source_sha,
        "--source-ref",
        "refs/heads/main",
        "--deny-self-hosted-runners",
        "--format",
        "json",
    )


def collect(args: argparse.Namespace) -> None:
    if not verifier.REPOSITORY_RE.fullmatch(args.repository):
        raise CompositeCollectionError("repository must be owner/name")
    if not verifier.SHA1_RE.fullmatch(args.expected_main_sha):
        raise CompositeCollectionError("expected main SHA is invalid")
    if not str(args.run_id).isdigit() or int(args.run_id) <= 0:
        raise CompositeCollectionError("run ID is invalid")
    if args.workflow_path != ".github/workflows/source-discovery.yml":
        raise CompositeCollectionError("workflow path is invalid")
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
        raise CompositeCollectionError("output directory must be empty and regular")

    run = gh_json(
        "api", f"repos/{args.repository}/actions/runs/{args.run_id}"
    )
    if (
        run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != args.expected_main_sha
        or run.get("path") != args.workflow_path
        or run.get("event") not in verifier.ALLOWED_EVENTS
        or not isinstance(run.get("head_repository"), dict)
        or run["head_repository"].get("full_name") != args.repository
    ):
        raise CompositeCollectionError("Source Discovery run identity is invalid")
    artifacts = gh_json(
        "api",
        f"repos/{args.repository}/actions/runs/{args.run_id}/artifacts?per_page=100",
    )
    raw_artifacts = artifacts.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise CompositeCollectionError("artifact listing is malformed")
    matches = [
        item
        for item in raw_artifacts
        if isinstance(item, dict)
        and item.get("expired") is False
        and isinstance(item.get("name"), str)
        and verifier.ARTIFACT_RE.fullmatch(item["name"])
    ]
    if len(matches) != 1:
        raise CompositeCollectionError(
            f"run must contain exactly one composite v2 artifact, found {len(matches)}"
        )
    artifact = matches[0]
    artifact_id = verifier.require_positive_int(artifact.get("id"), "artifact ID")
    artifact_name = str(artifact.get("name", ""))
    parsed_name = verifier.parse_artifact_name(artifact_name)
    if parsed_name.source_sha != args.expected_main_sha:
        raise CompositeCollectionError("artifact name source is not expected main")
    workflow_run = artifact.get("workflow_run")
    if not isinstance(workflow_run, dict) or workflow_run.get("id") != int(args.run_id):
        raise CompositeCollectionError("artifact is not bound to the requested run")

    archive_path = output / "artifact.zip"
    archive_path.write_bytes(
        gh_bytes(
            "api",
            f"repos/{args.repository}/actions/artifacts/{artifact_id}/zip",
        )
    )
    artifact_files, _zip_digest = verifier.read_artifact_zip(
        archive_path,
        expected_digest=str(artifact.get("digest", "")),
        expected_size=verifier.require_positive_int(
            artifact.get("size_in_bytes"), "artifact size"
        ),
    )
    evidence = artifact_files["upstream-isolation-composite-evidence.tar"]
    evidence_files = verifier.read_exact_evidence_tar(evidence)
    inner = evidence_files["ruleset-composite-dist.tar.gz"]
    with tempfile.TemporaryDirectory(prefix="project-g-attestation-subjects.") as raw:
        subjects = pathlib.Path(raw)
        inner_path = subjects / "ruleset-composite-dist.tar.gz"
        outer_path = subjects / "upstream-isolation-composite-evidence.tar"
        inner_path.write_bytes(inner)
        outer_path.write_bytes(evidence)
        (output / "inner-attestation.json").write_bytes(
            verified_attestation(
                subject=inner_path,
                repository=args.repository,
                workflow_path=args.workflow_path,
                source_sha=args.expected_main_sha,
            )
        )
        (output / "outer-attestation.json").write_bytes(
            verified_attestation(
                subject=outer_path,
                repository=args.repository,
                workflow_path=args.workflow_path,
                source_sha=args.expected_main_sha,
            )
        )

    metadata = {
        "schema": verifier.CYCLE_METADATA_SCHEMA,
        "repository": args.repository,
        "workflow_path": args.workflow_path,
        "run": {
            "id": int(args.run_id),
            "run_attempt": run.get("run_attempt"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "head_branch": run.get("head_branch"),
            "head_sha": run.get("head_sha"),
            "head_repository": run["head_repository"].get("full_name"),
            "path": run.get("path"),
            "event": run.get("event"),
            "created_at": run.get("created_at"),
            "run_started_at": run.get("run_started_at"),
            "updated_at": run.get("updated_at"),
        },
        "artifact": {
            "id": artifact_id,
            "name": artifact_name,
            "digest": artifact.get("digest"),
            "size_in_bytes": artifact.get("size_in_bytes"),
            "expired": artifact.get("expired"),
            "workflow_run_id": workflow_run.get("id"),
        },
    }
    (output / "metadata.json").write_bytes(verifier.canonical_bytes(metadata))
    verifier.validate_remote_identity(
        output,
        repository=args.repository,
        workflow_path=args.workflow_path,
        expected_main_sha=args.expected_main_sha,
    )
    print(
        "[upstream-composite-collect] "
        f"run={args.run_id} artifact={artifact_id} name={artifact_name}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collect one exact GitHub Source Discovery composite v2 cycle with "
            "run-bound inner and outer attestation evidence."
        )
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--expected-main-sha", required=True)
    parser.add_argument(
        "--workflow-path", default=".github/workflows/source-discovery.yml"
    )
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        collect(args)
        return 0
    except (
        CompositeCollectionError,
        verifier.CompositeVerificationError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        print(f"[upstream-composite-collect] error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
