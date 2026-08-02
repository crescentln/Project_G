#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile
from typing import Any


EMPTY_BLOB_SHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class VerifyError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[verify-published] {message}")


def gh_json(path: str) -> Any:
    command = ["gh", "api", path]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise VerifyError(
            f"GitHub API request failed for {path}: {result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise VerifyError(f"GitHub API returned invalid JSON for {path}") from exc


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def archive_dist_tree(path: pathlib.Path) -> dict[str, str]:
    files: dict[str, str] = {}
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                member_path = pathlib.PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                    or member_path.parts[0] != "dist"
                    or member.issym()
                    or member.islnk()
                    or not (member.isfile() or member.isdir())
                ):
                    raise VerifyError(f"unsafe archive member: {member.name}")
                if member.isdir():
                    continue
                relative = pathlib.PurePosixPath(*member_path.parts[1:]).as_posix()
                if not relative or relative in files:
                    raise VerifyError(f"duplicate archive member: {member.name}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise VerifyError(f"archive member cannot be read: {member.name}")
                files[relative] = git_blob_sha(extracted.read())
    except (tarfile.TarError, OSError) as exc:
        raise VerifyError(f"invalid release archive: {exc}") from exc
    if not files:
        raise VerifyError("release archive contains no dist files")
    return files


def remote_dist_tree(repository: str, sha: str) -> dict[str, str]:
    commit = gh_json(f"repos/{repository}/git/commits/{sha}")
    tree_sha = str(commit.get("tree", {}).get("sha", "")).lower()
    if not SHA_RE.fullmatch(tree_sha):
        raise VerifyError("published commit has an invalid tree")
    tree = gh_json(f"repos/{repository}/git/trees/{tree_sha}?recursive=1")
    if tree.get("truncated"):
        raise VerifyError("published Git tree response was truncated")
    prefix = "ruleset/dist/"
    return {
        str(item.get("path", ""))[len(prefix) :]: str(item.get("sha", "")).lower()
        for item in tree.get("tree", [])
        if isinstance(item, dict)
        and item.get("type") == "blob"
        and str(item.get("path", "")).startswith(prefix)
    }


def peel_tag(repository: str, tag: str) -> str:
    payload = gh_json(f"repos/{repository}/git/ref/tags/{tag}")
    obj = payload.get("object", {})
    for _ in range(4):
        object_type = str(obj.get("type", ""))
        object_sha = str(obj.get("sha", "")).lower()
        if object_type == "commit" and SHA_RE.fullmatch(object_sha):
            return object_sha
        if object_type != "tag" or not SHA_RE.fullmatch(object_sha):
            break
        tag_payload = gh_json(f"repos/{repository}/git/tags/{object_sha}")
        obj = tag_payload.get("object", {})
    raise VerifyError(f"tag did not peel to a commit: {tag}")


def verify_empty_readme(repository: str, sha: str, *, label: str) -> None:
    readme = gh_json(f"repos/{repository}/contents/README.md?ref={sha}")
    if int(readme.get("size", -1)) != 0:
        raise VerifyError(f"{label} public root README.md is not zero bytes")
    if str(readme.get("sha", "")).lower() != EMPTY_BLOB_SHA:
        raise VerifyError(f"{label} public root README.md is not the empty Git blob")


def verified_category_count(repository: str, sha: str, *, label: str) -> int:
    raw_index = gh_json(
        f"repos/{repository}/contents/ruleset/dist/index.json?ref={sha}"
    )
    try:
        index_bytes = base64.b64decode(
            str(raw_index["content"]).replace("\n", ""),
            validate=True,
        )
        index = json.loads(index_bytes.decode("utf-8", errors="strict"))
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifyError(f"{label} raw index could not be decoded") from exc
    category_count = int(index.get("category_count", 0))
    if category_count <= 0:
        raise VerifyError(f"{label} raw index has no categories")
    return category_count


def require_published_status(repository: str, sha: str) -> int:
    combined = gh_json(f"repos/{repository}/commits/{sha}/status")
    statuses = combined.get("statuses", [])
    if not isinstance(statuses, list):
        raise VerifyError("published commit status response is malformed")
    latest = max(
        (
            item
            for item in statuses
            if isinstance(item, dict)
            and str(item.get("context", "")) == "ruleset/published"
        ),
        key=lambda item: (
            str(item.get("updated_at") or item.get("created_at") or ""),
            int(item.get("id", 0)),
        ),
        default=None,
    )
    if not isinstance(latest, dict) or latest.get("state") != "success":
        raise VerifyError("published commit lacks a latest successful ruleset/published status")
    avatar_url = str(latest.get("avatar_url", ""))
    if not re.fullmatch(
        r"https://avatars\.githubusercontent\.com/in/15368(?:\?.*)?",
        avatar_url,
    ):
        raise VerifyError("ruleset/published status is not bound to GitHub Actions App 15368")
    target_url = str(latest.get("target_url", ""))
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(repository)}/actions/runs/([0-9]+)",
        target_url,
    )
    if match is None:
        raise VerifyError("ruleset/published status target is not a repository Actions run")
    run_id = int(match.group(1))
    run = gh_json(f"repos/{repository}/actions/runs/{run_id}")
    if (
        run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("path") != ".github/workflows/ruleset-update.yml"
        or run.get("repository", {}).get("full_name") != repository
    ):
        raise VerifyError("ruleset/published status does not resolve to a successful promotion run")
    return run_id


def verify(args: argparse.Namespace) -> None:
    if not SHA_RE.fullmatch(args.sha):
        raise VerifyError("--sha must be a 40-character lowercase commit SHA")
    archive_digest = sha256_file(args.archive)
    checksum_lines = [
        line.strip()
        for line in args.checksum.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(checksum_lines) != 1:
        raise VerifyError("checksum file must contain exactly one non-empty line")
    declared_digest = checksum_lines[0].split(None, 1)[0].lower()
    if declared_digest != archive_digest:
        raise VerifyError("local archive digest does not match checksum file")
    checksum_parts = checksum_lines[0].split()
    if len(checksum_parts) != 2 or checksum_parts[1].lstrip("*") != args.archive.name:
        raise VerifyError("checksum file does not name the release archive")

    if args.skip_main and args.main_sha:
        raise VerifyError("--skip-main and --main-sha cannot be combined")
    if args.main_sha and not SHA_RE.fullmatch(args.main_sha):
        raise VerifyError("--main-sha must be a 40-character lowercase commit SHA")

    main_sha = ""
    if not args.skip_main:
        main = gh_json(f"repos/{args.repository}/commits/main")
        main_sha = str(main.get("sha", "")).lower()
        expected_main = args.main_sha or args.sha
        if main_sha != expected_main:
            raise VerifyError(
                f"remote main mismatch: expected={expected_main} actual={main.get('sha')}"
            )
        if args.main_sha and args.sha != args.main_sha:
            comparison = gh_json(
                f"repos/{args.repository}/compare/{args.sha}...{args.main_sha}"
            )
            if comparison.get("status") not in {"ahead", "identical"}:
                raise VerifyError("canonical release commit is not an ancestor of current main")
    peeled = peel_tag(args.repository, args.tag)
    if peeled != args.sha:
        raise VerifyError(
            f"tag target mismatch: expected={args.sha} actual={peeled}"
        )

    release = gh_json(f"repos/{args.repository}/releases/tags/{args.tag}")
    if str(release.get("tag_name", "")) != args.tag:
        raise VerifyError("release tag mismatch")
    if release.get("draft") or release.get("prerelease"):
        raise VerifyError("release must be final, not draft or prerelease")
    if release.get("immutable") is not True:
        raise VerifyError("release immutability is absent or not enabled")
    assets = {
        str(item.get("name", "")): item
        for item in release.get("assets", [])
        if isinstance(item, dict)
    }
    archive_asset = assets.get(args.archive.name)
    checksum_asset = assets.get(args.checksum.name)
    if archive_asset is None or checksum_asset is None:
        raise VerifyError("release is missing archive or checksum asset")
    remote_digest = str(archive_asset.get("digest", "")).lower()
    if remote_digest != f"sha256:{archive_digest}":
        raise VerifyError(
            f"release archive digest mismatch: expected=sha256:{archive_digest} "
            f"actual={remote_digest}"
        )
    checksum_digest = sha256_file(args.checksum)
    remote_checksum_digest = str(checksum_asset.get("digest", "")).lower()
    if remote_checksum_digest != f"sha256:{checksum_digest}":
        raise VerifyError(
            "release checksum asset digest mismatch: "
            f"expected=sha256:{checksum_digest} actual={remote_checksum_digest}"
        )

    archive_tree = archive_dist_tree(args.archive)
    published_tree = remote_dist_tree(args.repository, args.sha)
    if archive_tree != published_tree:
        missing = sorted(set(archive_tree) - set(published_tree))
        extra = sorted(set(published_tree) - set(archive_tree))
        changed = sorted(
            item
            for item in set(archive_tree) & set(published_tree)
            if archive_tree[item] != published_tree[item]
        )
        raise VerifyError(
            "release archive does not match published dist tree: "
            f"missing={len(missing)} extra={len(extra)} changed={len(changed)}"
        )
    verify_empty_readme(args.repository, args.sha, label="release")
    category_count = verified_category_count(
        args.repository, args.sha, label="release"
    )
    if args.main_sha:
        current_tree = remote_dist_tree(args.repository, args.main_sha)
        if current_tree != archive_tree:
            raise VerifyError(
                "current main dist tree does not converge with canonical release archive"
            )
        verify_empty_readme(args.repository, args.main_sha, label="main")
        main_category_count = verified_category_count(
            args.repository, args.main_sha, label="main"
        )
        if main_category_count != category_count:
            raise VerifyError("release and main category counts differ")
    promotion_run_id = None
    if args.require_published_status:
        promotion_run_id = require_published_status(args.repository, args.sha)

    log(
        f"verified main={'skipped' if args.skip_main else main_sha} "
        f"tag={args.tag} release-assets=2+ dist_files={len(archive_tree)} "
        f"archive_sha256={archive_digest} categories={category_count} "
        f"promotion_run={promotion_run_id or 'not-required'} "
        "root_readme_bytes=0"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a published Project_G main/tag/release/raw snapshot."
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument(
        "--main-sha",
        default="",
        help="Allow code-only main advancement while requiring an identical dist tree.",
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--archive", type=pathlib.Path, required=True)
    parser.add_argument("--checksum", type=pathlib.Path, required=True)
    parser.add_argument(
        "--skip-main",
        action="store_true",
        help="Verify the commit, tag, release, assets, and tree before moving main.",
    )
    parser.add_argument(
        "--require-published-status",
        action="store_true",
        help="Require the latest ruleset/published status to resolve to a successful promotion run.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        verify(args)
        return 0
    except (VerifyError, FileNotFoundError, UnicodeDecodeError) as exc:
        log(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
