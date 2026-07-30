#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


USER_AGENT = "project-g-source-radar/1.0"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class RadarError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[source-radar] {message}")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RadarError(f"missing file: {path}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RadarError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RadarError(f"JSON root must be an object: {path}")
    return payload


def github_api(path: str) -> tuple[dict[str, Any], dict[str, str]]:
    encoded_path = urllib.parse.quote(path, safe="/?=&")
    url = f"https://api.github.com/{encoded_path.lstrip('/')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise RadarError(f"GitHub response exceeded 8 MiB: {path}")
            validators = {
                "etag": str(response.headers.get("ETag", "")).strip(),
                "last_modified": str(response.headers.get("Last-Modified", "")).strip(),
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RadarError(f"GitHub API request failed for {path}: {exc}") from exc
    try:
        payload = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RadarError(f"GitHub API returned invalid JSON for {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RadarError(f"GitHub API response root must be an object: {path}")
    return payload, validators


def discover(
    config: dict[str, Any],
    baseline: dict[str, Any],
    source_lock: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    previous = {
        str(item.get("repository", "")): str(item.get("resolved_revision", ""))
        for item in baseline.get("repositories", [])
        if isinstance(item, dict)
    }
    rows: list[dict[str, Any]] = []
    changed: list[str] = []
    repositories = config.get("repositories", [])
    if not isinstance(repositories, list) or not repositories:
        raise RadarError("source radar config requires repositories")
    locked_repositories = source_lock.get("repositories", {})
    if not isinstance(locked_repositories, dict):
        raise RadarError("source lock repositories must be an object")

    for raw in repositories:
        if not isinstance(raw, dict):
            raise RadarError("source radar repository entries must be objects")
        repository = str(raw.get("repository", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise RadarError(f"invalid repository: {repository}")
        repo, _repo_validators = github_api(f"repos/{repository}")
        default_branch = str(repo.get("default_branch", "")).strip()
        if not default_branch:
            raise RadarError(f"repository has no default branch: {repository}")
        commit, validators = github_api(
            f"repos/{repository}/commits/{urllib.parse.quote(default_branch, safe='')}"
        )
        revision = str(commit.get("sha", "")).strip().lower()
        if not SHA_RE.fullmatch(revision):
            raise RadarError(f"repository returned invalid revision: {repository}")
        head_tree_revision = str(
            commit.get("commit", {}).get("tree", {}).get("sha", "")
        ).strip().lower()
        if not SHA_RE.fullmatch(head_tree_revision):
            raise RadarError(f"repository returned invalid tree revision: {repository}")
        lock_row = locked_repositories.get(repository, {})
        locked_revision = (
            str(lock_row.get("resolved_revision", "")).strip().lower()
            if isinstance(lock_row, dict)
            else ""
        )
        baseline_revision = previous.get(repository, "")
        comparison_revision = baseline_revision or locked_revision
        comparison_basis = (
            "baseline"
            if baseline_revision
            else "source-lock"
            if locked_revision
            else "none"
        )
        committed_at = str(
            commit.get("commit", {}).get("committer", {}).get("date", "")
        ).strip()
        row = {
            "repository": repository,
            "ecosystem": str(raw.get("ecosystem", "")),
            "trust_tier": str(raw.get("trust_tier", "")),
            "role": str(raw.get("role", "independent-radar")),
            "candidate_only": bool(raw.get("candidate_only", True)),
            "default_branch": default_branch,
            "resolved_revision": revision,
            "head_tree_revision": head_tree_revision,
            "committed_at_utc": committed_at,
            "locked_revision": locked_revision,
            "previous_revision": comparison_revision,
            "comparison_basis": comparison_basis,
            "changed": bool(comparison_revision and comparison_revision != revision),
            "etag": validators["etag"],
            "last_modified": validators["last_modified"],
        }
        if row["changed"]:
            changed.append(repository)
        rows.append(row)

    v2fly_tree: dict[str, Any] = {}
    lock_entry = (
        source_lock.get("repositories", {})
        .get("v2fly/domain-list-community", {})
    )
    if isinstance(lock_entry, dict) and lock_entry.get("tree_revision"):
        locked_tree_revision = str(lock_entry["tree_revision"]).strip().lower()
        if not SHA_RE.fullmatch(locked_tree_revision):
            raise RadarError("v2fly source lock has an invalid tree revision")
        v2fly_row = next(
            (
                row
                for row in rows
                if row["repository"] == "v2fly/domain-list-community"
            ),
            None,
        )
        if v2fly_row is None:
            raise RadarError("source radar config is missing active v2fly repository")
        head_tree_revision = str(v2fly_row["head_tree_revision"])

        def load_tree_files(tree_revision: str) -> dict[str, str]:
            tree_payload, _validators = github_api(
                "repos/v2fly/domain-list-community/git/trees/"
                f"{tree_revision}?recursive=1"
            )
            if tree_payload.get("truncated"):
                raise RadarError(
                    f"v2fly recursive tree response was truncated: {tree_revision}"
                )
            return {
                str(item.get("path", "")): str(item.get("sha", ""))
                for item in tree_payload.get("tree", [])
                if isinstance(item, dict)
                and item.get("type") == "blob"
                and str(item.get("path", "")).startswith("data/")
                and len(pathlib.PurePosixPath(str(item.get("path", ""))).parts)
                == 2
            }

        locked_files = load_tree_files(locked_tree_revision)
        head_files = (
            locked_files
            if head_tree_revision == locked_tree_revision
            else load_tree_files(head_tree_revision)
        )
        reachable = {
            str(file_row.get("path", ""))
            for source in provenance.get("sources", [])
            if isinstance(source, dict) and source.get("type") == "v2fly_dlc"
            for file_row in source.get("files", [])
            if isinstance(file_row, dict) and str(file_row.get("path", ""))
        }
        previous_files = {
            str(item.get("path", "")): str(item.get("blob_sha", ""))
            for item in baseline.get("v2fly_tree", {}).get("files", [])
            if isinstance(item, dict)
        }
        current_paths = set(head_files)
        previous_paths = set(previous_files)
        new_paths = sorted(current_paths - previous_paths) if previous_files else []
        removed_paths = sorted(previous_paths - current_paths)
        changed_paths = sorted(
            path
            for path in current_paths & previous_paths
            if head_files[path] != previous_files[path]
        )
        locked_paths = set(locked_files)
        head_new_paths = sorted(current_paths - locked_paths)
        head_removed_paths = sorted(locked_paths - current_paths)
        head_changed_paths = sorted(
            path
            for path in current_paths & locked_paths
            if head_files[path] != locked_files[path]
        )
        v2fly_tree = {
            "tree_revision": head_tree_revision,
            "file_count": len(head_files),
            "reachable_file_count": len(current_paths & reachable),
            "isolated_file_count": len(current_paths - reachable),
            "new_files_since_baseline": new_paths,
            "removed_files_since_baseline": removed_paths,
            "changed_files_since_baseline": changed_paths,
            "isolated_files": sorted(current_paths - reachable),
            "unbuilt_head_files": sorted(
                set(head_new_paths) | set(head_changed_paths)
            ),
            "locked_tree": {
                "tree_revision": locked_tree_revision,
                "file_count": len(locked_files),
                "reachable_file_count": len(locked_paths & reachable),
                "isolated_file_count": len(locked_paths - reachable),
                "isolated_files": sorted(locked_paths - reachable),
            },
            "head_vs_lock": {
                "head_advanced_after_lock": bool(
                    v2fly_row["resolved_revision"]
                    != v2fly_row["locked_revision"]
                ),
                "new_files": head_new_paths,
                "removed_files": head_removed_paths,
                "changed_files": head_changed_paths,
            },
            "files": [
                {"path": path, "blob_sha": head_files[path]}
                for path in sorted(head_files)
            ],
            "policy": "isolated or newly discovered files remain candidate-only",
        }

    return {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "candidate_only": bool(config.get("candidate_only", True)),
        "high_impact_quorum": int(config.get("high_impact_quorum", 2)),
        "changed_repository_count": len(changed),
        "changed_repositories": changed,
        "repositories": rows,
        "v2fly_tree": v2fly_tree,
        "manual_only_categories": config.get("manual_only_categories", []),
        "policy": config.get("policy", {}),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only radar for upstream ruleset ecosystems."
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/config/source_radar.json"),
    )
    parser.add_argument("--baseline", type=pathlib.Path, default=None)
    parser.add_argument("--source-lock", type=pathlib.Path, required=True)
    parser.add_argument("--provenance", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = read_json(args.config)
        baseline: dict[str, Any] = {}
        if args.baseline is not None and args.baseline.is_file():
            baseline = read_json(args.baseline)
        source_lock = read_json(args.source_lock)
        provenance = read_json(args.provenance)
        payload = discover(config, baseline, source_lock, provenance)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        log(
            f"checked {len(payload['repositories'])} repositories; "
            f"changed={payload['changed_repository_count']}; candidate_only=true"
        )
        return 0
    except RadarError as exc:
        log(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
