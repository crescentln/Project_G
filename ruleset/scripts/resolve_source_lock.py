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
import urllib.request
from typing import Any


USER_AGENT = "project-g-source-lock/1.0"
V2FLY_REPOSITORY = "v2fly/domain-list-community"
V2FLY_REQUESTED_REF = "master"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class LockError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[source-lock] {message}")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LockError(f"missing file: {path}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise LockError(f"JSON root must be an object: {path}")
    return payload


def validate_configured_v2fly_sources(payload: dict[str, Any]) -> int:
    count = 0
    categories = payload.get("categories", [])
    if not isinstance(categories, list):
        raise LockError("sources config: categories must be an array")
    for category in categories:
        if not isinstance(category, dict):
            continue
        for source in category.get("sources", []):
            if not isinstance(source, dict) or source.get("type") != "v2fly_dlc":
                continue
            count += 1
            urls: list[str] = []
            for field_name in ("url",):
                value = str(source.get(field_name, "")).strip()
                if value:
                    urls.append(value)
            for field_name in ("urls", "fallback_urls"):
                raw = source.get(field_name, [])
                if raw is None:
                    continue
                if not isinstance(raw, list):
                    raise LockError(f"v2fly source field {field_name} must be an array")
                urls.extend(str(item).strip() for item in raw if str(item).strip())
            if not urls:
                raise LockError("v2fly source has no URL")
            for url in urls:
                if "v2fly/domain-list-community" not in url:
                    raise LockError(f"unexpected v2fly repository URL: {url}")
                if "/master/" not in url and "@master/" not in url:
                    raise LockError(
                        "configured v2fly roots must request the single lockable "
                        f"ref '{V2FLY_REQUESTED_REF}': {url}"
                    )
    if count == 0:
        raise LockError("sources config contains no v2fly_dlc bindings")
    return count


def fetch_commit(repository: str, ref: str) -> tuple[dict[str, Any], dict[str, str]]:
    url = f"https://api.github.com/repos/{repository}/commits/{ref}"
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
            if response.geturl().split("?", 1)[0] != url:
                raise LockError("GitHub commit API redirected unexpectedly")
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise LockError("GitHub commit response exceeded 2 MiB")
            validators = {
                "etag": str(response.headers.get("ETag", "")).strip(),
                "last_modified": str(response.headers.get("Last-Modified", "")).strip(),
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LockError(f"failed to resolve {repository}@{ref}: {exc}") from exc
    try:
        payload = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockError(f"GitHub commit response was invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise LockError("GitHub commit response root must be an object")
    return payload, validators


def build_lock(sources_path: pathlib.Path) -> dict[str, Any]:
    sources = read_json(sources_path)
    binding_count = validate_configured_v2fly_sources(sources)
    commit, validators = fetch_commit(V2FLY_REPOSITORY, V2FLY_REQUESTED_REF)
    revision = str(commit.get("sha", "")).strip().lower()
    if not SHA_RE.fullmatch(revision):
        raise LockError("GitHub returned an invalid commit SHA")
    tree_revision = str(
        commit.get("commit", {}).get("tree", {}).get("sha", "")
    ).strip().lower()
    if not SHA_RE.fullmatch(tree_revision):
        raise LockError("GitHub returned an invalid tree SHA")
    committed_at = str(
        commit.get("commit", {}).get("committer", {}).get("date", "")
    ).strip()
    if not committed_at:
        raise LockError("GitHub commit response is missing committer date")

    return {
        "version": 1,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repositories": {
            V2FLY_REPOSITORY: {
                "requested_ref": V2FLY_REQUESTED_REF,
                "resolved_revision": revision,
                "tree_revision": tree_revision,
                "committed_at_utc": committed_at,
                "binding_count": binding_count,
                "api_url": f"https://api.github.com/repos/{V2FLY_REPOSITORY}/commits/{revision}",
                "archive_urls": [
                    f"https://api.github.com/repos/{V2FLY_REPOSITORY}/tarball/{revision}",
                    f"https://codeload.github.com/{V2FLY_REPOSITORY}/tar.gz/{revision}"
                ],
                "etag": validators["etag"],
                "last_modified": validators["last_modified"]
            }
        }
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve mutable upstream refs into an immutable Project_G source lock."
    )
    parser.add_argument(
        "--sources",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/config/sources.json"),
    )
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        lock = build_lock(args.sources)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(lock, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        entry = lock["repositories"][V2FLY_REPOSITORY]
        log(
            f"resolved {V2FLY_REPOSITORY}@{V2FLY_REQUESTED_REF} "
            f"to {entry['resolved_revision']} for {entry['binding_count']} bindings"
        )
        return 0
    except LockError as exc:
        log(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
