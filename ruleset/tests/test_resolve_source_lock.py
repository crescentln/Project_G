from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest
from unittest import mock


SCRIPT_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "resolve_source_lock.py"
)
SPEC = importlib.util.spec_from_file_location("resolve_source_lock", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
resolve_source_lock = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = resolve_source_lock
SPEC.loader.exec_module(resolve_source_lock)


class SourceLockTests(unittest.TestCase):
    def test_v2fly_ref_resolves_to_exact_commit_archive(self) -> None:
        sources_path = pathlib.Path(__file__).resolve().parents[1] / "config" / "sources.json"
        commit_sha = "1" * 40
        tree_sha = "2" * 40
        commit = {
            "sha": commit_sha,
            "commit": {
                "tree": {"sha": tree_sha},
                "committer": {"date": "2026-07-30T12:00:00Z"},
            },
        }
        with mock.patch.object(
            resolve_source_lock,
            "fetch_commit",
            return_value=(commit, {"etag": '"etag"', "last_modified": "today"}),
        ):
            payload = resolve_source_lock.build_lock(sources_path)

        entry = payload["repositories"]["v2fly/domain-list-community"]
        self.assertEqual(entry["resolved_revision"], commit_sha)
        self.assertEqual(entry["tree_revision"], tree_sha)
        self.assertGreater(entry["binding_count"], 0)
        for url in entry["archive_urls"]:
            self.assertIn(commit_sha, url)
            self.assertNotIn("master", url)


if __name__ == "__main__":
    unittest.main()
