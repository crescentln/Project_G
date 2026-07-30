import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "discover_source_radar.py"
SPEC = importlib.util.spec_from_file_location("discover_source_radar", SCRIPT)
assert SPEC and SPEC.loader
RADAR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RADAR)


class SourceRadarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = {
            "candidate_only": True,
            "repositories": [
                {
                    "repository": "v2fly/domain-list-community",
                    "role": "active-locked-source",
                    "candidate_only": False,
                }
            ],
        }
        self.source_lock = {
            "repositories": {
                "v2fly/domain-list-community": {
                    "resolved_revision": "1" * 40,
                    "tree_revision": "2" * 40,
                }
            }
        }
        self.provenance = {
            "sources": [
                {
                    "type": "v2fly_dlc",
                    "files": [{"path": "data/example"}],
                }
            ]
        }

    @staticmethod
    def api_response(path: str):
        if path == "repos/v2fly/domain-list-community":
            return {"default_branch": "master"}, {}
        if path == "repos/v2fly/domain-list-community/commits/master":
            return {
                "sha": "3" * 40,
                "commit": {
                    "committer": {"date": "2026-01-01T00:00:00Z"},
                    "tree": {"sha": "7" * 40},
                },
            }, {"etag": "etag", "last_modified": "last-modified"}
        if path.startswith("repos/v2fly/domain-list-community/git/trees/"):
            return {
                "truncated": False,
                "tree": [
                    {"type": "blob", "path": "data/example", "sha": "4" * 40},
                    {"type": "blob", "path": "data/isolated", "sha": "5" * 40},
                ],
            }, {}
        raise AssertionError(path)

    @mock.patch.object(RADAR, "github_api")
    def test_uses_source_lock_as_first_run_comparison(self, github_api) -> None:
        github_api.side_effect = self.api_response
        result = RADAR.discover(
            self.config, {}, self.source_lock, self.provenance
        )
        row = result["repositories"][0]
        self.assertEqual(row["comparison_basis"], "source-lock")
        self.assertEqual(row["previous_revision"], "1" * 40)
        self.assertTrue(row["changed"])
        self.assertEqual(result["changed_repositories"], ["v2fly/domain-list-community"])
        self.assertEqual(result["v2fly_tree"]["isolated_files"], ["data/isolated"])
        self.assertTrue(
            result["v2fly_tree"]["head_vs_lock"]["head_advanced_after_lock"]
        )

    @mock.patch.object(RADAR, "github_api")
    def test_baseline_takes_precedence_over_source_lock(self, github_api) -> None:
        github_api.side_effect = self.api_response
        baseline = {
            "repositories": [
                {
                    "repository": "v2fly/domain-list-community",
                    "resolved_revision": "3" * 40,
                }
            ],
            "v2fly_tree": {
                "files": [
                    {"path": "data/example", "blob_sha": "0" * 40},
                    {"path": "data/removed", "blob_sha": "6" * 40},
                ]
            },
        }
        result = RADAR.discover(
            self.config, baseline, self.source_lock, self.provenance
        )
        row = result["repositories"][0]
        self.assertEqual(row["comparison_basis"], "baseline")
        self.assertFalse(row["changed"])
        tree = result["v2fly_tree"]
        self.assertEqual(tree["new_files_since_baseline"], ["data/isolated"])
        self.assertEqual(tree["removed_files_since_baseline"], ["data/removed"])
        self.assertEqual(tree["changed_files_since_baseline"], ["data/example"])


if __name__ == "__main__":
    unittest.main()
