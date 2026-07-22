from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "generate_release_notes.py"


class ReleaseNotesTests(unittest.TestCase):
    def test_artifact_urls_are_pinned_to_release_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "index.json").write_text(
                json.dumps({"category_count": 1}), encoding="utf-8"
            )
            (root / "conflicts.json").write_text(
                json.dumps({"conflict_count": 0}), encoding="utf-8"
            )
            (root / "fetch.json").write_text(
                json.dumps({"network_success_count": 1}), encoding="utf-8"
            )
            (root / "CHANGELOG.md").write_text("## now\n", encoding="utf-8")
            output = root / "notes.md"

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT_PATH),
                    "--repo",
                    "owner/repo",
                    "--tag",
                    "ruleset-20260722T000000Z",
                    "--changelog",
                    str(root / "CHANGELOG.md"),
                    "--index",
                    str(root / "index.json"),
                    "--conflicts",
                    str(root / "conflicts.json"),
                    "--fetch-report",
                    str(root / "fetch.json"),
                    "--output",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            notes = output.read_text(encoding="utf-8")
            self.assertIn("/ruleset-20260722T000000Z/ruleset/dist/index.json", notes)
            self.assertNotIn("/main/ruleset/dist", notes)


if __name__ == "__main__":
    unittest.main()
