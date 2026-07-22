from __future__ import annotations

import pathlib
import re
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"


class WorkflowIntegrityTests(unittest.TestCase):
    def test_all_actions_are_pinned_to_full_commit_sha(self) -> None:
        action_pattern = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
        pinned_pattern = re.compile(r"^[^@]+@[0-9a-f]{40}$")
        unpinned: list[str] = []
        for workflow in sorted(WORKFLOW_ROOT.glob("*.yml")):
            for action in action_pattern.findall(workflow.read_text(encoding="utf-8")):
                if not pinned_pattern.fullmatch(action):
                    unpinned.append(f"{workflow.name}: {action}")
        self.assertEqual(unpinned, [])

    def test_update_workflow_has_atomic_non_rebasing_publish(self) -> None:
        workflow = (WORKFLOW_ROOT / "ruleset-update.yml").read_text(encoding="utf-8")
        self.assertIn("git push --atomic", workflow)
        self.assertIn("Source moved before push", workflow)
        self.assertIn("include-hidden-files: true", workflow)
        self.assertNotIn("pull --rebase", workflow)
        self.assertNotIn("gh release edit", workflow)

    def test_gitleaks_scans_generated_dist(self) -> None:
        config = (REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        self.assertNotIn("ruleset/dist", config)
        workflows = "\n".join(
            path.read_text(encoding="utf-8") for path in WORKFLOW_ROOT.glob("*.yml")
        )
        self.assertRegex(
            workflows,
            r"ghcr\.io/gitleaks/gitleaks@sha256:[0-9a-f]{64}",
        )


if __name__ == "__main__":
    unittest.main()
