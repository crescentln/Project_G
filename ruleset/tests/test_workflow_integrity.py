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

    def test_update_workflow_has_staged_non_rebasing_publish_and_forward_rollback(self) -> None:
        workflow = (WORKFLOW_ROOT / "ruleset-update.yml").read_text(encoding="utf-8")
        self.assertIn("Publish verified snapshot to main", workflow)
        self.assertIn("Source moved before push", workflow)
        self.assertNotIn("pull --rebase", workflow)
        self.assertNotIn("push --force", workflow)
        self.assertNotIn("gh release edit", workflow)
        self.assertIn("ruleset/published", workflow)
        self.assertIn("verify_published.py", workflow)
        self.assertIn("git revert --no-edit", workflow)

    def test_discovery_cannot_publish_repository_content(self) -> None:
        workflow = (WORKFLOW_ROOT / "source-discovery.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r"permissions:\n  contents: read")
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("git push", workflow)
        self.assertNotIn("gh release create", workflow)
        self.assertIn("ruleset-candidate-", workflow)

    def test_promotion_consumes_exact_candidate_and_attests_it(self) -> None:
        workflow = (WORKFLOW_ROOT / "ruleset-update.yml").read_text(encoding="utf-8")
        self.assertIn("run-id:", workflow)
        self.assertIn("digest-mismatch: error", workflow)
        self.assertIn("require-promotable", workflow)
        self.assertIn(
            "Candidate expired while awaiting protected-environment approval",
            workflow,
        )
        self.assertIn(
            "A newer successful discovery superseded this candidate",
            workflow,
        )
        discovery = (WORKFLOW_ROOT / "source-discovery.yml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            discovery,
            r"actions/attest-build-provenance@[0-9a-f]{40}",
        )
        self.assertIn("ruleset-production", workflow)
        self.assertIn("ruleset-low-risk", workflow)

    def test_all_linux_jobs_use_fixed_runner(self) -> None:
        for workflow in sorted(WORKFLOW_ROOT.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            self.assertNotIn("runs-on: ubuntu-latest", text, workflow.name)

    def test_public_readme_zero_byte_gate_is_in_write_workflow(self) -> None:
        workflow = (WORKFLOW_ROOT / "ruleset-update.yml").read_text(encoding="utf-8")
        self.assertIn("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", workflow)
        self.assertGreaterEqual(workflow.count("contents/README.md?ref=main"), 6)

    def test_repository_governance_runs_without_path_filter(self) -> None:
        workflow = (WORKFLOW_ROOT / "repository-governance.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("paths:", workflow)
        self.assertIn("ruleset/dist", workflow)
        self.assertIn("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", workflow)
        ruleset_tests = (WORKFLOW_ROOT / "ruleset-tests.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('- "README.md"', ruleset_tests)
        self.assertIn('- "ruleset/dist/**"', ruleset_tests)

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
