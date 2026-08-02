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
        self.assertIn("Authorize the verified main transition", workflow)
        self.assertGreaterEqual(workflow.count("context='ruleset/gate'"), 2)
        self.assertIn("verify_published.py", workflow)
        self.assertIn("git revert --no-edit", workflow)
        self.assertNotIn("steps.publish_main.outputs.main_published", workflow)
        self.assertIn('remote_sha" = "$PREVIOUS_SHA', workflow)
        self.assertIn(
            'git diff --quiet "$PREVIOUS_SHA" "$rollback_sha"',
            workflow,
        )

    def test_discovery_cannot_publish_repository_content(self) -> None:
        workflow = (WORKFLOW_ROOT / "source-discovery.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r"permissions:\n(?:  .+\n)*  contents: read")
        self.assertIn("actions: read", workflow)
        self.assertIn("statuses: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("git push", workflow)
        self.assertNotIn("gh release create", workflow)
        self.assertIn("ruleset-candidate-", workflow)
        self.assertIn(
            "Run candidate-only radar against the published baseline", workflow
        )
        self.assertIn(
            '--baseline "${RUNNER_TEMP}/baseline-dist/candidate_sources.json"',
            workflow,
        )
        self.assertNotIn("previous-radar", workflow)
        self.assertIn("candidate-sources.json", workflow)
        self.assertIn("build_candidate_identity.py", workflow)
        self.assertIn("candidate-decision.json", workflow)
        self.assertIn("decision-fingerprint.txt", workflow)
        self.assertIn("check_automated_review.py", workflow)
        self.assertIn("automated-review.json", workflow)
        self.assertIn("expected_source_sha:", workflow)
        self.assertIn("observation_id:", workflow)
        self.assertIn("observation_attempt:", workflow)
        self.assertIn("observation-id.txt", workflow)
        self.assertIn("run-name: >-", workflow)
        self.assertIn("push:\n    branches:\n      - main", workflow)
        self.assertIn("EXPECTED_SOURCE_SHA: ${{ inputs.expected_source_sha }}", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_SHA"', workflow)
        self.assertGreaterEqual(workflow.count("queue: max"), 2)
        self.assertRegex(
            workflow,
            r"jobs:\n  candidate:\n(?:.*\n){0,8}?    concurrency:\n"
            r"      group: ruleset-publication-main\n"
            r"      cancel-in-progress: false",
        )

    def test_upstream_isolation_is_attested_shadow_only_evidence(self) -> None:
        discovery = (WORKFLOW_ROOT / "source-discovery.yml").read_text(
            encoding="utf-8"
        )
        promotion = (WORKFLOW_ROOT / "ruleset-update.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("plan_upstream_isolation.py", discovery)
        self.assertIn("build_category_lkg_binding.py", discovery)
        self.assertIn(
            "Bind immutable published category LKG for shadow planning",
            discovery,
        )
        lkg_step = discovery.split(
            "Bind immutable published category LKG for shadow planning", maxsplit=1
        )[1].split("Build isolated candidate", maxsplit=1)[0]
        self.assertIn("continue-on-error: true", lkg_step)
        self.assertIn("timeout-minutes: 15", lkg_step)
        self.assertIn("--require-published-status", discovery)
        self.assertIn("--published-lkg-binding", discovery)
        self.assertIn("category-lkg-binding.json", discovery)
        self.assertIn("stable_selection_fingerprint", discovery)
        self.assertIn("steps.category_lkg.outcome == 'success'", discovery)
        self.assertIn("gh attestation verify", discovery)
        self.assertIn("--isolation-output", discovery)
        self.assertIn("--isolation-evidence", discovery)
        self.assertIn("ruleset-isolation-shadow-", discovery)
        self.assertIn("upstream-isolation-shadow.tar", discovery)
        self.assertIn("Attest upstream isolation shadow evidence", discovery)
        self.assertIn("Scan upstream isolation shadow evidence for secrets", discovery)
        self.assertIn("Record non-authoritative shadow outcome", discovery)
        self.assertIn("continue-on-error: true", discovery)
        self.assertIn("candidate decision and packaging continue unchanged", discovery)
        self.assertIn("cmp \\", discovery)
        self.assertIn('${RUNNER_TEMP}/upstream-isolation-shadow', discovery)
        self.assertNotIn(".candidate/upstream-isolation", discovery)
        self.assertNotIn(".candidate/isolation-evidence", discovery)
        self.assertNotIn("contents: write", discovery)
        upload_block = discovery.split(
            "Upload attested upstream isolation shadow archive", maxsplit=1
        )[1].split("Record non-authoritative shadow outcome", maxsplit=1)[0]
        self.assertIn("upstream-isolation-shadow.tar", upload_block)
        self.assertIn("upstream-isolation-shadow.sha256", upload_block)
        self.assertNotIn("/payload", upload_block)
        self.assertLess(
            discovery.index("Build non-authoritative upstream isolation shadow plan"),
            discovery.index("Package immutable candidate"),
        )
        self.assertNotIn("plan_upstream_isolation.py", promotion)
        self.assertNotIn("ruleset-isolation-shadow-", promotion)

    def test_promotion_consumes_exact_candidate_and_attests_it(self) -> None:
        workflow = (WORKFLOW_ROOT / "ruleset-update.yml").read_text(encoding="utf-8")
        self.assertIn("run-id:", workflow)
        self.assertIn("digest-mismatch: error", workflow)
        self.assertIn("require-promotable", workflow)
        self.assertIn("attestations: read", workflow)
        self.assertGreaterEqual(workflow.count("--signer-workflow"), 2)
        self.assertGreaterEqual(workflow.count("--source-digest"), 2)
        self.assertIn(
            "Candidate expired before automatic publication completed",
            workflow,
        )
        self.assertNotIn("status=success&per_page=100", workflow)
        self.assertNotIn("superseded this candidate", workflow)
        self.assertIn(".workflow_runs[1]", workflow)
        self.assertIn(
            "The adjacent prior discovery was not a successful same-source run; stability reset",
            workflow,
        )
        self.assertIn(
            "Candidate decision and full identity were not stable across adjacent cycles",
            workflow,
        )
        self.assertIn("less than 300 seconds apart", workflow)
        self.assertIn("Exact candidate identity was not identical", workflow)
        self.assertGreaterEqual(workflow.count("gh attestation verify"), 4)
        self.assertIn(
            "the exact reserved candidate remains selected",
            workflow,
        )
        self.assertIn(
            "A newer completed discovery failed, was cancelled, or changed source identity",
            workflow,
        )
        self.assertIn("Publication reservation closed", workflow)
        self.assertIn('echo "continue=false" >> "$GITHUB_OUTPUT"', workflow)
        self.assertIn(
            "Ignoring ${active_newer_count} newer active discovery run(s)", workflow
        )
        self.assertGreaterEqual(
            workflow.count("steps.reservation.outputs.continue == 'true'"),
            15,
        )
        self.assertIn("newer-discovery-evidence", workflow)
        self.assertIn("Newer discovery ${newer_run_id} has unhealthy source evidence", workflow)
        self.assertIn("Newer discovery ${newer_run_id} has an active-source race", workflow)
        self.assertIn(".budget_exceeded | length", workflow)
        self.assertIn("candidate_decision_fingerprint", workflow)
        self.assertIn("candidate-decision.json", workflow)
        self.assertIn("decision-fingerprint.txt", workflow)
        self.assertIn("automated-review.json", workflow)
        self.assertIn("check_automated_review.py", workflow)
        self.assertGreaterEqual(workflow.count("--require-eligible"), 2)
        self.assertIn("build_candidate_identity.py", workflow)
        self.assertIn("project-g-candidate-decision-v1", workflow)
        self.assertIn("Build exact publication receipt", workflow)
        self.assertIn("Upload immutable publication receipt", workflow)
        self.assertIn("project-g-publication-receipt-v1", workflow)
        self.assertIn("ruleset-publication-receipt-${PUBLISHED_SHA}", workflow)
        self.assertIn("include-hidden-files: true", workflow)
        self.assertNotIn("  rediscover:", workflow)
        self.assertGreaterEqual(workflow.count("queue: max"), 2)
        self.assertEqual(workflow.count("actions: write"), 0)
        publish_permissions = workflow.split("  publish:", maxsplit=1)[1]
        self.assertIn("actions: read", publish_permissions)
        discovery = (WORKFLOW_ROOT / "source-discovery.yml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            discovery,
            r"actions/attest-build-provenance@[0-9a-f]{40}",
        )
        self.assertRegex(
            discovery,
            r"ruleset-candidate-\$\{risk_level\}-\$\{semantic_digest\}-"
            r"\$\{decision_fingerprint\}-\$\{identity_digest\}",
        )
        self.assertIn("ruleset-production", workflow)
        self.assertIn("ruleset-low-risk", workflow)
        self.assertIn('promotion_mode="auto-high-risk"', workflow)
        self.assertNotIn('promotion_mode="reviewed"', workflow)
        self.assertIn("group: ruleset-publication-main", workflow)
        self.assertIn("unattended-evidence-gated-v2", workflow)
        self.assertIn("minimum_cycle_separation_seconds", workflow)

    def test_post_publication_observation_separates_snapshot_from_live_sources(
        self,
    ) -> None:
        workflow = (
            WORKFLOW_ROOT / "post-publication-observation.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("- Ruleset Promotion", workflow)
        self.assertIn("project-g-publication-receipt-v1", workflow)
        self.assertIn("Promotion run has an unexpected event", workflow)
        self.assertIn("produced no publication receipt", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("attestations: read", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("statuses: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("statuses: write", workflow)
        self.assertIn("queue: max", workflow)
        self.assertIn("Checkout current main verifier", workflow)
        self.assertLess(
            workflow.index("Checkout current main verifier"),
            workflow.index("Download exact publication receipt"),
        )
        self.assertIn("Verify frozen snapshot convergence", workflow)
        self.assertIn("--require-published-status", workflow)
        self.assertIn("gh workflow run source-discovery.yml", workflow)
        self.assertIn('-f expected_source_sha="$OBSERVATION_SHA"', workflow)
        self.assertIn('-f observation_id="$observation_id"', workflow)
        self.assertIn('-f observation_attempt="$observation_attempt"', workflow)
        self.assertIn(".display_title == $title", workflow)
        self.assertNotIn("/cancel", workflow)
        self.assertIn("failed after one automatic retry", workflow)
        self.assertIn("did not complete within 330 minutes", workflow)
        self.assertIn("timeout-minutes: 360", workflow)
        self.assertIn("+ 19800", workflow)
        self.assertIn("check_automated_review.py", workflow)
        self.assertIn("build_candidate_identity.py", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn("ruleset-candidate-(none|low|high)-", workflow)
        self.assertIn('blockers == ["candidate has no semantic changes"]', workflow)
        self.assertIn('observation_state="live-clean"', workflow)
        self.assertIn(
            'observation_state="next-candidate-${artifact_risk}-eligible"',
            workflow,
        )
        self.assertIn(
            'observation_state="candidate-${artifact_risk}-held-by-policy"',
            workflow,
        )
        self.assertIn("User action for this observation: \\`none\\`", workflow)
        self.assertIn("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", workflow)

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
        self.assertNotIn("paths:", ruleset_tests)

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

    def test_watchdog_replays_candidate_and_release_evidence(self) -> None:
        workflow = (WORKFLOW_ROOT / "freshness-watchdog.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("actions: read", workflow)
        self.assertIn("attestations: read", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("statuses: read", workflow)
        self.assertIn("workflow_run:", workflow)
        self.assertIn("- Source Discovery", workflow)
        self.assertIn("- Ruleset Promotion", workflow)
        self.assertIn("- Post-Publication Observation", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("statuses: write", workflow)
        self.assertIn("actions/download-artifact@", workflow)
        self.assertIn("source-health.json", workflow)
        self.assertIn("source-radar-decision.json", workflow)
        self.assertIn("candidate-decision.json", workflow)
        self.assertIn("decision-fingerprint.txt", workflow)
        self.assertIn("automated-review.json", workflow)
        self.assertIn("check_automated_review.py", workflow)
        self.assertIn("build_candidate_identity.py", workflow)
        self.assertIn("candidate decision identity could not be reproduced", workflow)
        self.assertIn("candidate identity does not match artifact name", workflow)
        self.assertIn("verify_published.py", workflow)
        self.assertIn("--signer-workflow", workflow)
        self.assertIn("--source-digest", workflow)
        self.assertIn("runs?branch=main&per_page=100", workflow)
        self.assertNotIn("status=success&per_page=", workflow)
        self.assertIn(
            'run.get("conclusion") != "success"',
            workflow,
        )
        self.assertIn(": > .watchdog/advisories.txt", workflow)
        self.assertIn(
            'echo "latest eligible candidate awaits a second identical discovery cycle at least 300 seconds later"',
            workflow,
        )
        self.assertNotIn(
            'echo "latest eligible candidate awaits a second identical discovery cycle at least 300 seconds later" >> "$failures"',
            workflow,
        )
        self.assertIn("latest completed Source Discovery did not succeed", workflow)
        self.assertIn("Source Discovery is still running automatically", workflow)
        self.assertIn("watchdog verifier was superseded", workflow)
        self.assertIn("Superseded verifier", workflow)
        self.assertIn("convergence_pending", workflow)
        self.assertIn("stable eligible candidate was not published", workflow)
        self.assertIn("--main-sha", workflow)
        self.assertIn("--require-published-status", workflow)
        self.assertIn("no canonical immutable release", workflow)
        self.assertIn("::warning title=Automated publication pending::", workflow)
        self.assertNotIn("Protected review pending", workflow)
        self.assertIn('echo "state=pass" >> "$GITHUB_OUTPUT"', workflow)
        self.assertIn('echo "state=attention" >> "$GITHUB_OUTPUT"', workflow)
        self.assertIn('echo "state=fail" >> "$GITHUB_OUTPUT"', workflow)
        self.assertIn(
            'echo "source radar detected an active-source race" >> "$failures"',
            workflow,
        )
        for hard_failure in (
            "candidate archive checksum failed",
            "candidate manifest freshness or budget gate failed",
            "latest source health is degraded",
            "latest discovery used fallback cache",
            "canonical release does not converge with current main dist",
            "release discovery attestation verification failed",
        ):
            self.assertIn(hard_failure, workflow)
        advisory_block = workflow.split(
            "if [ -s .watchdog/advisories.txt ]; then",
            maxsplit=1,
        )[1].split(
            "if [ -s .watchdog/failures.txt ]; then",
            maxsplit=1,
        )[0]
        self.assertNotIn("exit 1", advisory_block)

    def test_main_gate_is_default_branch_owned_and_fail_closed(self) -> None:
        workflow = (WORKFLOW_ROOT / "main-gate.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_run:", workflow)
        self.assertIn("statuses: write", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("actions/checkout@", workflow)
        self.assertIn("ruleset/gate", workflow)
        self.assertIn("github.event.workflow_run.event == 'push'", workflow)
        self.assertIn('trigger_event == "push"', workflow)
        self.assertIn("push gate refuses a superseded main commit", workflow)
        self.assertIn("group: main-gate-${{ github.event.workflow_run.head_sha }}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("queue: max", workflow)
        self.assertIn("for attempt in range(1, max_attempts + 1)", workflow)
        self.assertIn('GATE_MAX_ATTEMPTS", "30"', workflow)
        self.assertIn('state = "pending"', workflow)
        self.assertIn('if state == "failure"', workflow)
        self.assertIn('if state == "pending"', workflow)
        self.assertIn('("repository-governance", 15368)', workflow)
        self.assertIn('("CodeQL", 57789)', workflow)
        self.assertIn('("CodeQL", "/language:python")', workflow)
        self.assertIn(
            '("Gitleaks", ".github/workflows/secret-scan.yml:gitleaks")',
            workflow,
        )
        self.assertIn("code-scanning/analyses?", workflow)
        self.assertIn("security-events: read", workflow)
        self.assertIn("contents/README.md?ref={head_sha}", workflow)
        for context in (
            "repository-governance",
            "full-validation",
            "Analyze Python",
            "dependency-review",
            "CodeQL",
            "gitleaks",
        ):
            self.assertIn(context, workflow)
        self.assertIn("exactly one open pull request into main", workflow)
        self.assertIn("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", workflow)


if __name__ == "__main__":
    unittest.main()
