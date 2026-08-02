from __future__ import annotations

import copy
import hashlib
import importlib.util
import pathlib
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "build_candidate_identity.py"
)
SPEC = importlib.util.spec_from_file_location("build_candidate_identity", SCRIPT)
assert SPEC and SPEC.loader
IDENTITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITY)


def base_manifest() -> dict[str, object]:
    return {
        "semantic_digest": "a" * 64,
        "source_lock_sha256": "b" * 64,
        "changed": True,
        "risk_level": "low",
        "requires_review": False,
        "auto_promotion_eligible": True,
        "baseline_available": True,
        "source_lock_changed": True,
        "source_head_advanced_after_lock": False,
        "fallback_cache_count": 0,
        "cache_blocked_source_ids": [],
        "changed_categories": ["global", "ai"],
        "risk_markers": ["marker-b", "marker-a"],
        "budget_exceeded": [],
        "conflict_delta": {
            "high_severity": 0,
            "cross_action": 0,
            "informational_by_category": {"global": 1, "ai": 0},
        },
        "generated_at_utc": "2026-08-01T00:00:00Z",
    }


def base_radar() -> dict[str, object]:
    return {
        "candidate_only": True,
        "promotion_blocked": False,
        "auto_promotion_blocked": False,
        "advanced_active_repositories": [],
        "independent_changed_repositories": ["repo/b", "repo/a"],
        "unbuilt_head_files": [],
        "high_impact_quorum": 2,
        "quorum_review_required": False,
        "generated_at_utc": "2026-08-01T00:00:00Z",
    }


def base_automated_review() -> dict[str, object]:
    return {
        "schema": "project-g-automated-review-v2",
        "eligible": True,
        "required_stable_cycles": 2,
        "minimum_cycle_separation_seconds": 300,
        "review_policy": "unattended-evidence-gated-v2",
        "changed_categories": ["ai", "global"],
        "risk_level": "low",
        "risk_markers": ["marker-a", "marker-b"],
        "policy_modes": ["low-risk"],
        "category_evidence": [],
        "source_evidence": [],
        "blockers": [],
    }


class CandidateIdentityTests(unittest.TestCase):
    def fingerprint(
        self,
        manifest: dict[str, object],
        radar: dict[str, object],
        automated_review: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], bytes, str]:
        return IDENTITY.build_identity(
            manifest,
            radar,
            automated_review or base_automated_review(),
            "c" * 40,
            b"workflow\n",
        )

    def test_decision_is_deterministic_and_excludes_timestamps(self) -> None:
        first_manifest = base_manifest()
        first_radar = base_radar()
        second_manifest = copy.deepcopy(first_manifest)
        second_radar = copy.deepcopy(first_radar)
        first_review = base_automated_review()
        second_review = copy.deepcopy(first_review)
        second_manifest["changed_categories"] = ["ai", "global"]
        second_manifest["risk_markers"] = ["marker-a", "marker-b"]
        second_manifest["generated_at_utc"] = "2030-01-01T00:00:00Z"
        second_radar["independent_changed_repositories"] = ["repo/a", "repo/b"]
        second_radar["generated_at_utc"] = "2030-01-01T00:00:00Z"

        first_identity, first_decision, first_fingerprint = self.fingerprint(
            first_manifest, first_radar, first_review
        )
        second_identity, second_decision, second_fingerprint = self.fingerprint(
            second_manifest, second_radar, second_review
        )

        self.assertEqual(first_decision, second_decision)
        self.assertEqual(first_fingerprint, second_fingerprint)
        self.assertEqual(first_identity, second_identity)
        self.assertNotIn(b"generated_at", first_decision)
        self.assertEqual(
            hashlib.sha256(first_decision).hexdigest(),
            first_fingerprint,
        )

    def test_decision_changes_for_each_promotion_relevant_dimension(self) -> None:
        baseline = self.fingerprint(base_manifest(), base_radar())[2]
        mutations = {
            "semantic digest": ("manifest", "semantic_digest", "d" * 64),
            "source lock": ("manifest", "source_lock_sha256", "e" * 64),
            "changed categories": (
                "manifest",
                "changed_categories",
                ["ai", "global", "google"],
            ),
            "risk markers": (
                "manifest",
                "risk_markers",
                ["marker-a", "marker-b", "marker-c"],
            ),
            "budget": ("manifest", "budget_exceeded", ["ai:add"]),
            "conflicts": (
                "manifest",
                "conflict_delta",
                {"high_severity": 1, "cross_action": 0},
            ),
            "radar": (
                "radar",
                "independent_changed_repositories",
                ["repo/a", "repo/b", "repo/c"],
            ),
            "automated review": (
                "review",
                "review_policy",
                "unattended-evidence-gated-v3",
            ),
        }
        for label, (target, key, value) in mutations.items():
            with self.subTest(label=label):
                manifest = base_manifest()
                radar = base_radar()
                if target == "manifest":
                    manifest[key] = value
                elif target == "radar":
                    radar[key] = value
                review = base_automated_review()
                if target == "review":
                    review[key] = value
                self.assertNotEqual(
                    self.fingerprint(manifest, radar, review)[2], baseline
                )

    def test_decision_is_independent_of_source_and_workflow_identity(self) -> None:
        first_identity, _, first_fingerprint = IDENTITY.build_identity(
            base_manifest(),
            base_radar(),
            base_automated_review(),
            "c" * 40,
            b"workflow one\n",
        )
        second_identity, _, second_fingerprint = IDENTITY.build_identity(
            base_manifest(),
            base_radar(),
            base_automated_review(),
            "d" * 40,
            b"workflow two\n",
        )
        self.assertEqual(first_fingerprint, second_fingerprint)
        self.assertNotEqual(first_identity["source_sha"], second_identity["source_sha"])
        self.assertNotEqual(
            first_identity["workflow_sha256"],
            second_identity["workflow_sha256"],
        )

    def test_invalid_identity_inputs_fail_closed(self) -> None:
        manifest = base_manifest()
        manifest["requires_review"] = "false"
        with self.assertRaisesRegex(
            IDENTITY.CandidateIdentityError,
            "requires_review must be a boolean",
        ):
            self.fingerprint(manifest, base_radar())
        with self.assertRaisesRegex(
            IDENTITY.CandidateIdentityError,
            "source_sha must be",
        ):
            IDENTITY.build_identity(
                base_manifest(),
                base_radar(),
                base_automated_review(),
                "not-a-sha",
                b"workflow\n",
            )

        blocked_review = base_automated_review()
        blocked_review["eligible"] = False
        with self.assertRaisesRegex(
            IDENTITY.CandidateIdentityError,
            "eligibility must match its blocker set",
        ):
            self.fingerprint(base_manifest(), base_radar(), blocked_review)

        short_cycle = base_automated_review()
        short_cycle["minimum_cycle_separation_seconds"] = 299
        with self.assertRaisesRegex(
            IDENTITY.CandidateIdentityError,
            "cycle separation must be at least 300 seconds",
        ):
            self.fingerprint(base_manifest(), base_radar(), short_cycle)


if __name__ == "__main__":
    unittest.main()
