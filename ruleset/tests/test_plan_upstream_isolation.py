from __future__ import annotations

import copy
import importlib.util
import pathlib
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "plan_upstream_isolation.py"
)
SPEC = importlib.util.spec_from_file_location("plan_upstream_isolation", SCRIPT)
assert SPEC and SPEC.loader
PLANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLANNER)


def source_config() -> dict:
    return {
        "categories": [
            {
                "id": "a",
                "sources": [
                    {
                        "source_id": "source-a",
                        "type": "remote_domain",
                        "url": "https://raw.githubusercontent.com/shared/repo/main/a",
                        "authority": "community",
                    }
                ],
            },
            {
                "id": "b",
                "sources": [
                    {
                        "source_id": "source-b",
                        "type": "remote_domain",
                        "url": "https://raw.githubusercontent.com/shared/repo/main/b",
                        "authority": "community",
                    }
                ],
            },
            {
                "id": "c",
                "sources": [
                    {
                        "source_id": "source-c",
                        "type": "remote_domain",
                        "url": "https://independent.example/c",
                        "authority": "official",
                    }
                ],
            },
            {"id": "aggregate", "aggregate_of": ["a", "c"]},
        ]
    }


def provenance() -> dict:
    return {
        "sources": [
            {
                "source_id": "source-a",
                "repository": "shared/repo",
                "resolved_ref": "https://github.com/shared/repo/blob/" + "a" * 40 + "/a",
            },
            {
                "source_id": "source-b",
                "repository": "shared/repo",
                "resolved_ref": "https://github.com/shared/repo/blob/" + "a" * 40 + "/b",
            },
            {
                "source_id": "source-c",
                "resolved_ref": "https://independent.example/c",
            },
        ]
    }


def build_review(
    config: dict,
    baseline_index: dict,
    candidate_index: dict,
    findings: list[dict],
    blockers: list[str],
    *,
    unscoped: list[str] | None = None,
) -> dict:
    changed = ["a", "aggregate", "b", "c"]
    unscoped_blockers = sorted(unscoped or [])
    blocker_set = set(blockers) - set(unscoped_blockers)
    bound_findings = []
    for raw_finding in findings:
        finding = copy.deepcopy(raw_finding)
        finding.pop("evidence_digest", None)
        message = str(finding.get("message", ""))
        finding["blocker_sha256"] = (
            PLANNER.hashlib.sha256(message.encode("utf-8")).hexdigest()
            if message in blocker_set
            else ""
        )
        finding["evidence_digest"] = PLANNER.digest_payload(finding)
        bound_findings.append(finding)
    ordered_findings = sorted(
        bound_findings,
        key=lambda item: (
            str(item["scope"]),
            str(item["category"]),
            str(item["rule"]),
            str(item["code"]),
            str(item["evidence_digest"]),
        ),
    )
    isolation = {
        "schema": PLANNER.ISOLATION_EVIDENCE_SCHEMA,
        "mode": "shadow-only",
        "source_provenance_sha256": PLANNER.digest_payload(provenance()),
        "complete_blocker_mapping": not unscoped_blockers,
        "blocker_count": len(blockers),
        "mapped_blocker_count": len(blockers) - len(unscoped_blockers),
        "derived_blocker_count": 0,
        "derived_blocker_sha256s": [],
        "unscoped_blockers": unscoped_blockers,
        "findings": ordered_findings,
        "findings_sha256": PLANNER.digest_payload(ordered_findings),
    }
    isolation["evidence_sha256"] = PLANNER.digest_payload(isolation)
    return {
        "schema": PLANNER.REPORT_SCHEMA,
        "source_config_sha256": PLANNER.digest_payload(config),
        "baseline_index_sha256": PLANNER.digest_payload(baseline_index),
        "current_index_sha256": PLANNER.digest_payload(candidate_index),
        "changed_categories": changed,
        "category_evidence": [
            {"category": category, "added_count": 1, "removed_count": 0}
            for category in changed
        ],
        "blockers": sorted(blockers),
        "isolation_evidence": isolation,
    }


class UpstreamIsolationPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = source_config()
        self.baseline_index = {"categories": [{"id": "baseline"}]}
        self.candidate_index = {"categories": [{"id": "candidate"}]}

    def test_shared_repository_and_aggregate_dependencies_are_atomic(self) -> None:
        message = "source a lacks independent authority"
        finding = PLANNER.isolation_finding(
            code="addition-independent-authority",
            scope="rule",
            isolatable=True,
            message=message,
            category="a",
            rule="DOMAIN-SUFFIX,example.com",
            source_ids=["source-a"],
            repository_bindings=["shared/repo"],
            dependency_closure=["category:a", "repository:shared/repo"],
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        plan = PLANNER.build_plan(
            review,
            self.config,
            self.baseline_index,
            self.candidate_index,
            provenance(),
        )
        self.assertEqual(plan["accepted_candidate_categories"], ["c"])
        self.assertEqual(
            plan["quarantined_categories"], ["a", "aggregate", "b"]
        )
        self.assertTrue(plan["safe_slice_changed"])
        self.assertEqual(plan["planned_safe_delta_count"], 1)
        self.assertEqual(plan["publishable_safe_delta_count"], 0)
        self.assertTrue(plan["composite_validation_required"])
        self.assertFalse(plan["global_hold"])
        self.assertFalse(plan["enforcement_ready"])

    def test_nonisolatable_finding_fails_closed_to_global_hold(self) -> None:
        message = "candidate evidence is structurally inconsistent"
        finding = PLANNER.isolation_finding(
            code="source-integrity-failure",
            scope="source-binding",
            isolatable=False,
            message=message,
            category="a",
            source_ids=["source-a"],
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        plan = PLANNER.build_plan(
            review,
            self.config,
            self.baseline_index,
            self.candidate_index,
            provenance(),
        )
        self.assertEqual(plan["accepted_candidate_categories"], [])
        self.assertEqual(
            plan["quarantined_categories"], ["a", "aggregate", "b", "c"]
        )
        self.assertTrue(plan["global_hold"])

    def test_unscoped_blocker_fails_closed_to_global_hold(self) -> None:
        blocker = "candidate manifest does not bind to the baseline"
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [blocker],
            unscoped=[blocker],
        )
        plan = PLANNER.build_plan(
            review,
            self.config,
            self.baseline_index,
            self.candidate_index,
            provenance(),
        )
        self.assertTrue(plan["global_hold"])
        self.assertEqual(plan["accepted_candidate_categories"], [])

    def test_evidence_digest_tamper_is_rejected(self) -> None:
        message = "source a lacks independent authority"
        finding = PLANNER.isolation_finding(
            code="addition-independent-authority",
            scope="rule",
            isolatable=True,
            message=message,
            category="a",
            rule="DOMAIN-SUFFIX,example.com",
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        review["isolation_evidence"]["findings"][0]["category"] = "b"
        with self.assertRaisesRegex(PLANNER.IsolationPlannerError, "digest"):
            PLANNER.build_plan(
                review,
                self.config,
                self.baseline_index,
                self.candidate_index,
                provenance(),
            )

    def test_candidate_provenance_tamper_is_rejected(self) -> None:
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        tampered_provenance = provenance()
        tampered_provenance["sources"] = tampered_provenance["sources"][:-1]
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError, "provenance binding"
        ):
            PLANNER.build_plan(
                review,
                self.config,
                self.baseline_index,
                self.candidate_index,
                tampered_provenance,
            )

    def test_rehashed_evidence_cannot_leave_a_blocker_uncovered(self) -> None:
        message = "source a lacks independent authority"
        finding = PLANNER.isolation_finding(
            code="addition-independent-authority",
            scope="rule",
            isolatable=True,
            message=message,
            category="a",
            rule="DOMAIN-SUFFIX,example.com",
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        isolation = review["isolation_evidence"]
        isolation["findings"] = []
        isolation["findings_sha256"] = PLANNER.digest_payload([])
        isolation["mapped_blocker_count"] = 0
        isolation.pop("evidence_sha256")
        isolation["evidence_sha256"] = PLANNER.digest_payload(isolation)
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError, "coverage is not exact"
        ):
            PLANNER.build_plan(
                review,
                self.config,
                self.baseline_index,
                self.candidate_index,
                provenance(),
            )

    def test_detached_artifact_is_bound_to_exact_automated_review(self) -> None:
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        isolation = review.pop("isolation_evidence")
        artifact = {
            "schema": PLANNER.ISOLATION_ARTIFACT_SCHEMA,
            "mode": "shadow-only",
            "automated_review_sha256": PLANNER.digest_payload(review),
            "baseline_index_sha256": review["baseline_index_sha256"],
            "candidate_index_sha256": review["current_index_sha256"],
            "source_config_sha256": review["source_config_sha256"],
            "isolation_evidence": isolation,
        }
        artifact["artifact_sha256"] = PLANNER.digest_payload(artifact)
        attached = PLANNER.attach_isolation_evidence(review, artifact)
        self.assertEqual(attached["isolation_evidence"], isolation)

        tampered = copy.deepcopy(review)
        tampered["changed_categories"] = ["a"]
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError, "review binding"
        ):
            PLANNER.attach_isolation_evidence(tampered, artifact)

    def test_plan_is_deterministic(self) -> None:
        message = "source a lacks independent authority"
        finding = PLANNER.isolation_finding(
            code="addition-independent-authority",
            scope="rule",
            isolatable=True,
            message=message,
            category="a",
            rule="DOMAIN-SUFFIX,example.com",
            repository_bindings=["shared/repo"],
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        first = PLANNER.build_plan(
            review,
            self.config,
            self.baseline_index,
            self.candidate_index,
            provenance(),
        )
        second = PLANNER.build_plan(
            copy.deepcopy(review),
            copy.deepcopy(self.config),
            copy.deepcopy(self.baseline_index),
            copy.deepcopy(self.candidate_index),
            copy.deepcopy(provenance()),
        )
        self.assertEqual(PLANNER.canonical_bytes(first), PLANNER.canonical_bytes(second))


if __name__ == "__main__":
    unittest.main()
