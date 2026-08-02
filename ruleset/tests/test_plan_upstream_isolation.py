from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import tempfile
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


def provenance(revision: str = "b" * 40) -> dict:
    payload = {
        "sources": [
            {
                "source_id": "source-a",
                "repository": "shared/repo",
                "requested_ref": "main",
                "resolved_revision": revision,
                "resolved_ref": "https://github.com/shared/repo/blob/" + revision + "/a",
                "content_sha256": PLANNER.digest_payload(
                    {"source": "a", "revision": revision}
                ),
            },
            {
                "source_id": "source-b",
                "repository": "shared/repo",
                "requested_ref": "main",
                "resolved_revision": revision,
                "resolved_ref": "https://github.com/shared/repo/blob/" + revision + "/b",
                "content_sha256": PLANNER.digest_payload(
                    {"source": "b", "revision": revision}
                ),
            },
            {
                "source_id": "source-c",
                "resolved_ref": "https://independent.example/c",
                "content_sha256": PLANNER.digest_payload(
                    {"source": "c", "revision": revision}
                ),
            },
        ],
    }
    payload["source_count"] = len(payload["sources"])
    payload["source_lock_sha256"] = PLANNER.source_lock_identity(
        source_lock(revision), "test"
    )[0]
    return payload


def source_lock(revision: str) -> dict:
    return {
        "version": 1,
        "repositories": {
            "shared/repo": {
                "requested_ref": "main",
                "resolved_revision": revision,
                "tree_revision": revision,
                "binding_count": 2,
            }
        },
    }


def category_paths(category: str) -> dict[str, str]:
    return {
        field: template.format(category=category)
        for field, template in PLANNER.CATEGORY_OUTPUT_PATH_TEMPLATES.items()
    }


def write_dist(root: pathlib.Path, *, candidate: bool) -> dict:
    categories = ["a", "aggregate", "b", "c"]
    rows = []
    for priority, category in enumerate(categories, start=1):
        rules = [f"DOMAIN,{category}.baseline.example"]
        if candidate:
            rules.append(f"DOMAIN,{category}.candidate.example")
        output_paths = category_paths(category)
        rows.append(
            {
                "id": category,
                "rule_count": len(rules),
                "recommended_action": "PROXY",
                "recommended_priority": priority,
                "contract": {"category": category, "action": "PROXY"},
                **output_paths,
            }
        )
        (root / "stash").mkdir(parents=True, exist_ok=True)
        (root / "meta").mkdir(parents=True, exist_ok=True)
        (root / "stash" / f"{category}.list").write_text(
            "\n".join(sorted(rules)) + "\n", encoding="utf-8"
        )
        (root / "meta" / f"{category}.json").write_text(
            json.dumps({"id": category}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for field, raw_path in output_paths.items():
            if field == "stash_path":
                continue
            path = root / raw_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{field}:{category}\n", encoding="utf-8")
    index = {"category_count": len(rows), "categories": rows}
    (root / "index.json").write_text(
        json.dumps(index, sort_keys=True) + "\n", encoding="utf-8"
    )
    lock = source_lock("b" * 40 if candidate else "a" * 40)
    (root / "sources.lock.json").write_text(
        json.dumps(lock, sort_keys=True) + "\n", encoding="utf-8"
    )
    dist_provenance = provenance("b" * 40 if candidate else "a" * 40)
    (root / "source_provenance.json").write_text(
        json.dumps(dist_provenance, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "candidate_manifest.json").write_text(
        json.dumps(
            {
                "source_commit_sha": "e" * 40,
                "semantic_digest": "3" * 64,
                "source_lock_sha256": dist_provenance["source_lock_sha256"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return index


def build_review(
    config: dict,
    baseline_index: dict,
    candidate_index: dict,
    findings: list[dict],
    blockers: list[str],
    *,
    unscoped: list[str] | None = None,
    changed: list[str] | None = None,
    evidence_overrides: dict[str, dict] | None = None,
) -> dict:
    changed_categories = sorted(changed or ["a", "aggregate", "b", "c"])
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
        "baseline_source_lock_sha256": PLANNER.source_lock_identity(
            source_lock("a" * 40), "baseline"
        )[0],
        "current_source_lock_sha256": PLANNER.source_lock_identity(
            source_lock("b" * 40), "candidate"
        )[0],
        "changed_categories": changed_categories,
        "category_evidence": [
            {
                "category": category,
                "added_count": 1,
                "removed_count": 0,
                **(evidence_overrides or {}).get(category, {}),
            }
            for category in changed_categories
        ],
        "blockers": sorted(blockers),
        "isolation_evidence": isolation,
    }


class UpstreamIsolationPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = source_config()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repository_root = pathlib.Path(self.temp_dir.name)
        self.baseline_dist = self.repository_root / "baseline-dist"
        self.candidate_dist = self.repository_root / "candidate-dist"
        self.baseline_dist.mkdir()
        self.candidate_dist.mkdir()
        self.baseline_index = write_dist(self.baseline_dist, candidate=False)
        self.candidate_index = write_dist(self.candidate_dist, candidate=True)
        lkg_categories = PLANNER.category_output_identities(
            self.baseline_dist, self.baseline_index
        )
        baseline_lock_sha256, baseline_repositories = PLANNER.source_lock_identity(
            source_lock("a" * 40), "baseline"
        )
        anchor = {
            "repository": "owner/project",
            "release_id": 1,
            "release_tag": "ruleset-20260730T164904Z-c3c4a5cf3a8f",
            "release_commit_sha": "c3c4a5cf3a8f" + "1" * 28,
            "release_dist_tree_oid": "d" * 40,
            "archive_asset": {
                "name": "ruleset-dist.tar.gz",
                "sha256": "1" * 64,
            },
            "checksum_asset": {
                "name": "ruleset-dist.sha256",
                "sha256": "2" * 64,
            },
            "published_status": {
                "context": "ruleset/published",
                "state": "success",
                "github_actions_app_id": 15368,
            },
            "source_attestation": {
                "workflow": "owner/project/.github/workflows/source-discovery.yml",
                "source_sha": "e" * 40,
                "subject_sha256": "1" * 64,
            },
            "anchor_sha256": "",
        }
        anchor["anchor_sha256"] = PLANNER.digest_payload(
            {key: value for key, value in anchor.items() if key != "anchor_sha256"}
        )
        self.lkg_binding = {
            "schema": PLANNER.BINDING_SCHEMA,
            "mode": "shadow-bootstrap-only",
            "enforcement_ready": False,
            "binding_policy": PLANNER.BINDING_POLICY,
            "lkg_granularity": "published-category-output-bundle",
            "per_source_lkg_available": False,
            "single_source_snapshot": False,
            "normalized_source_payloads_included": False,
            "licensing_assertions_added": False,
            "exact_main_sha": "f" * 40,
            "main_dist_tree_oid": "d" * 40,
            "lkg_anchor": anchor,
            "dist_tree_sha256": PLANNER.digest_payload(
                PLANNER.directory_manifest(self.baseline_dist)
            ),
            "baseline_index_sha256": PLANNER.digest_payload(self.baseline_index),
            "baseline_candidate_manifest_sha256": PLANNER.digest_payload(
                json.loads(
                    (self.baseline_dist / "candidate_manifest.json").read_text(
                        encoding="utf-8"
                    )
                )
            ),
            "baseline_source_provenance_sha256": PLANNER.digest_payload(
                provenance("a" * 40)
            ),
            "baseline_source_lock_sha256": baseline_lock_sha256,
            "baseline_source_lock_repositories": sorted(baseline_repositories),
            "category_count": len(lkg_categories),
            "categories": [
                lkg_categories[category] for category in sorted(lkg_categories)
            ],
        }
        self.lkg_binding["binding_sha256"] = PLANNER.digest_payload(
            self.lkg_binding
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def build_plan(
        self,
        review: dict,
        *,
        config: dict | None = None,
        baseline_index: dict | None = None,
        candidate_index: dict | None = None,
        candidate_provenance: dict | None = None,
        lkg_binding: dict | None = None,
    ) -> dict:
        return PLANNER.build_plan(
            review,
            config or self.config,
            baseline_index or self.baseline_index,
            candidate_index or self.candidate_index,
            candidate_provenance or provenance(),
            exact_main_sha="f" * 40,
            baseline_dist=self.baseline_dist,
            candidate_dist=self.candidate_dist,
            lkg_binding=lkg_binding or self.lkg_binding,
            source_root=self.repository_root,
        )

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
        plan = self.build_plan(review)
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
        plan = self.build_plan(review)
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
        plan = self.build_plan(review)
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
            self.build_plan(review)

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
            self.build_plan(review, candidate_provenance=tampered_provenance)

    def test_rehashed_provenance_cannot_omit_a_canonical_source(self) -> None:
        tampered_provenance = provenance()
        tampered_provenance["sources"] = [
            row
            for row in tampered_provenance["sources"]
            if row["source_id"] != "source-b"
        ]
        tampered_provenance["source_count"] = len(
            tampered_provenance["sources"]
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        isolation = review["isolation_evidence"]
        isolation["source_provenance_sha256"] = PLANNER.digest_payload(
            tampered_provenance
        )
        isolation.pop("evidence_sha256")
        isolation["evidence_sha256"] = PLANNER.digest_payload(isolation)
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError, "canonical coverage is incomplete"
        ):
            self.build_plan(review, candidate_provenance=tampered_provenance)

    def test_rehashed_provenance_cannot_reassign_repository_membership(self) -> None:
        tampered_provenance = provenance()
        rows = {
            row["source_id"]: row for row in tampered_provenance["sources"]
        }
        rows["source-b"].pop("repository")
        rows["source-b"]["resolved_ref"] = "https://decoy.example/b"
        rows["source-c"]["repository"] = "shared/repo"
        rows["source-c"]["requested_ref"] = "main"
        rows["source-c"]["resolved_revision"] = "b" * 40
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        isolation = review["isolation_evidence"]
        isolation["source_provenance_sha256"] = PLANNER.digest_payload(
            tampered_provenance
        )
        isolation.pop("evidence_sha256")
        isolation["evidence_sha256"] = PLANNER.digest_payload(isolation)
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError,
            "repository differs from configuration",
        ):
            self.build_plan(review, candidate_provenance=tampered_provenance)

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
            self.build_plan(review)

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
        first = self.build_plan(review)
        second = self.build_plan(
            copy.deepcopy(review),
            config=copy.deepcopy(self.config),
            baseline_index=copy.deepcopy(self.baseline_index),
            candidate_index=copy.deepcopy(self.candidate_index),
            candidate_provenance=copy.deepcopy(provenance()),
            lkg_binding=copy.deepcopy(self.lkg_binding),
        )
        self.assertEqual(PLANNER.canonical_bytes(first), PLANNER.canonical_bytes(second))

    def test_removal_holds_the_leaf_shared_repository_and_aggregate(self) -> None:
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
            evidence_overrides={"a": {"added_count": 0, "removed_count": 1}},
        )
        plan = self.build_plan(review)
        self.assertEqual(plan["accepted_candidate_categories"], ["c"])
        self.assertEqual(
            plan["quarantined_categories"], ["a", "aggregate", "b"]
        )
        decisions = {
            item["category"]: item for item in plan["category_decisions"]
        }
        self.assertIn(
            "removal-absence-proof-unavailable",
            decisions["a"]["reason_codes"],
        )
        self.assertIn(
            "removal-absence-proof-unavailable",
            decisions["b"]["reason_codes"],
        )

    def test_unreported_peer_identity_change_is_rejected(self) -> None:
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
            changed=["a", "aggregate", "c"],
        )
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError,
            "identity changes are absent from review",
        ):
            self.build_plan(review)

    def test_candidate_equivalent_peer_closes_changed_repository(self) -> None:
        (self.candidate_dist / "stash" / "b.list").write_bytes(
            (self.baseline_dist / "stash" / "b.list").read_bytes()
        )
        (self.candidate_dist / "meta" / "b.json").write_bytes(
            (self.baseline_dist / "meta" / "b.json").read_bytes()
        )
        (self.candidate_dist / "meta" / "b.json").write_text(
            '{"id":"b","revision":"candidate"}\n', encoding="utf-8"
        )
        candidate_index = copy.deepcopy(self.candidate_index)
        for row in candidate_index["categories"]:
            if row["id"] == "b":
                row["rule_count"] = 1
        review = build_review(
            self.config,
            self.baseline_index,
            candidate_index,
            [],
            [],
            changed=["a", "aggregate", "c"],
        )
        plan = self.build_plan(review, candidate_index=candidate_index)
        self.assertEqual(plan["accepted_candidate_categories"], ["a", "c"])
        decisions = {
            item["category"]: item for item in plan["category_decisions"]
        }
        self.assertEqual(decisions["a"]["selection"], "candidate-category")
        self.assertEqual(
            decisions["b"]["selection"], "candidate-equivalent-category"
        )
        self.assertNotEqual(
            decisions["b"]["selected_output_bundle_sha256"],
            next(
                row["output_bundle_sha256"]
                for row in self.lkg_binding["categories"]
                if row["category"] == "b"
            ),
        )
        self.assertEqual(
            plan["stable_selection"]["repository_selections"][0]["selection"],
            "observed-candidate-lock",
        )

    def test_candidate_repository_closure_reaches_a_second_locked_repo(self) -> None:
        config = copy.deepcopy(self.config)
        for category, source_id in (("b", "source-b2"), ("c", "source-c2")):
            row = next(item for item in config["categories"] if item["id"] == category)
            row["sources"].append(
                {
                    "source_id": source_id,
                    "type": "remote_domain",
                    "url": (
                        f"https://raw.githubusercontent.com/second/repo/main/{category}"
                    ),
                    "authority": "community",
                }
            )

        baseline_lock = source_lock("a" * 40)
        candidate_lock = source_lock("b" * 40)
        baseline_lock["repositories"]["second/repo"] = {
            "requested_ref": "main",
            "resolved_revision": "c" * 40,
            "tree_revision": "c" * 40,
            "binding_count": 2,
        }
        candidate_lock["repositories"]["second/repo"] = {
            "requested_ref": "main",
            "resolved_revision": "d" * 40,
            "tree_revision": "d" * 40,
            "binding_count": 2,
        }

        def extended_provenance(revision: str, lock: dict) -> dict:
            payload = provenance(revision)
            second_revision = lock["repositories"]["second/repo"][
                "resolved_revision"
            ]
            for category, source_id in (("b", "source-b2"), ("c", "source-c2")):
                payload["sources"].append(
                    {
                        "source_id": source_id,
                        "repository": "second/repo",
                        "requested_ref": "main",
                        "resolved_revision": second_revision,
                        "resolved_ref": (
                            "https://github.com/second/repo/blob/"
                            f"{second_revision}/{category}"
                        ),
                        "content_sha256": PLANNER.digest_payload(
                            {
                                "source": source_id,
                                "revision": second_revision,
                            }
                        ),
                    }
                )
            payload["source_count"] = len(payload["sources"])
            payload["source_lock_sha256"] = PLANNER.source_lock_identity(
                lock, "extended"
            )[0]
            return payload

        baseline_provenance = extended_provenance("a" * 40, baseline_lock)
        candidate_provenance = extended_provenance("b" * 40, candidate_lock)
        for root, lock, source_rows in (
            (self.baseline_dist, baseline_lock, baseline_provenance),
            (self.candidate_dist, candidate_lock, candidate_provenance),
        ):
            (root / "sources.lock.json").write_text(
                json.dumps(lock, sort_keys=True) + "\n", encoding="utf-8"
            )
            (root / "source_provenance.json").write_text(
                json.dumps(source_rows, sort_keys=True) + "\n", encoding="utf-8"
            )
            manifest = json.loads(
                (root / "candidate_manifest.json").read_text(encoding="utf-8")
            )
            manifest["source_lock_sha256"] = source_rows["source_lock_sha256"]
            (root / "candidate_manifest.json").write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )

        candidate_index = copy.deepcopy(self.candidate_index)
        for category in ("b", "c"):
            (self.candidate_dist / "stash" / f"{category}.list").write_bytes(
                (self.baseline_dist / "stash" / f"{category}.list").read_bytes()
            )
            next(
                row for row in candidate_index["categories"] if row["id"] == category
            )["rule_count"] = 1

        lkg_binding = copy.deepcopy(self.lkg_binding)
        baseline_lock_sha256, baseline_repositories = PLANNER.source_lock_identity(
            baseline_lock, "extended baseline"
        )
        lkg_binding["dist_tree_sha256"] = PLANNER.digest_payload(
            PLANNER.directory_manifest(self.baseline_dist)
        )
        lkg_binding["baseline_candidate_manifest_sha256"] = PLANNER.digest_payload(
            json.loads(
                (self.baseline_dist / "candidate_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
        )
        lkg_binding["baseline_source_provenance_sha256"] = PLANNER.digest_payload(
            baseline_provenance
        )
        lkg_binding["baseline_source_lock_sha256"] = baseline_lock_sha256
        lkg_binding["baseline_source_lock_repositories"] = sorted(
            baseline_repositories
        )
        lkg_binding.pop("binding_sha256")
        lkg_binding["binding_sha256"] = PLANNER.digest_payload(lkg_binding)

        review = build_review(
            config,
            self.baseline_index,
            candidate_index,
            [],
            [],
            changed=["a", "aggregate"],
        )
        review["baseline_source_lock_sha256"] = baseline_lock_sha256
        review["current_source_lock_sha256"] = PLANNER.source_lock_identity(
            candidate_lock, "extended candidate"
        )[0]
        isolation = review["isolation_evidence"]
        isolation["source_provenance_sha256"] = PLANNER.digest_payload(
            candidate_provenance
        )
        isolation.pop("evidence_sha256")
        isolation["evidence_sha256"] = PLANNER.digest_payload(isolation)

        plan = self.build_plan(
            review,
            config=config,
            candidate_index=candidate_index,
            candidate_provenance=candidate_provenance,
            lkg_binding=lkg_binding,
        )
        decisions = {
            item["category"]: item for item in plan["category_decisions"]
        }
        self.assertEqual(plan["accepted_candidate_categories"], ["a"])
        self.assertEqual(
            decisions["b"]["selection"], "candidate-equivalent-category"
        )
        self.assertEqual(
            decisions["c"]["selection"], "candidate-equivalent-category"
        )
        self.assertEqual(
            {
                row["repository"]
                for row in plan["stable_selection"]["repository_selections"]
                if row["selection"] == "observed-candidate-lock"
            },
            {"shared/repo", "second/repo"},
        )

    def test_all_categories_are_explicit_and_aggregate_requires_recompute(self) -> None:
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        plan = self.build_plan(review)
        decisions = {
            item["category"]: item for item in plan["category_decisions"]
        }
        self.assertEqual(set(decisions), {"a", "aggregate", "b", "c"})
        self.assertEqual(
            decisions["aggregate"]["selection"],
            "derived-recompute-required",
        )
        self.assertTrue(
            decisions["aggregate"]["composite_materialization_required"]
        )
        self.assertFalse(plan["composite_identity_ready"])
        self.assertFalse(plan["two_cycle_enforcement_eligible"])
        self.assertEqual(
            plan["stable_selection_fingerprint_kind"],
            "shadow-selection-not-composite",
        )
        self.assertFalse(plan["enforcement_ready"])

    def test_held_aggregate_uses_complete_published_lkg_without_overlay(self) -> None:
        message = "source a lacks independent authority"
        finding = PLANNER.isolation_finding(
            code="addition-independent-authority",
            scope="rule",
            isolatable=True,
            message=message,
            category="a",
            repository_bindings=["shared/repo"],
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        plan = self.build_plan(review)
        aggregate = next(
            row
            for row in plan["category_decisions"]
            if row["category"] == "aggregate"
        )
        lkg_aggregate = next(
            row
            for row in self.lkg_binding["categories"]
            if row["category"] == "aggregate"
        )
        self.assertEqual(aggregate["selection"], "published-category-lkg")
        self.assertEqual(
            aggregate["selected_snapshot_sha256"],
            lkg_aggregate["snapshot_sha256"],
        )
        self.assertNotIn("manual_overlay_sha256", aggregate)
        self.assertFalse(aggregate["composite_materialization_required"])

    def test_stable_selection_excludes_discarded_candidate_index_noise(self) -> None:
        message = "source a lacks independent authority"
        finding = PLANNER.isolation_finding(
            code="addition-independent-authority",
            scope="rule",
            isolatable=True,
            message=message,
            category="a",
            repository_bindings=["shared/repo"],
        )
        first_review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        first = self.build_plan(first_review)

        noisy_index = copy.deepcopy(self.candidate_index)
        noisy_index["generated_at_utc"] = "2099-01-01T00:00:00Z"
        noisy_index["categories"][0]["transient_observation"] = "discarded"
        second_review = build_review(
            self.config,
            self.baseline_index,
            noisy_index,
            [finding],
            [message],
        )
        second = self.build_plan(
            second_review, candidate_index=noisy_index
        )
        self.assertNotEqual(first["plan_fingerprint"], second["plan_fingerprint"])
        self.assertEqual(
            first["stable_selection_fingerprint"],
            second["stable_selection_fingerprint"],
        )

    def test_stable_selection_binds_an_accepted_candidate_bundle(self) -> None:
        message = "source a lacks independent authority"
        finding = PLANNER.isolation_finding(
            code="addition-independent-authority",
            scope="rule",
            isolatable=True,
            message=message,
            category="a",
            repository_bindings=["shared/repo"],
        )
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [finding],
            [message],
        )
        first = self.build_plan(review)
        (self.candidate_dist / "meta" / "c.json").write_text(
            '{"id":"c","selected":"different"}\n', encoding="utf-8"
        )
        second = self.build_plan(copy.deepcopy(review))
        self.assertNotEqual(
            first["stable_selection_fingerprint"],
            second["stable_selection_fingerprint"],
        )

    def test_stable_selection_binds_selected_mutable_source_provenance(self) -> None:
        first_review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        first = self.build_plan(first_review)
        changed_provenance = provenance()
        for row in changed_provenance["sources"]:
            if row["source_id"] == "source-c":
                row["content_sha256"] = "7" * 64
        second_review = copy.deepcopy(first_review)
        isolation = second_review["isolation_evidence"]
        isolation["source_provenance_sha256"] = PLANNER.digest_payload(
            changed_provenance
        )
        isolation.pop("evidence_sha256")
        isolation["evidence_sha256"] = PLANNER.digest_payload(isolation)
        second = self.build_plan(
            second_review, candidate_provenance=changed_provenance
        )
        self.assertNotEqual(
            first["stable_selection"]["selected_source_provenance_sha256"],
            second["stable_selection"]["selected_source_provenance_sha256"],
        )
        self.assertNotEqual(
            first["stable_selection_fingerprint"],
            second["stable_selection_fingerprint"],
        )

    def test_stable_selection_excludes_reason_code_noise(self) -> None:
        first_message = "source a lacks independent authority"
        second_message = "source a failed a separate trust check"
        findings = []
        for code, message in (
            ("addition-independent-authority", first_message),
            ("addition-source-policy", second_message),
        ):
            findings.append(
                PLANNER.isolation_finding(
                    code=code,
                    scope="rule",
                    isolatable=True,
                    message=message,
                    category="a",
                    repository_bindings=["shared/repo"],
                )
            )
        first = self.build_plan(
            build_review(
                self.config,
                self.baseline_index,
                self.candidate_index,
                [findings[0]],
                [first_message],
            )
        )
        second = self.build_plan(
            build_review(
                self.config,
                self.baseline_index,
                self.candidate_index,
                [findings[1]],
                [second_message],
            )
        )
        self.assertNotEqual(first["plan_fingerprint"], second["plan_fingerprint"])
        self.assertEqual(first["held_categories"], second["held_categories"])
        self.assertEqual(
            first["stable_selection_fingerprint"],
            second["stable_selection_fingerprint"],
        )
        self.assertNotIn(
            "reason_codes",
            first["stable_selection"]["category_selections"][0],
        )

    def test_rehashed_lkg_snapshot_cannot_replace_verified_baseline(self) -> None:
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        tampered = copy.deepcopy(self.lkg_binding)
        tampered["categories"][0]["rule_count"] += 1
        snapshot = tampered["categories"][0]
        snapshot.pop("snapshot_sha256")
        snapshot["snapshot_sha256"] = PLANNER.digest_payload(snapshot)
        tampered.pop("binding_sha256")
        tampered["binding_sha256"] = PLANNER.digest_payload(tampered)
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError, "verified baseline"
        ):
            self.build_plan(review, lkg_binding=tampered)

    def test_rehashed_lkg_binding_cannot_detach_candidate_manifest(self) -> None:
        review = build_review(
            self.config,
            self.baseline_index,
            self.candidate_index,
            [],
            [],
        )
        tampered = copy.deepcopy(self.lkg_binding)
        tampered["baseline_candidate_manifest_sha256"] = "4" * 64
        tampered.pop("binding_sha256")
        tampered["binding_sha256"] = PLANNER.digest_payload(tampered)
        with self.assertRaisesRegex(
            PLANNER.IsolationPlannerError, "candidate manifest binding"
        ):
            self.build_plan(review, lkg_binding=tampered)


if __name__ == "__main__":
    unittest.main()
