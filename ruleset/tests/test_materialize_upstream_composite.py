from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import tempfile
import types
import unittest
from unittest import mock

from ruleset.scripts import build_category_lkg_binding as LKG


RULESET_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = RULESET_ROOT / "scripts" / "materialize_upstream_composite.py"
SPEC = importlib.util.spec_from_file_location(
    "materialize_upstream_composite", SCRIPT
)
assert SPEC and SPEC.loader
COMPOSITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPOSITE)


class UpstreamCompositeMaterializerTests(unittest.TestCase):
    def test_observation_summary_binds_isolated_sources_and_blockers(self) -> None:
        source_config = {"categories": []}
        baseline_index = {"category_count": 0, "categories": []}
        candidate_index = {"category_count": 0, "categories": []}
        provenance = {"source_count": 0, "sources": []}
        finding = {
            "category": "safe",
            "code": "source-network-freshness",
            "source_ids": ["safe-source"],
        }
        finding["evidence_digest"] = COMPOSITE.digest_payload(finding)
        evidence = {
            "schema": COMPOSITE.ISOLATION_EVIDENCE_SCHEMA,
            "mode": "shadow-only",
            "source_provenance_sha256": COMPOSITE.digest_payload(provenance),
            "complete_blocker_mapping": True,
            "blocker_count": 1,
            "findings": [finding],
            "findings_sha256": COMPOSITE.digest_payload([finding]),
            "unscoped_blockers": [],
        }
        evidence["evidence_sha256"] = COMPOSITE.digest_payload(evidence)
        plan = {
            "automated_review_sha256": "1" * 64,
            "isolation_evidence_sha256": evidence["evidence_sha256"],
            "quarantined_categories": ["safe"],
            "held_categories": ["safe"],
        }
        artifact = {
            "schema": COMPOSITE.ISOLATION_ARTIFACT_SCHEMA,
            "mode": "shadow-only",
            "automated_review_sha256": plan["automated_review_sha256"],
            "baseline_index_sha256": COMPOSITE.digest_payload(baseline_index),
            "candidate_index_sha256": COMPOSITE.digest_payload(candidate_index),
            "source_config_sha256": COMPOSITE.digest_payload(source_config),
            "isolation_evidence": evidence,
        }
        artifact["artifact_sha256"] = COMPOSITE.digest_payload(artifact)
        summary = COMPOSITE.isolation_observation_summary(
            artifact=artifact,
            plan=plan,
            source_config=source_config,
            baseline_index=baseline_index,
            candidate_index=candidate_index,
            candidate_provenance=provenance,
        )
        self.assertEqual(summary["blocker_count"], 1)
        self.assertEqual(summary["isolated_source_ids"], ["safe-source"])
        self.assertEqual(summary["quarantined_categories"], ["safe"])

    def test_shadow_outputs_cannot_target_repository_dist(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = pathlib.Path(raw_temp)
            args = types.SimpleNamespace(
                output_dist=COMPOSITE.builder.DEFAULT_DIST_DIR,
                output_identity=root / "composite-identity.json",
                output_review=root / "composite-review.json",
            )
            with self.assertRaisesRegex(
                COMPOSITE.CompositeError, "outside the repository tree"
            ):
                COMPOSITE.validate_shadow_outputs(args)

    def test_shadow_sidecars_cannot_be_written_inside_dist(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = pathlib.Path(raw_temp)
            args = types.SimpleNamespace(
                output_dist=root / "dist",
                output_identity=root / "dist" / "composite-identity.json",
                output_review=root / "composite-review.json",
            )
            with self.assertRaisesRegex(
                COMPOSITE.CompositeError, "outside the output dist tree"
            ):
                COMPOSITE.validate_shadow_outputs(args)

    def test_candidate_delta_rejects_removals_without_absence_proof(self) -> None:
        with self.assertRaisesRegex(COMPOSITE.CompositeError, "removals"):
            COMPOSITE.raw_delta_attribution(
                category="safe",
                before_rules={"DOMAIN-SUFFIX,old.example"},
                after_rules=set(),
                candidate_delta_rows={},
                selected_provenance={},
                allowed_source_ids=set(),
            )

    def test_candidate_delta_rejects_duplicate_membership_witnesses(self) -> None:
        rule = "DOMAIN-SUFFIX,new.example"
        source_id = "safe-source"
        rules = {rule}
        witness = COMPOSITE.witness_for_rules(source_id, rule, rules)
        provenance = {
            "source_id": source_id,
            "accepted_rules_merkle_root": COMPOSITE.builder.rule_set_merkle_root(
                rules
            ),
            "accepted_rules_merkle_leaf_count": 1,
        }
        with self.assertRaisesRegex(COMPOSITE.CompositeError, "membership coverage"):
            COMPOSITE.raw_delta_attribution(
                category="safe",
                before_rules=set(),
                after_rules=rules,
                candidate_delta_rows={
                    "safe": {
                        "added": [
                            {
                                "rule": rule,
                                "sources": [source_id],
                                "source_membership": [witness, dict(witness)],
                            }
                        ]
                    }
                },
                selected_provenance={source_id: provenance},
                allowed_source_ids={source_id},
            )

    def test_mixed_complete_components_recompute_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = pathlib.Path(raw_temp)
            (root / "manual").mkdir()
            (root / "manual" / "aggregate.txt").write_text(
                "overlay.example\n", encoding="utf-8"
            )
            (root / "manual" / "exclude.txt").write_text(
                "excluded.example\n", encoding="utf-8"
            )
            category = {
                "id": "aggregate",
                "aggregate_of": ["held_lkg", "safe_candidate"],
                "manual_overlay_path": "manual/aggregate.txt",
                "exclude_rules_path": "manual/exclude.txt",
            }
            rules, attribution, overlay = COMPOSITE.aggregate_rules(
                category=category,
                rules_by_category={
                    "held_lkg": [
                        "DOMAIN-SUFFIX,held.example",
                        "DOMAIN-SUFFIX,excluded.example",
                    ],
                    "safe_candidate": [
                        "DOMAIN-SUFFIX,safe-new.example",
                    ],
                },
                attribution_by_category={
                    "held_lkg": {},
                    "safe_candidate": {
                        "DOMAIN-SUFFIX,safe-new.example": {"safe-source"}
                    },
                },
                source_root=root,
            )

        self.assertEqual(
            rules,
            [
                "DOMAIN-SUFFIX,held.example",
                "DOMAIN-SUFFIX,overlay.example",
                "DOMAIN-SUFFIX,safe-new.example",
            ],
        )
        self.assertEqual(
            attribution["DOMAIN-SUFFIX,safe-new.example"], {"safe-source"}
        )
        self.assertEqual(
            attribution["DOMAIN-SUFFIX,overlay.example"],
            {"aggregate:manual-overlay"},
        )
        self.assertEqual(overlay, {"DOMAIN-SUFFIX,overlay.example"})

    def test_repository_lock_selection_can_advance_independent_repo(self) -> None:
        def entry(revision: str, count: int) -> dict:
            return {
                "requested_ref": "main",
                "resolved_revision": revision,
                "tree_revision": revision,
                "binding_count": count,
            }

        baseline = {
            "version": 1,
            "repositories": {
                "bad/repo": entry("a" * 40, 1),
                "safe/repo": entry("b" * 40, 1),
            },
        }
        candidate = {
            "version": 1,
            "repositories": {
                "bad/repo": entry("c" * 40, 1),
                "safe/repo": entry("d" * 40, 1),
            },
        }
        rows = [
            {
                "repository": "bad/repo",
                "selection": "published-lkg-lock",
                "bound_leaf_categories": ["held"],
                "selected_entry_sha256": COMPOSITE.digest_payload(
                    baseline["repositories"]["bad/repo"]
                ),
            },
            {
                "repository": "safe/repo",
                "selection": "observed-candidate-lock",
                "bound_leaf_categories": ["safe"],
                "selected_entry_sha256": COMPOSITE.digest_payload(
                    candidate["repositories"]["safe/repo"]
                ),
            },
        ]
        plan = {
            "stable_selection": {
                "repository_selections": rows,
                "selected_repository_lock_sha256": COMPOSITE.digest_payload(rows),
            }
        }
        selected, _digest, _repositories = COMPOSITE.selected_source_lock(
            plan=plan,
            baseline_lock=baseline,
            candidate_lock=candidate,
            generated_at_utc="2026-08-02T00:00:00+00:00",
        )
        self.assertEqual(
            selected["repositories"]["bad/repo"]["resolved_revision"],
            "a" * 40,
        )
        self.assertEqual(
            selected["repositories"]["safe/repo"]["resolved_revision"],
            "d" * 40,
        )

    def test_legacy_lkg_provenance_requires_exact_current_binding(self) -> None:
        COMPOSITE.builder.SOURCE_REGISTRY = json.loads(
            (RULESET_ROOT / "config" / "source_registry.json").read_text(
                encoding="utf-8"
            )
        )
        source = {
            "type": "local_domain",
            "path": "manual/categories/test.txt",
            "authority": "owner-controlled",
        }
        controls = COMPOSITE.builder.source_controls(source)
        provenance = {
            "type": "local_domain",
            "authority": "owner-controlled",
            "trust_tier": controls["trust_tier"],
            "license": controls["license"],
            "owner": controls["owner"],
            "revision_strategy": controls["revision_strategy"],
            "requested_refs": ["manual/categories/test.txt"],
            "limits": {
                "allowed_hosts": list(controls["allowed_hosts"]),
                "max_bytes": int(controls["max_bytes"]),
                "max_files": int(controls["max_files"]),
                "max_include_depth": int(controls["max_include_depth"]),
                "freshness_ttl_hours": float(controls["freshness_ttl_hours"]),
            },
            "critical": bool(controls["critical"]),
            "no_cache_publish": bool(controls["no_cache_publish"]),
            "parser_stats": {
                "accepted_line_ratio": 1.0,
                "rule_type_counts": {},
            },
        }
        COMPOSITE.validate_configured_source(
            source=source,
            source_id="test-source",
            provenance=provenance,
            legacy_config_digest=COMPOSITE.builder.configured_source_digest(
                source
            ),
        )
        with self.assertRaisesRegex(
            COMPOSITE.CompositeError, "lacks an exact bound config digest"
        ):
            COMPOSITE.validate_configured_source(
                source=source,
                source_id="test-source",
                provenance=provenance,
            )
        drifted = dict(provenance)
        drifted["requested_refs"] = ["manual/categories/other.txt"]
        with self.assertRaisesRegex(
            COMPOSITE.CompositeError, "differs from config"
        ):
            COMPOSITE.validate_configured_source(
                source=source,
                source_id="test-source",
                provenance=drifted,
                legacy_config_digest=COMPOSITE.builder.configured_source_digest(
                    source
                ),
            )

    def test_end_to_end_candidate_materialization_is_deterministic(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="project-g-e2e-repo-") as raw_repo,
            tempfile.TemporaryDirectory(prefix="project-g-e2e-first-") as raw_first,
            tempfile.TemporaryDirectory(prefix="project-g-e2e-second-") as raw_second,
        ):
            repository_root = pathlib.Path(raw_repo)
            ruleset_root = repository_root / "ruleset"
            (ruleset_root / "config").mkdir(parents=True)
            (ruleset_root / "manual" / "categories").mkdir(parents=True)
            shutil.copy2(
                RULESET_ROOT / "config" / "public_suffix_list.dat",
                ruleset_root / "config" / "public_suffix_list.dat",
            )

            config = {
                "version": 3,
                "categories": [
                    {
                        "id": "safe",
                        "description": "safe fixture",
                        "sources": [
                            {
                                "type": "local_domain",
                                "path": "manual/categories/safe.txt",
                                "authority": "owner-controlled",
                            }
                        ],
                    }
                ],
            }
            policy = {
                "version": 1,
                "categories": {
                    "safe": {
                        "action": "PROXY",
                        "priority": 100,
                        "note": "fixture",
                    }
                },
            }
            registry = json.loads(
                (RULESET_ROOT / "config" / "source_registry.json").read_text(
                    encoding="utf-8"
                )
            )
            canonical_contracts = json.loads(
                (RULESET_ROOT / "config" / "category_contracts.json").read_text(
                    encoding="utf-8"
                )
            )
            contracts = {
                "version": 1,
                "defaults": canonical_contracts["defaults"],
                "categories": {},
            }
            fixture_paths = {
                "source_config": ruleset_root / "sources.json",
                "policy": ruleset_root / "policy.json",
                "source_registry": ruleset_root / "registry.json",
                "category_contracts": ruleset_root / "contracts.json",
            }
            for key, payload in (
                ("source_config", config),
                ("policy", policy),
                ("source_registry", registry),
                ("category_contracts", contracts),
            ):
                fixture_paths[key].write_bytes(COMPOSITE.canonical_bytes(payload))

            source_path = ruleset_root / "manual" / "categories" / "safe.txt"
            baseline_dist = repository_root / "baseline-dist"
            candidate_dist = repository_root / "candidate-dist"
            build_args = {
                "config_path": fixture_paths["source_config"],
                "policy_path": fixture_paths["policy"],
                "source_registry_path": fixture_paths["source_registry"],
                "category_contracts_path": fixture_paths["category_contracts"],
                "source_lock_path": None,
                "cache_dir": repository_root / "cache",
                "offline": True,
                "fail_on_conflicts": False,
                "fail_on_cross_action_conflicts": True,
            }
            exact_main_sha = "f" * 40
            with mock.patch.object(COMPOSITE.builder, "ROOT_DIR", ruleset_root):
                source_path.write_text("old.example\n", encoding="utf-8")
                self.assertEqual(
                    COMPOSITE.builder.build_all_staged(
                        baseline_dist_dir=None,
                        dist_dir=baseline_dist,
                        **build_args,
                    ),
                    0,
                )
                source_path.write_text(
                    "old.example\nnew.example\n", encoding="utf-8"
                )
                self.assertEqual(
                    COMPOSITE.builder.build_all_staged(
                        baseline_dist_dir=baseline_dist,
                        dist_dir=candidate_dist,
                        **build_args,
                    ),
                    0,
                )

                for dist in (baseline_dist, candidate_dist):
                    manifest = COMPOSITE.read_json(
                        dist / "candidate_manifest.json"
                    )
                    manifest["source_commit_sha"] = exact_main_sha
                    (dist / "candidate_manifest.json").write_bytes(
                        COMPOSITE.canonical_bytes(manifest)
                    )

                baseline_index = COMPOSITE.read_json(baseline_dist / "index.json")
                candidate_index = COMPOSITE.read_json(
                    candidate_dist / "index.json"
                )
                baseline_provenance = COMPOSITE.read_json(
                    baseline_dist / "source_provenance.json"
                )
                candidate_provenance = COMPOSITE.read_json(
                    candidate_dist / "source_provenance.json"
                )
                baseline_lock = COMPOSITE.read_json(
                    baseline_dist / "sources.lock.json"
                )
                baseline_lock_sha256, baseline_repositories = (
                    COMPOSITE.source_lock_identity(baseline_lock, "fixture LKG")
                )
                lkg_identities = COMPOSITE.category_output_identities(
                    baseline_dist, baseline_index
                )
                candidate_identities = COMPOSITE.category_output_identities(
                    candidate_dist, candidate_index
                )

                legacy_exception = {
                    "schema": "project-g-legacy-provenance-derivation-v1",
                    "policy": "exact-immutable-archive-allowlist-v1",
                    "active": False,
                    "release_archive_sha256": "1" * 64,
                    "derived_source_count": 0,
                    "derived_sources": [],
                }
                legacy_exception["exception_sha256"] = COMPOSITE.digest_payload(
                    legacy_exception
                )
                publication_statuses = {
                    context: {
                        "id": status_id,
                        "run_id": 20,
                        "context": context,
                        "state": "success",
                        "description": LKG.PUBLICATION_STATUS_DESCRIPTIONS[context],
                        "github_actions_app_id": 15368,
                    }
                    for context, status_id in (
                        ("ruleset/gate", 9),
                        ("ruleset/published", 10),
                    )
                }
                publication_receipt = {
                    "receipt_sha256": "6" * 64,
                    "release_parent_sha": exact_main_sha,
                    "publication_statuses": {
                        context: {
                            "status_id": status["id"],
                            "run_id": 20,
                            "run_attempt": 1,
                        }
                        for context, status in publication_statuses.items()
                    },
                }
                anchor = {
                    "repository": "owner/project",
                    "release_id": 1,
                    "release_tag": "ruleset-20260802T000000Z-aaaaaaaaaaaa",
                    "release_commit_sha": "a" * 40,
                    "release_dist_tree_oid": "d" * 40,
                    "archive_asset": {
                        "name": "ruleset-dist.tar.gz",
                        "sha256": "1" * 64,
                    },
                    "checksum_asset": {
                        "name": "ruleset-dist.sha256",
                        "sha256": "2" * 64,
                    },
                    "publication_statuses": publication_statuses,
                    "publication_receipt": publication_receipt,
                    "source_attestation": {
                        "workflow": (
                            "owner/project/.github/workflows/source-discovery.yml"
                        ),
                        "source_sha": exact_main_sha,
                        "subject_sha256": "1" * 64,
                    },
                }
                anchor["anchor_sha256"] = COMPOSITE.digest_payload(anchor)
                baseline_manifest = COMPOSITE.read_json(
                    baseline_dist / "candidate_manifest.json"
                )
                binding = {
                    "schema": LKG.BINDING_SCHEMA,
                    "mode": "shadow-bootstrap-only",
                    "enforcement_ready": False,
                    "binding_policy": LKG.BINDING_POLICY,
                    "lkg_granularity": "published-category-output-bundle",
                    "per_source_lkg_available": False,
                    "single_source_snapshot": False,
                    "normalized_source_payloads_included": False,
                    "licensing_assertions_added": False,
                    "source_config_unchanged_since_release": True,
                    "source_config_candidate_release_main_bound": True,
                    "source_config_blob_oid": "9" * 40,
                    "source_config_sha256": COMPOSITE.digest_payload(config),
                    "source_registry_unchanged_since_release": True,
                    "source_registry_candidate_release_main_bound": True,
                    "source_registry_blob_oid": "8" * 40,
                    "source_registry_sha256": COMPOSITE.digest_payload(registry),
                    "legacy_provenance_exception": legacy_exception,
                    "exact_main_sha": exact_main_sha,
                    "main_dist_tree_oid": "d" * 40,
                    "lkg_anchor": anchor,
                    "dist_tree_sha256": COMPOSITE.digest_payload(
                        COMPOSITE.directory_manifest(baseline_dist)
                    ),
                    "baseline_index_sha256": COMPOSITE.digest_payload(
                        baseline_index
                    ),
                    "baseline_candidate_manifest_sha256": (
                        COMPOSITE.digest_payload(baseline_manifest)
                    ),
                    "baseline_source_provenance_sha256": (
                        COMPOSITE.digest_payload(baseline_provenance)
                    ),
                    "baseline_source_lock_sha256": baseline_lock_sha256,
                    "baseline_source_lock_repositories": sorted(
                        baseline_repositories
                    ),
                    "category_count": 1,
                    "categories": [lkg_identities["safe"]],
                }
                binding["binding_sha256"] = COMPOSITE.digest_payload(binding)

                selected = candidate_identities["safe"]
                decision = {
                    "category": "safe",
                    "category_kind": "leaf",
                    "selection": "candidate-category",
                    "selected_snapshot_sha256": selected["snapshot_sha256"],
                    "selected_normalized_rules_sha256": selected[
                        "normalized_rules_sha256"
                    ],
                    "selected_rule_count": selected["rule_count"],
                    "selected_output_bundle_sha256": selected[
                        "output_bundle_sha256"
                    ],
                }
                stable_selection = {
                    "schema": COMPOSITE.SELECTION_SCHEMA,
                    "composite_identity_ready": False,
                    "two_cycle_enforcement_eligible": False,
                    "repository_selections": [],
                    "selected_repository_lock_sha256": (
                        COMPOSITE.digest_payload([])
                    ),
                }
                isolation_evidence = {
                    "schema": COMPOSITE.ISOLATION_EVIDENCE_SCHEMA,
                    "mode": "shadow-only",
                    "source_provenance_sha256": COMPOSITE.digest_payload(
                        candidate_provenance
                    ),
                    "complete_blocker_mapping": True,
                    "blocker_count": 0,
                    "findings": [],
                    "findings_sha256": COMPOSITE.digest_payload([]),
                    "unscoped_blockers": [],
                }
                isolation_evidence["evidence_sha256"] = (
                    COMPOSITE.digest_payload(isolation_evidence)
                )
                plan = {
                    "schema": COMPOSITE.PLAN_SCHEMA,
                    "planner_policy": COMPOSITE.PLANNER_POLICY,
                    "mode": "shadow-only",
                    "enforcement_ready": False,
                    "exact_main_sha": exact_main_sha,
                    "source_config_sha256": COMPOSITE.digest_payload(config),
                    "source_registry_sha256": COMPOSITE.digest_payload(registry),
                    "baseline_index_sha256": COMPOSITE.digest_payload(
                        baseline_index
                    ),
                    "candidate_index_sha256": COMPOSITE.digest_payload(
                        candidate_index
                    ),
                    "source_provenance_sha256": COMPOSITE.digest_payload(
                        candidate_provenance
                    ),
                    "category_lkg_binding_sha256": binding["binding_sha256"],
                    "category_lkg_anchor_sha256": anchor["anchor_sha256"],
                    "automated_review_sha256": "7" * 64,
                    "isolation_evidence_sha256": isolation_evidence[
                        "evidence_sha256"
                    ],
                    "quarantined_categories": [],
                    "held_categories": [],
                    "category_decisions": [decision],
                    "stable_selection": stable_selection,
                    "stable_selection_fingerprint": COMPOSITE.digest_payload(
                        stable_selection
                    ),
                }
                plan["plan_fingerprint"] = COMPOSITE.digest_payload(plan)
                isolation_artifact = {
                    "schema": COMPOSITE.ISOLATION_ARTIFACT_SCHEMA,
                    "mode": "shadow-only",
                    "automated_review_sha256": plan[
                        "automated_review_sha256"
                    ],
                    "baseline_index_sha256": COMPOSITE.digest_payload(
                        baseline_index
                    ),
                    "candidate_index_sha256": COMPOSITE.digest_payload(
                        candidate_index
                    ),
                    "source_config_sha256": COMPOSITE.digest_payload(config),
                    "isolation_evidence": isolation_evidence,
                }
                isolation_artifact["artifact_sha256"] = (
                    COMPOSITE.digest_payload(isolation_artifact)
                )

                evidence_paths = {
                    "plan": repository_root / "plan.json",
                    "isolation_evidence": repository_root / "evidence.json",
                    "lkg_binding": repository_root / "binding.json",
                }
                for key, payload in (
                    ("plan", plan),
                    ("isolation_evidence", isolation_artifact),
                    ("lkg_binding", binding),
                ):
                    evidence_paths[key].write_bytes(
                        COMPOSITE.canonical_bytes(payload)
                    )

                results = []
                output_roots = [pathlib.Path(raw_first), pathlib.Path(raw_second)]
                for output_root in output_roots:
                    args = types.SimpleNamespace(
                        **evidence_paths,
                        candidate_dist=candidate_dist,
                        lkg_dist=baseline_dist,
                        **fixture_paths,
                        source_root=ruleset_root,
                        exact_main_sha=exact_main_sha,
                        generated_at_utc="2026-08-02T00:00:00Z",
                        output_dist=output_root / "dist",
                        output_identity=output_root / "identity.json",
                        output_review=output_root / "review.json",
                    )
                    results.append(COMPOSITE.build_composite(args))

            first_composite, first_review = results[0]
            second_composite, second_review = results[1]
            self.assertEqual(
                COMPOSITE.canonical_bytes(first_composite),
                COMPOSITE.canonical_bytes(second_composite),
            )
            self.assertEqual(
                COMPOSITE.canonical_bytes(first_review),
                COMPOSITE.canonical_bytes(second_review),
            )
            self.assertEqual(
                COMPOSITE.directory_manifest(pathlib.Path(raw_first) / "dist"),
                COMPOSITE.directory_manifest(pathlib.Path(raw_second) / "dist"),
            )
            self.assertEqual(first_review["changed_categories"], ["safe"])
            self.assertEqual(
                COMPOSITE.read_rules(pathlib.Path(raw_first) / "dist", "safe"),
                [
                    "DOMAIN-SUFFIX,new.example",
                    "DOMAIN-SUFFIX,old.example",
                ],
            )
            self.assertFalse(first_composite["source_health_complete"])
            self.assertFalse(first_composite["licensing_assertions_complete"])


if __name__ == "__main__":
    unittest.main()
