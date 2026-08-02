from __future__ import annotations

import copy
import hashlib
import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "check_automated_review.py"
SPEC = importlib.util.spec_from_file_location("check_automated_review", SCRIPT)
assert SPEC and SPEC.loader
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


def leaf_root(rule: str) -> str:
    return hashlib.sha256(REVIEW.RULE_LEAF_DOMAIN + rule.encode("utf-8")).hexdigest()


def base_inputs() -> tuple[dict, ...]:
    repository_root = pathlib.Path(__file__).resolve().parents[2]
    rule = "DOMAIN-SUFFIX,example.com"
    active_revision = "b" * 40
    source_lock_repositories = {
        "v2fly/domain-list-community": {
            "requested_ref": "master",
            "resolved_revision": active_revision,
            "tree_revision": "c" * 40,
        }
    }
    source_lock_digest, _ = REVIEW.source_lock_identity(
        {"version": 1, "repositories": source_lock_repositories}, "test"
    )
    manifest = {
        "changed": True,
        "baseline_available": True,
        "source_head_advanced_after_lock": False,
        "fallback_cache_count": 0,
        "cache_blocked_source_ids": [],
        "budget_exceeded": [],
        "conflict_delta": {"cross_action": 0, "high_severity": 0},
        "risk_markers": ["category-policy-review", "new-apex"],
        "changed_categories": ["global"],
        "risk_level": "high",
        "requires_review": True,
        "auto_promotion_eligible": False,
        "source_lock_sha256": source_lock_digest,
        "source_lock_changed": False,
    }
    rule_delta = {
        "changed": True,
        "changed_categories": ["global"],
        "risk_markers": ["category-policy-review", "new-apex"],
        "budget_exceeded": [],
        "conflict_delta": {"cross_action": 0, "high_severity": 0},
        "source_lock_changed": False,
        "categories": [
            {
                "category": "global",
                "action": "PROXY",
                "previous_action": "PROXY",
                "priority": 20,
                "previous_priority": 20,
                "category_added": False,
                "category_removed": False,
                "action_changed": False,
                "priority_changed": False,
                "before_count": 0,
                "after_count": 1,
                "budget_observed": {
                    "max_add": 1,
                    "max_remove": 0,
                    "max_pct": 100.0,
                    "max_new_apex": 1,
                    "max_new_regex": 0,
                    "max_new_cidr": 0,
                },
                "budget_exceeded": [],
                "added": [
                    {
                        "rule": rule,
                        "sources": ["global:00:official"],
                        "source_tiers": ["official"],
                        "source_membership": [
                            {
                                "source_id": "global:00:official",
                                "leaf_index": 0,
                                "leaf_count": 1,
                                "proof": [],
                            }
                        ],
                        "old_effective_action": "ABSENT",
                        "new_effective_action": "PROXY",
                        "risk": ["new-apex"],
                    }
                ],
                "removed": [],
            }
        ],
    }
    canonical_contracts = {
        "defaults": {
            "allowed_rule_types": ["DOMAIN-SUFFIX"],
            "allowed_source_tiers": ["official", "community"],
            "required_action": None,
            "aggregate_of": None,
            "auto_promotion_policy": "review",
            "max_add": 10,
            "max_remove": 10,
            "max_pct": 100,
            "max_new_apex": 10,
            "max_new_regex": 10,
            "max_new_cidr": 10,
            "max_informational_overlap_delta": 10,
        },
        "action_profiles": {"PROXY": {}},
        "categories": {"global": {}},
        "manual_only_categories": [],
    }
    resolved = {
        **canonical_contracts["defaults"],
        "category": "global",
        "action": "PROXY",
    }
    contracts = {"categories": {"global": resolved}}
    configured_source = {
        "source_id": "global:00:official",
        "type": "remote_domain",
        "url": "https://official.example/rules.txt",
        "authority": "official",
    }
    source_config = {
        "categories": [{"id": "global", "sources": [configured_source]}]
    }
    dist_evidence = {
        "baseline_index_sha256": "1" * 64,
        "current_index_sha256": "2" * 64,
        "changed_categories": ["global"],
        "conflict_delta": {"cross_action": 0, "high_severity": 0},
        "baseline_source_lock_sha256": source_lock_digest,
        "current_source_lock_sha256": source_lock_digest,
        "source_lock_changed": False,
        "source_lock_repositories": source_lock_repositories,
        "categories": {
            "global": {
                "category_added": False,
                "category_removed": False,
                "previous_action": "PROXY",
                "action": "PROXY",
                "previous_priority": 20,
                "priority": 20,
                "action_changed": False,
                "priority_changed": False,
                "before_count": 0,
                "after_count": 1,
                "added": [rule],
                "removed": [],
                "added_effective_actions": {
                    rule: {"old": "ABSENT", "new": "PROXY"}
                },
                "removed_effective_actions": {},
                "current_contract": resolved,
            }
        },
    }
    source_bindings = REVIEW.canonical_source_bindings(source_config)
    protected_roots = REVIEW.read_json(
        repository_root / "ruleset" / "config" / "protected_domain_roots.json"
    )
    provenance = {
        "source_lock_sha256": source_lock_digest,
        "sources": [
            {
                "source_id": "global:00:official",
                "type": "remote_domain",
                "configured_source_sha256": REVIEW.digest_payload(configured_source),
                "requested_refs": ["https://official.example/rules.txt"],
                "authority": "official",
                "trust_tier": "official",
                "license": "upstream-declared",
                "owner": "upstream-authority",
                "revision_strategy": "https-validators-and-content-sha256",
                "critical": True,
                "used_cache": False,
                "no_cache_publish": True,
                "content_sha256": "a" * 64,
                "resolved_ref": "https://official.example/rules.txt",
                "cache_mode": "network",
                "parser_stats": {"accepted_rule_count": 1},
                "accepted_rules_merkle_root": leaf_root(rule),
                "accepted_rules_merkle_leaf_count": 1,
                "limits": {"allowed_hosts": ["official.example"]},
            }
        ]
    }
    source_registry = {
        "authority_profiles": {
            "official": {
                "trust_tier": "official",
                "license": "upstream-declared",
                "owner": "upstream-authority",
                "revision_strategy": "https-validators-and-content-sha256",
                "critical": True,
                "no_cache_publish": True,
                "allowed_hosts": ["official.example"],
                "allowed_rule_types": ["DOMAIN-SUFFIX"],
            }
        }
    }
    dist_evidence["current_provenance_sha256"] = REVIEW.digest_payload(provenance)
    radar_snapshot = {
        "candidate_only": True,
        "high_impact_quorum": 2,
        "repositories": [
            {
                "repository": "v2fly/domain-list-community",
                "role": "active-locked-source",
                "trust_tier": "community",
                "candidate_only": False,
                "resolved_revision": active_revision,
                "head_tree_revision": "c" * 40,
                "locked_revision": active_revision,
                "previous_revision": active_revision,
                "comparison_basis": "source-lock",
                "changed": False,
            }
        ],
        "v2fly_tree": {"unbuilt_head_files": []},
    }
    radar = {
        "candidate_only": True,
        "promotion_blocked": False,
        "auto_promotion_blocked": False,
        "advanced_active_repositories": [],
        "independent_changed_repositories": [],
        "unbuilt_head_files": [],
        "high_impact_quorum": 2,
        "quorum_review_required": False,
    }
    return (
        manifest,
        rule_delta,
        contracts,
        canonical_contracts,
        source_config,
        dist_evidence,
        source_bindings,
        protected_roots,
        provenance,
        source_registry,
        radar,
        radar_snapshot,
        repository_root,
    )


def build_report(inputs: tuple[object, ...]) -> dict:
    return REVIEW.build_report(*inputs)


def set_rule(inputs: tuple[dict, ...], rule: str, risks: list[str]) -> None:
    addition = inputs[1]["categories"][0]["added"][0]
    addition["rule"] = rule
    addition["risk"] = risks
    inputs[8]["sources"][0]["accepted_rules_merkle_root"] = leaf_root(rule)
    inputs[5]["categories"]["global"]["added"] = [rule]
    inputs[5]["categories"]["global"]["added_effective_actions"] = {
        rule: {"old": "ABSENT", "new": "PROXY"}
    }
    inputs[5]["current_provenance_sha256"] = REVIEW.digest_payload(inputs[8])


class AutomatedReviewTests(unittest.TestCase):
    def test_unchanged_candidate_has_only_the_expected_hold_reason(self) -> None:
        inputs = base_inputs()
        inputs[0].update(
            {
                "changed": False,
                "changed_categories": [],
                "risk_level": "none",
                "risk_markers": [],
                "requires_review": False,
                "auto_promotion_eligible": False,
            }
        )
        inputs[1].update(
            {
                "changed": False,
                "changed_categories": [],
                "risk_markers": [],
                "categories": [],
            }
        )
        inputs[5].update(
            {
                "changed_categories": [],
                "categories": {},
            }
        )
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertEqual(report["blockers"], ["candidate has no semantic changes"])

    def test_official_elevated_addition_is_eligible(self) -> None:
        report = build_report(base_inputs())
        self.assertTrue(report["eligible"], report["blockers"])
        self.assertEqual(report["blockers"], [])
        self.assertEqual(report["required_stable_cycles"], 2)
        self.assertEqual(report["minimum_cycle_separation_seconds"], 300)
        self.assertEqual(report["review_policy"], "unattended-evidence-gated-v2")
        self.assertRegex(
            report["category_evidence"][0]["added_rule_evidence_sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_report_is_deterministic_for_unordered_evidence(self) -> None:
        first = base_inputs()
        second = copy.deepcopy(first)
        first[0]["risk_markers"] = list(reversed(first[0]["risk_markers"]))
        first[1]["risk_markers"] = list(reversed(first[1]["risk_markers"]))
        self.assertEqual(
            REVIEW.canonical_bytes(build_report(first)),
            REVIEW.canonical_bytes(build_report(second)),
        )

    def test_canonical_manual_only_cannot_be_overridden_by_candidate(self) -> None:
        inputs = base_inputs()
        inputs[3]["categories"]["global"]["auto_promotion_policy"] = "manual"
        inputs[3]["manual_only_categories"] = ["global"]
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn("category global is canonical manual-only", report["blockers"])
        self.assertIn(
            "category global resolved contract differs from canonical policy",
            report["blockers"],
        )

    def test_omitted_tld_risk_is_recomputed_and_fails_closed(self) -> None:
        inputs = base_inputs()
        set_rule(inputs, "DOMAIN-SUFFIX,com", [])
        inputs[0]["risk_markers"] = ["category-policy-review"]
        inputs[1]["risk_markers"] = ["category-policy-review"]
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn(
            "category global addition risk was not recomputed exactly: DOMAIN-SUFFIX,com",
            report["blockers"],
        )
        self.assertTrue(
            any(
                blocker.startswith("unsupported elevated risk markers:")
                and "new-tld" in blocker
                for blocker in report["blockers"]
            )
        )

    def test_declared_source_tiers_must_equal_actual_tiers(self) -> None:
        inputs = base_inputs()
        inputs[1]["categories"][0]["added"][0]["source_tiers"] = [
            "community",
            "official",
        ]
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertTrue(
            any("source tiers are not exact" in blocker for blocker in report["blockers"])
        )

    def test_unrelated_radar_repositories_do_not_supply_rule_quorum(self) -> None:
        inputs = base_inputs()
        source = inputs[8]["sources"][0]
        source.update(
            {
                "authority": "community-curated",
                "trust_tier": "community",
                "owner": "trusted/example",
                "revision_strategy": "github-commit-lock",
                "repository": "trusted/example",
                "resolved_revision": "d" * 40,
                "resolved_ref": "https://github.com/trusted/example/blob/"
                + "d" * 40
                + "/rules.txt",
                "cache_mode": "network",
                "limits": {"allowed_hosts": ["raw.githubusercontent.com"]},
            }
        )
        inputs[9]["authority_profiles"] = {
            "community-curated": {
                "trust_tier": "community",
                "license": "upstream-declared",
                "owner": "trusted/example",
                "revision_strategy": "github-commit-lock",
                "critical": True,
                "no_cache_publish": True,
                "allowed_hosts": ["raw.githubusercontent.com"],
                "allowed_rule_types": ["DOMAIN-SUFFIX"],
            }
        }
        addition = inputs[1]["categories"][0]["added"][0]
        addition["source_tiers"] = ["community"]
        addition["risk"] = ["new-apex", "single-community-tier"]
        inputs[0]["risk_markers"] = [
            "category-policy-review",
            "new-apex",
            "single-community-tier",
        ]
        inputs[1]["risk_markers"] = list(inputs[0]["risk_markers"])
        inputs[10]["quorum_review_required"] = True
        inputs[10]["auto_promotion_blocked"] = True
        for index, repository in enumerate(("trusted/a", "trusted/b")):
            row = {
                "repository": repository,
                "role": "independent-radar",
                "trust_tier": "community",
                "candidate_only": True,
                "resolved_revision": str(index + 1) * 40,
                "head_tree_revision": str(index + 3) * 40,
                "locked_revision": "",
                "previous_revision": str(index + 5) * 40,
                "comparison_basis": "baseline",
                "changed": True,
            }
            inputs[11]["repositories"].append(row)
        inputs[10]["independent_changed_repositories"] = ["trusted/a", "trusted/b"]
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn(
            "category global elevated addition lacks rule-level independent authority: DOMAIN-SUFFIX,example.com",
            report["blockers"],
        )

    def test_removal_without_current_source_absence_proof_is_held(self) -> None:
        inputs = base_inputs()
        inputs[1]["categories"][0]["removed"] = [
            {
                "rule": "DOMAIN-SUFFIX,old.example",
                "sources": ["previous_snapshot"],
                "old_effective_action": "PROXY",
                "new_effective_action": "ABSENT",
                "risk": ["new-apex"],
            }
        ]
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn(
            "category global automated removal lacks current-source absence proof: DOMAIN-SUFFIX,old.example",
            report["blockers"],
        )

    def test_membership_tamper_and_https_host_drift_fail_closed(self) -> None:
        inputs = base_inputs()
        inputs[1]["categories"][0]["added"][0]["source_membership"][0][
            "leaf_index"
        ] = 1
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertTrue(
            any("membership index or root" in blocker for blocker in report["blockers"])
        )

        inputs = base_inputs()
        inputs[8]["sources"][0]["resolved_ref"] = "https://attacker.example/rules.txt"
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertTrue(
            any("resolved HTTPS host is not allowlisted" in blocker for blocker in report["blockers"])
        )

    def test_action_priority_and_budget_are_not_accepted_from_producer_flags(self) -> None:
        inputs = base_inputs()
        inputs[1]["categories"][0].update(
            {
                "previous_action": "PROXY",
                "action": "DIRECT",
                "action_changed": False,
            }
        )
        inputs[5]["categories"]["global"].update(
            {
                "previous_action": "PROXY",
                "action": "DIRECT",
                "action_changed": True,
            }
        )
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn(
            "category global action_changed differs from independently recomputed dist",
            report["blockers"],
        )

        inputs = base_inputs()
        inputs[1]["categories"][0].update(
            {
                "previous_priority": 10,
                "priority": 20,
                "priority_changed": False,
            }
        )
        inputs[5]["categories"]["global"].update(
            {
                "previous_priority": 10,
                "priority": 20,
                "priority_changed": True,
            }
        )
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn(
            "category global priority_changed differs from independently recomputed dist",
            report["blockers"],
        )

        inputs = base_inputs()
        inputs[3]["defaults"]["max_add"] = 0
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn(
            "category global budget blockers were not independently recomputed",
            report["blockers"],
        )
        self.assertIn(
            "manifest budget blockers were not independently recomputed",
            report["blockers"],
        )

    def test_source_must_be_reachable_from_canonical_category_graph(self) -> None:
        inputs = base_inputs()
        inputs[4]["categories"][0]["sources"] = []
        inputs = list(inputs)
        inputs[6] = REVIEW.canonical_source_bindings(inputs[4])
        report = build_report(tuple(inputs))
        self.assertFalse(report["eligible"])
        self.assertIn(
            "category global cites source outside canonical source graph: global:00:official",
            report["blockers"],
        )
        self.assertIn(
            "source global:00:official is absent from canonical source config",
            report["blockers"],
        )

    def test_public_suffix_and_multi_tenant_roots_are_automatically_held(self) -> None:
        for root in (
            "co.uk",
            "github.io",
            "pages.dev",
            "tenant.github.io",
            "tenant.pages.dev",
            "tenant.duckdns.org",
            "project.githubusercontent.com",
            "foo.uk.com",
        ):
            with self.subTest(root=root):
                inputs = base_inputs()
                set_rule(inputs, f"DOMAIN-SUFFIX,{root}", ["new-apex"])
                inputs[0]["risk_markers"] = ["category-policy-review", "new-apex"]
                inputs[1]["risk_markers"] = list(inputs[0]["risk_markers"])
                report = build_report(inputs)
                self.assertFalse(report["eligible"])
                self.assertIn(
                    "unsupported elevated risk markers: protected-domain-root",
                    report["blockers"],
                )

    def test_public_suffix_registrable_apex_is_recomputed(self) -> None:
        for root in ("example.co.uk", "foo.blog.br"):
            with self.subTest(root=root):
                inputs = base_inputs()
                set_rule(inputs, f"DOMAIN-SUFFIX,{root}", ["new-apex"])
                report = build_report(inputs)
                self.assertTrue(report["eligible"], report["blockers"])

    def test_source_lock_identity_mismatches_are_held(self) -> None:
        for target, field in (
            (0, "source_lock_sha256"),
            (8, "source_lock_sha256"),
        ):
            with self.subTest(target=target, field=field):
                inputs = base_inputs()
                inputs[target][field] = "f" * 64
                report = build_report(inputs)
                self.assertFalse(report["eligible"])
                self.assertTrue(
                    any("lock" in blocker for blocker in report["blockers"]),
                    report["blockers"],
                )

        inputs = base_inputs()
        inputs[1]["source_lock_changed"] = True
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertIn(
            "rule delta source lock change state was not independently reproduced",
            report["blockers"],
        )

    def test_github_provenance_and_radar_must_match_source_lock(self) -> None:
        inputs = base_inputs()
        source = inputs[8]["sources"][0]
        source.update(
            {
                "repository": "v2fly/domain-list-community",
                "resolved_revision": "d" * 40,
                "resolved_ref": (
                    "https://github.com/v2fly/domain-list-community/blob/"
                    + "d" * 40
                    + "/data/example"
                ),
                "revision_strategy": "github-commit-lock",
            }
        )
        inputs[5]["current_provenance_sha256"] = REVIEW.digest_payload(inputs[8])
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertTrue(
            any("lock" in blocker for blocker in report["blockers"]),
            report["blockers"],
        )

        inputs = base_inputs()
        inputs[11]["repositories"][0]["locked_revision"] = "d" * 40
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertTrue(
            any("lock revision" in blocker for blocker in report["blockers"]),
            report["blockers"],
        )

    def test_cached_source_action_priority_budget_and_conflict_fail_closed(self) -> None:
        inputs = base_inputs()
        inputs[8]["sources"][0]["used_cache"] = True
        inputs[1]["categories"][0]["action_changed"] = True
        inputs[1]["categories"][0]["priority_changed"] = True
        inputs[1]["categories"][0]["budget_exceeded"] = ["global:add"]
        inputs[0]["conflict_delta"]["cross_action"] = 1
        report = build_report(inputs)
        self.assertFalse(report["eligible"])
        self.assertTrue(any("used cache" in blocker for blocker in report["blockers"]))
        self.assertIn(
            "category global action_changed differs from independently recomputed dist",
            report["blockers"],
        )
        self.assertIn(
            "category global budget blockers were not independently recomputed",
            report["blockers"],
        )
        self.assertIn("candidate introduces gated cross-action conflicts", report["blockers"])


if __name__ == "__main__":
    unittest.main()
