from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "check_quality_gates.py"
SPEC = importlib.util.spec_from_file_location("check_quality_gates", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
gates = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gates
SPEC.loader.exec_module(gates)


class ApprovedDriftTests(unittest.TestCase):
    def test_explicit_zero_conflict_counts_do_not_fall_back_to_informationals(self) -> None:
        payload = {
            "cross_action_conflict_count": 0,
            "high_severity_conflict_count": 0,
            "conflicts": [
                {
                    "type": "specific_override_direct_reject_conflict",
                    "severity": "low",
                    "gated": False,
                }
            ],
        }
        self.assertEqual(gates.resolve_conflict_counts(payload), (0, 0))

    def test_matching_category_and_bounds_suppress_only_that_violation(self) -> None:
        changes, violations = gates.compute_count_drift(
            baseline_counts={"cdn": 1000, "direct": 1000},
            current_counts={"cdn": 200, "direct": 200},
            max_change_pct=20,
            min_abs_delta=50,
            min_baseline_rules=100,
            approved_drift={
                "cdn": {
                    "before": 1000,
                    "after_min": 190,
                    "after_max": 210,
                    "reason": "remove global shared cloud ranges",
                }
            },
        )

        self.assertEqual(len(changes), 2)
        self.assertEqual(len(violations), 1)
        self.assertIn("direct", violations[0])

    def test_changed_baseline_hash_deactivates_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            baseline = root / "baseline.json"
            approval = root / "approval.json"
            baseline.write_text('{"categories": []}\n', encoding="utf-8")
            approval.write_text(
                json.dumps(
                    {
                        "baseline_policy_sha256": "0" * 64,
                        "approvals": [
                            {
                                "category": "cdn",
                                "before": 1000,
                                "after_min": 100,
                                "after_max": 300,
                                "reason": "bounded migration",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(gates.read_approved_drift(approval, baseline), {})

    def test_exact_baseline_hash_activates_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            baseline = root / "baseline.json"
            approval = root / "approval.json"
            baseline_bytes = b'{"categories": []}\n'
            baseline.write_bytes(baseline_bytes)
            approval.write_text(
                json.dumps(
                    {
                        "baseline_policy_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
                        "approvals": [
                            {
                                "category": "cdn",
                                "before": 1000,
                                "after_min": 100,
                                "after_max": 300,
                                "reason": "bounded migration",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            loaded = gates.read_approved_drift(approval, baseline)
            self.assertEqual(loaded["cdn"]["before"], 1000)
            self.assertEqual(loaded["cdn"]["after_min"], 100)
            self.assertEqual(loaded["cdn"]["after_max"], 300)

    def test_small_category_removal_is_always_rejected(self) -> None:
        _changes, violations = gates.compute_count_drift(
            baseline_counts={"small": 1},
            current_counts={},
            max_change_pct=100,
            min_abs_delta=1000,
            min_baseline_rules=1000,
        )
        self.assertEqual(
            violations,
            ["category removed from current output: small (baseline=1)"],
        )


class CandidateManifestTests(unittest.TestCase):
    def test_promotion_rejects_budget_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = pathlib.Path(temp_dir) / "candidate.json"
            path.write_text(
                json.dumps(
                    {
                        "semantic_digest": "a" * 64,
                        "changed": True,
                        "fallback_cache_count": 0,
                        "cache_blocked_source_ids": [],
                        "budget_exceeded": ["direct:max_add observed=2 allowed=1"],
                    }
                ),
                encoding="utf-8",
            )
            violations = gates.validate_candidate_manifest(
                path,
                require_promotable=True,
            )
        self.assertEqual(len(violations), 1)
        self.assertIn("exceeds category budgets", violations[0])

    def test_promotion_rejects_source_head_advanced_after_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = pathlib.Path(temp_dir) / "candidate.json"
            path.write_text(
                json.dumps(
                    {
                        "semantic_digest": "a" * 64,
                        "changed": True,
                        "fallback_cache_count": 0,
                        "cache_blocked_source_ids": [],
                        "budget_exceeded": [],
                        "source_head_advanced_after_lock": True,
                        "auto_promotion_eligible": False,
                    }
                ),
                encoding="utf-8",
            )
            violations = gates.validate_candidate_manifest(
                path,
                require_promotable=True,
            )
        self.assertEqual(len(violations), 1)
        self.assertIn("source head advanced", violations[0])


class ClientParityTests(unittest.TestCase):
    def test_gate_recomputes_client_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dist = pathlib.Path(temp_dir)
            for child in ("openclash", "surge", "stash"):
                (dist / child).mkdir()
            (dist / "openclash" / "sample.yaml").write_text(
                "payload:\n  - 'DOMAIN,example.com'\n  - 'DOMAIN-REGEX,^x'\n",
                encoding="utf-8",
            )
            (dist / "surge" / "sample.list").write_text(
                "DOMAIN,wrong.example\n",
                encoding="utf-8",
            )
            (dist / "stash" / "sample.list").write_text(
                "DOMAIN,example.com\nDOMAIN-REGEX,^x\n",
                encoding="utf-8",
            )
            parity = dist / "client_parity.json"
            parity.write_text(
                json.dumps(
                    {
                        "clients": {
                            "openclash_effective_rules": 2,
                            "surge_effective_rules": 1,
                            "surge_lost_rules": 1,
                            "stash_effective_rules": 2,
                        },
                        "categories": [
                            {
                                "category": "sample",
                                "openclash": {
                                    "effective_rule_count": 2,
                                    "lost_rule_count": 0,
                                    "lost_rule_types": {},
                                },
                                "surge": {
                                    "effective_rule_count": 1,
                                    "lost_rule_count": 1,
                                    "lost_rule_types": {"DOMAIN-REGEX": 1},
                                },
                                "stash": {
                                    "effective_rule_count": 2,
                                    "lost_rule_count": 0,
                                    "lost_rule_types": {},
                                },
                                "contract": {
                                    "surge": {
                                        "unsupported_rule_types": ["DOMAIN-REGEX"]
                                    }
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            violations = gates.validate_client_parity(parity, {"sample"})
        self.assertTrue(
            any("surge content violates compatibility contract" in item for item in violations)
        )


if __name__ == "__main__":
    unittest.main()
