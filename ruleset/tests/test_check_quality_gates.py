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


if __name__ == "__main__":
    unittest.main()
