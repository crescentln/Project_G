import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "apply_radar_decision.py"
SPEC = importlib.util.spec_from_file_location("apply_radar_decision", SCRIPT)
assert SPEC and SPEC.loader
DECISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECISION)


class RadarDecisionTests(unittest.TestCase):
    def test_active_head_advance_blocks_promotion(self) -> None:
        manifest = {
            "changed": True,
            "risk_level": "low",
            "auto_promotion_eligible": True,
            "requires_review": False,
            "risk_markers": [],
        }
        radar = {
            "candidate_only": True,
            "high_impact_quorum": 2,
            "repositories": [
                {
                    "repository": "v2fly/domain-list-community",
                    "role": "active-locked-source",
                    "candidate_only": False,
                    "locked_revision": "1" * 40,
                    "resolved_revision": "2" * 40,
                },
                {
                    "repository": "independent/example",
                    "role": "independent-radar",
                    "candidate_only": True,
                    "changed": True,
                },
            ],
            "v2fly_tree": {
                "head_vs_lock": {"head_advanced_after_lock": True},
                "unbuilt_head_files": ["data/new"],
            },
        }
        updated, decision = DECISION.apply_decision(manifest, radar)
        self.assertEqual(updated["risk_level"], "high")
        self.assertFalse(updated["auto_promotion_eligible"])
        self.assertTrue(updated["source_head_advanced_after_lock"])
        self.assertTrue(decision["promotion_blocked"])
        self.assertEqual(decision["unbuilt_head_files"], ["data/new"])

    def test_independent_sources_must_remain_candidate_only(self) -> None:
        with self.assertRaisesRegex(
            DECISION.RadarDecisionError,
            "independent radar source is not candidate-only",
        ):
            DECISION.apply_decision(
                {"changed": False, "risk_markers": []},
                {
                    "candidate_only": True,
                    "high_impact_quorum": 2,
                    "repositories": [
                        {
                            "repository": "independent/example",
                            "role": "independent-radar",
                            "candidate_only": False,
                        }
                    ],
                    "v2fly_tree": {"head_vs_lock": {}},
                },
            )


if __name__ == "__main__":
    unittest.main()
