from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "generate_recommended_templates.py"
SPEC = importlib.util.spec_from_file_location("generate_recommended_templates", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
templates = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = templates
SPEC.loader.exec_module(templates)


class RecommendedTemplateTests(unittest.TestCase):
    def test_client_specific_reject_no_drop_mapping(self) -> None:
        self.assertEqual(
            templates.normalize_policy("REJECT-NO-DROP", "PROXY", "surge"),
            "REJECT-NO-DROP",
        )
        self.assertEqual(
            templates.normalize_policy("REJECT-NO-DROP", "PROXY", "openclash"),
            "REJECT",
        )
        self.assertEqual(
            templates.normalize_policy("REJECT-NO-DROP", "PROXY", "stash"),
            "REJECT",
        )

    def test_merged_direct_replaces_redundant_direct_categories(self) -> None:
        rows = [
            {"id": "wechat", "action": "DIRECT", "priority": 90},
            {"id": "reject", "action": "REJECT", "priority": 100},
            {"id": "direct", "action": "DIRECT", "priority": 205},
            {"id": "domestic", "action": "DIRECT", "priority": 210},
            {"id": "cdn", "action": "DIRECT", "priority": 250},
            {"id": "tiktok", "action": "PROXY", "priority": 341},
        ]

        simplified = templates.simplify_recommended_categories(rows)

        self.assertEqual(
            [row["id"] for row in simplified],
            ["wechat", "reject", "direct", "tiktok"],
        )


if __name__ == "__main__":
    unittest.main()
