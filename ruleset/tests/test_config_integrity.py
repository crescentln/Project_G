from __future__ import annotations

import json
import pathlib
import unittest


RULESET_ROOT = pathlib.Path(__file__).resolve().parents[1]


def read_json(relative: str) -> dict[str, object]:
    return json.loads((RULESET_ROOT / relative).read_text(encoding="utf-8"))


class ConfigIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = read_json("config/sources.json")
        self.policy = read_json("config/policy_map.json")
        self.minimums = read_json("config/min_rules.json")

    def test_category_sets_match_policy_and_minimums(self) -> None:
        source_ids = {row["id"] for row in self.sources["categories"]}
        policy_ids = set(self.policy["categories"])
        minimum_ids = set(self.minimums["minimum_rule_counts"])
        self.assertEqual(source_ids, policy_ids)
        self.assertEqual(source_ids, minimum_ids)

    def test_every_manual_rule_file_is_referenced(self) -> None:
        references: set[str] = set()
        for category in self.sources["categories"]:
            for field in ("allow_rules_path", "exclude_rules_path"):
                value = category.get(field)
                if value:
                    references.add(str(value))
            for source in category.get("sources", []):
                if source.get("type") == "local_domain":
                    references.add(str(source["path"]))

        manual_files = {
            path.relative_to(RULESET_ROOT).as_posix()
            for path in (RULESET_ROOT / "manual").rglob("*.txt")
        }
        self.assertEqual(manual_files - references, set())

    def test_global_shared_cloud_ranges_are_not_direct_sources(self) -> None:
        forbidden = {
            "https://www.cloudflare.com/ips-v4",
            "https://www.cloudflare.com/ips-v6",
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            "https://www.gstatic.com/ipranges/cloud.json",
            "https://api.fastly.com/public-ip-list",
        }
        categories = {row["id"]: row for row in self.sources["categories"]}
        for category_id in ("direct", "cdn"):
            urls = {str(source.get("url", "")) for source in categories[category_id]["sources"]}
            self.assertEqual(urls & forbidden, set())

    def test_wechat_direct_exception_precedes_reject(self) -> None:
        categories = self.policy["categories"]
        self.assertEqual(categories["wechat"]["action"], "DIRECT")
        self.assertLess(categories["wechat"]["priority"], categories["reject"]["priority"])

    def test_approved_drift_targets_known_category_with_bounded_counts(self) -> None:
        approval = read_json("config/approved_count_drift.json")
        source_ids = {row["id"] for row in self.sources["categories"]}
        self.assertRegex(str(approval["baseline_policy_sha256"]), r"^[0-9a-f]{64}$")
        for item in approval["approvals"]:
            self.assertIn(item["category"], source_ids)
            self.assertLessEqual(int(item["after_min"]), int(item["after_max"]))
            self.assertTrue(str(item["reason"]).strip())


if __name__ == "__main__":
    unittest.main()
