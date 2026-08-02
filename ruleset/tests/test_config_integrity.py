from __future__ import annotations

import json
import hashlib
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
        self.contracts = read_json("config/category_contracts.json")
        self.registry = read_json("config/source_registry.json")
        self.smoke = read_json("config/smoke_probes.json")
        self.protected_roots = read_json("config/protected_domain_roots.json")

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
            overlay = category.get("manual_overlay_path")
            if overlay:
                references.add(str(overlay))
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
            urls = {
                str(source.get("url", ""))
                for source in categories[category_id].get("sources", [])
            }
            self.assertEqual(urls & forbidden, set())

    def test_direct_is_derived_from_explicit_components(self) -> None:
        categories = {row["id"]: row for row in self.sources["categories"]}
        direct = categories["direct"]
        self.assertNotIn("sources", direct)
        self.assertEqual(
            direct["aggregate_of"],
            self.contracts["categories"]["direct"]["aggregate_of"],
        )
        self.assertEqual(direct["manual_overlay_path"], "manual/categories/direct.txt")
        self.assertEqual(
            self.contracts["categories"]["direct"]["required_action"],
            "DIRECT",
        )
        for component in direct["aggregate_of"]:
            self.assertEqual(self.policy["categories"][component]["action"], "DIRECT")

    def test_wechat_direct_exception_precedes_reject(self) -> None:
        categories = self.policy["categories"]
        self.assertEqual(categories["wechat"]["action"], "DIRECT")
        self.assertLess(categories["wechat"]["priority"], categories["reject"]["priority"])

    def test_download_contract_requires_direct(self) -> None:
        self.assertEqual(
            self.contracts["categories"]["download"]["required_action"],
            "DIRECT",
        )
        self.assertEqual(self.policy["categories"]["download"]["action"], "DIRECT")
        self.assertEqual(
            self.contracts["categories"]["download"]["must_be_disjoint_from"],
            ["games", "games_cn"],
        )

    def test_approved_drift_targets_known_category_with_bounded_counts(self) -> None:
        approval = read_json("config/approved_count_drift.json")
        source_ids = {row["id"] for row in self.sources["categories"]}
        self.assertRegex(str(approval["baseline_policy_sha256"]), r"^[0-9a-f]{64}$")
        for item in approval["approvals"]:
            self.assertIn(item["category"], source_ids)
            self.assertLessEqual(int(item["after_min"]), int(item["after_max"]))
            self.assertTrue(str(item["reason"]).strip())

    def test_all_categories_have_positive_smoke_contracts(self) -> None:
        source_ids = {row["id"] for row in self.sources["categories"]}
        self.assertEqual(set(self.smoke["require_non_empty"]), source_ids)
        self.assertEqual(set(self.smoke["expect_rules"]), source_ids)
        for category_id, rules in self.smoke["expect_rules"].items():
            self.assertTrue(rules, category_id)

    def test_source_authorities_are_enforced_by_registry(self) -> None:
        profiles = set(self.registry["authority_profiles"])
        observed = {
            str(source["authority"])
            for category in self.sources["categories"]
            for source in category.get("sources", [])
        }
        self.assertEqual(observed - profiles, set())
        for authority, profile in self.registry["authority_profiles"].items():
            for field in (
                "trust_tier",
                "license",
                "owner",
                "allowed_hosts",
                "revision_strategy",
                "max_bytes",
                "max_files",
                "max_include_depth",
                "freshness_ttl_hours",
                "expected_parser",
                "accepted_line_ratio",
                "critical",
                "no_cache_publish",
            ):
                self.assertIn(field, profile, f"{authority}/{field}")

    def test_conflict_overrides_are_owned_and_expiring(self) -> None:
        for item in self.sources["ignore_conflicts"]:
            self.assertGreaterEqual(len(item["categories"]), 2)
            self.assertTrue(str(item["reason"]).strip())
            self.assertTrue(str(item["owner"]).strip())
            self.assertRegex(str(item["expires_at"]), r"^\d{4}-\d{2}-\d{2}$")
            action_families = {
                (
                    "REJECT"
                    if str(self.policy["categories"][category]["action"]).startswith(
                        "REJECT"
                    )
                    else str(self.policy["categories"][category]["action"])
                )
                for category in item["categories"]
            }
            self.assertEqual(
                len(action_families),
                1,
                "cross-action waivers must be rule-scoped",
            )
        for item in self.sources["ignore_conflicts_by_rule"]:
            self.assertTrue(str(item["reason"]).strip())
            self.assertTrue(str(item["owner"]).strip())
            self.assertRegex(str(item["expires_at"]), r"^\d{4}-\d{2}-\d{2}$")

    def test_manual_only_categories_cannot_auto_promote(self) -> None:
        for category_id in self.contracts["manual_only_categories"]:
            self.assertEqual(
                self.contracts["categories"][category_id]["auto_promotion_policy"],
                "manual",
            )

    def test_protected_domain_roots_are_sorted_unique_and_disjoint(self) -> None:
        self.assertEqual(
            self.protected_roots["schema"],
            "project-g-protected-domain-roots-v1",
        )
        observed: list[set[str]] = []
        for field in ("public_suffixes", "multi_tenant_roots"):
            values = self.protected_roots[field]
            self.assertEqual(values, sorted(values))
            self.assertEqual(len(values), len(set(values)))
            self.assertTrue(all("." in value for value in values))
            observed.append(set(values))
        self.assertEqual(observed[0] & observed[1], set())
        metadata = self.protected_roots["public_suffix_list"]
        self.assertEqual(metadata["source_repository"], "publicsuffix/list")
        self.assertRegex(metadata["source_commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(metadata["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            metadata["source_url"],
            "https://raw.githubusercontent.com/publicsuffix/list/"
            f"{metadata['source_commit']}/public_suffix_list.dat",
        )
        psl_path = RULESET_ROOT.parent / metadata["path"]
        self.assertEqual(
            hashlib.sha256(psl_path.read_bytes()).hexdigest(), metadata["sha256"]
        )
        psl_text = psl_path.read_text(encoding="utf-8")
        self.assertIn("// ===BEGIN ICANN DOMAINS===", psl_text)
        self.assertIn("// ===END ICANN DOMAINS===", psl_text)
        self.assertIn("// ===BEGIN PRIVATE DOMAINS===", psl_text)
        self.assertIn("// ===END PRIVATE DOMAINS===", psl_text)


if __name__ == "__main__":
    unittest.main()
