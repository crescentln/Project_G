from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "build_rulesets.py"
SPEC = importlib.util.spec_from_file_location("build_rulesets", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
build_rulesets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build_rulesets
SPEC.loader.exec_module(build_rulesets)


class AdblockParserTests(unittest.TestCase):
    def test_keeps_only_dns_safe_whole_domain_rules(self) -> None:
        text = """
        ||safe.example^
        blocked.example
        0.0.0.0 hosts.example
        ||binance.com^$popup,domain=example.org
        ||bing.com^*/glinkping.aspx$ping,xmlhttprequest
        ||hotstar.com^*/midroll?
        .kijiji.ca/r/
        """

        rules = build_rulesets.parse_adblock_text(text)

        self.assertEqual(
            rules,
            {
                "DOMAIN-SUFFIX,safe.example",
                "DOMAIN-SUFFIX,blocked.example",
                "DOMAIN,hosts.example",
            },
        )

    def test_pure_exception_removes_matching_block(self) -> None:
        text = """
        ||allowed.example^
        @@||allowed.example^
        ||still-blocked.example^
        @@||contextual.example^$domain=example.org
        """

        self.assertEqual(
            build_rulesets.parse_adblock_text(text),
            {"DOMAIN-SUFFIX,still-blocked.example"},
        )


class V2FlyIncludeSelectorTests(unittest.TestCase):
    def _parse(self, root: str, files: dict[str, str]) -> set[str]:
        base = "https://example.invalid/data"

        def fake_fetch(source: dict[str, object], *_args: object, **_kwargs: object):
            url = str(source["url"])
            name = url.rsplit("/", 1)[-1]
            return files[name].encode(), False, url

        with mock.patch.object(build_rulesets, "fetch_source_bytes", side_effect=fake_fetch):
            rules, _used_cache, _source = build_rulesets.parse_v2fly_dlc_source(
                [f"{base}/{root}"],
                cache_dir=pathlib.Path("unused"),
                offline=False,
                include_attrs=set(),
                exclude_attrs={"@ads"},
                exclude_includes=set(),
            )
        return rules

    def test_negative_include_selector_filters_nested_rules(self) -> None:
        files = {
            "root": "include:child @-!cn\n",
            "child": "include:grandchild\ndouyin.example\ntiktok.example @!cn\n",
            "grandchild": "coze.example @!cn\ntracker.example @ads\n",
        }

        self.assertEqual(
            self._parse("root", files),
            {"DOMAIN-SUFFIX,douyin.example"},
        )

    def test_positive_include_selector_requires_attribute(self) -> None:
        files = {
            "root": "include:child @cn\n",
            "child": "china.example @cn\nglobal.example\n",
        }

        self.assertEqual(
            self._parse("root", files),
            {"DOMAIN-SUFFIX,china.example"},
        )


class ConflictDetectionTests(unittest.TestCase):
    def test_reject_conflict_is_not_silently_discarded(self) -> None:
        conflicts = build_rulesets.detect_rule_conflicts(
            rules_by_category={
                "reject": ["DOMAIN-SUFFIX,binance.com"],
                "crypto": ["DOMAIN-SUFFIX,binance.com"],
                "global": ["DOMAIN-SUFFIX,binance.com"],
            },
            category_actions={"reject": "REJECT", "crypto": "PROXY", "global": "PROXY"},
            category_priorities={"reject": 100, "crypto": 336, "global": 900},
            ignored_conflict_sets=set(),
            ignored_rule_conflicts={},
        )

        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["categories"], ["crypto", "reject"])
        self.assertEqual(
            conflicts[0]["type"],
            "expected_reject_override_proxy_reject_conflict",
        )
        self.assertFalse(conflicts[0]["gated"])

    def test_parent_suffix_shadow_is_gated(self) -> None:
        conflicts = build_rulesets.detect_rule_conflicts(
            rules_by_category={
                "direct": ["DOMAIN-SUFFIX,amazonaws.com"],
                "github": ["DOMAIN,github-cloud.s3.amazonaws.com"],
            },
            category_actions={"direct": "DIRECT", "github": "PROXY"},
            category_priorities={"direct": 205, "github": 325},
            ignored_conflict_sets=set(),
            ignored_rule_conflicts={},
        )

        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["covering_rule"], "DOMAIN-SUFFIX,amazonaws.com")
        self.assertEqual(conflicts[0]["type"], "parent_direct_proxy_conflict")
        self.assertTrue(conflicts[0]["gated"])

    def test_specific_reject_inside_later_direct_parent_is_informational(self) -> None:
        conflicts = build_rulesets.detect_rule_conflicts(
            rules_by_category={
                "reject": ["DOMAIN,beacon.qq.com"],
                "direct": ["DOMAIN-SUFFIX,qq.com"],
            },
            category_actions={"reject": "REJECT", "direct": "DIRECT"},
            category_priorities={"reject": 100, "direct": 205},
            ignored_conflict_sets=set(),
            ignored_rule_conflicts={},
        )

        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["type"], "specific_override_direct_reject_conflict")
        self.assertFalse(conflicts[0]["gated"])

    def test_earlier_reject_parent_is_reported_but_not_gated(self) -> None:
        conflicts = build_rulesets.detect_rule_conflicts(
            rules_by_category={
                "reject": ["DOMAIN-SUFFIX,tracker.example"],
                "direct": ["DOMAIN,api.tracker.example"],
            },
            category_actions={"reject": "REJECT", "direct": "DIRECT"},
            category_priorities={"reject": 100, "direct": 205},
            ignored_conflict_sets=set(),
            ignored_rule_conflicts={},
        )

        self.assertEqual(len(conflicts), 1)
        self.assertEqual(
            conflicts[0]["type"],
            "expected_reject_override_direct_reject_conflict",
        )
        self.assertFalse(conflicts[0]["gated"])


class DistTargetSafetyTests(unittest.TestCase):
    def test_temporary_dist_target_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "dist"
            self.assertEqual(build_rulesets.validate_dist_target(target), target.resolve())

    def test_arbitrary_non_temp_target_is_rejected(self) -> None:
        target = pathlib.Path.home() / "Documents" / "do-not-delete"
        with self.assertRaises(build_rulesets.BuildError):
            build_rulesets.validate_dist_target(target)

    def test_nonempty_unmarked_temporary_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "dist"
            target.mkdir()
            (target / "user-data.txt").write_text("preserve me", encoding="utf-8")
            with self.assertRaises(build_rulesets.BuildError):
                build_rulesets.validate_dist_target(target)

    def test_marked_temporary_dist_target_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "dist"
            target.mkdir()
            (target / "index.json").write_text("{}", encoding="utf-8")
            (target / "policy_reference.json").write_text("{}", encoding="utf-8")
            self.assertEqual(build_rulesets.validate_dist_target(target), target.resolve())


if __name__ == "__main__":
    unittest.main()
