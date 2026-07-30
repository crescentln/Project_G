from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
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


class SecureFetchTests(unittest.TestCase):
    def setUp(self) -> None:
        build_rulesets.FETCH_MEMO.clear()
        build_rulesets.FETCH_EVENTS.clear()
        build_rulesets.FETCH_ATTEMPTS.clear()

    def test_live_mirror_is_tried_before_any_cached_primary(self) -> None:
        calls: list[tuple[str, bool]] = []

        def fake_fetch(url: str, *_args: object, **kwargs: object):
            calls.append((url, bool(kwargs.get("allow_cache_fallback", True))))
            if "primary" in url:
                raise build_rulesets.BuildError("primary unavailable")
            return b"mirror", False

        source = {
            "url": "https://primary.example/source",
            "fallback_urls": ["https://mirror.example/source"],
            "allowed_hosts": ["primary.example", "mirror.example"],
        }
        with mock.patch.object(build_rulesets, "fetch_bytes", side_effect=fake_fetch):
            data, used_cache, chosen = build_rulesets.fetch_source_bytes(
                source,
                pathlib.Path("unused"),
                offline=False,
            )

        self.assertEqual(data, b"mirror")
        self.assertFalse(used_cache)
        self.assertEqual(chosen, "https://mirror.example/source")
        self.assertEqual(
            calls,
            [
                ("https://primary.example/source", False),
                ("https://mirror.example/source", False),
            ],
        )

    def _write_cache(
        self,
        cache_dir: pathlib.Path,
        url: str,
        data: bytes,
        *,
        fetched_at: dt.datetime,
        recorded_digest: str | None = None,
    ) -> None:
        cache_file, meta_file = build_rulesets.cache_paths(url, cache_dir)
        cache_file.write_bytes(data)
        meta_file.write_text(
            json.dumps(
                {
                    "url": url,
                    "fetched_at_utc": fetched_at.isoformat(),
                    "content_sha256": recorded_digest or hashlib.sha256(data).hexdigest(),
                    "byte_count": len(data),
                    "etag": "",
                    "last_modified": "",
                    "final_url": url,
                }
            ),
            encoding="utf-8",
        )

    def test_stale_cache_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = pathlib.Path(tmp)
            url = "https://cache.example/source"
            self._write_cache(
                cache_dir,
                url,
                b"cached",
                fetched_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=25),
            )
            with self.assertRaisesRegex(build_rulesets.BuildError, "cache expired"):
                build_rulesets.load_validated_cache(
                    url,
                    cache_dir,
                    max_bytes=1024,
                    cache_ttl_hours=24,
                    mode="fallback_cache",
                )

    def test_cache_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = pathlib.Path(tmp)
            url = "https://cache.example/source"
            self._write_cache(
                cache_dir,
                url,
                b"cached",
                fetched_at=dt.datetime.now(dt.timezone.utc),
                recorded_digest="0" * 64,
            )
            with self.assertRaisesRegex(build_rulesets.BuildError, "digest mismatch"):
                build_rulesets.load_validated_cache(
                    url,
                    cache_dir,
                    max_bytes=1024,
                    cache_ttl_hours=24,
                    mode="fallback_cache",
                )

    def test_response_larger_than_limit_is_rejected(self) -> None:
        class FakeResponse:
            headers = {"Content-Length": "11"}

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def geturl(self) -> str:
                return "https://large.example/source"

            def read(self, _size: int) -> bytes:
                return b"x" * 11

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                build_rulesets.urllib.request,
                "urlopen",
                return_value=FakeResponse(),
            ):
                with self.assertRaisesRegex(build_rulesets.BuildError, "max_bytes"):
                    build_rulesets.fetch_bytes(
                        "https://large.example/source",
                        pathlib.Path(tmp),
                        allow_cache_fallback=False,
                        max_bytes=10,
                        allowed_hosts={"large.example"},
                    )

    def test_invalid_utf8_is_rejected(self) -> None:
        with self.assertRaisesRegex(build_rulesets.BuildError, "valid UTF-8"):
            build_rulesets.decode_text(b"\xff\xfe\xfa")

    def test_http_304_is_live_revalidation_not_fallback_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = pathlib.Path(tmp)
            url = "https://cache.example/source"
            self._write_cache(
                cache_dir,
                url,
                b"cached",
                fetched_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30),
            )
            not_modified = build_rulesets.urllib.error.HTTPError(
                url,
                304,
                "Not Modified",
                {},
                None,
            )
            self.addCleanup(not_modified.close)
            with mock.patch.object(
                build_rulesets.urllib.request,
                "urlopen",
                side_effect=not_modified,
            ):
                data, used_cache = build_rulesets.fetch_bytes(
                    url,
                    cache_dir,
                    allow_cache_fallback=False,
                    max_bytes=1024,
                    allowed_hosts={"cache.example"},
                )

        self.assertEqual(data, b"cached")
        self.assertFalse(used_cache)
        self.assertEqual(build_rulesets.FETCH_EVENTS[url]["mode"], "not_modified")
        report = build_rulesets.build_fetch_report()
        self.assertEqual(report["network_success_count"], 1)
        self.assertEqual(report["fallback_cache_count"], 0)


class SourceControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_registry = build_rulesets.SOURCE_REGISTRY
        build_rulesets.SOURCE_REGISTRY = {
            "authority_profiles": {
                "test": {
                    "trust_tier": "official",
                    "license": "declared",
                    "owner": "authority",
                    "revision_strategy": "locked",
                    "allowed_hosts": ["allowed.example"],
                    "max_bytes": 100,
                    "max_files": 10,
                    "max_include_depth": 5,
                    "max_uncompressed_bytes": 1000,
                    "freshness_ttl_hours": 24,
                    "expected_parser": "*",
                    "accepted_line_ratio": 0.25,
                    "critical": True,
                    "no_cache_publish": True,
                    "require_lock": True,
                    "allowed_rule_types": ["DOMAIN", "DOMAIN-SUFFIX"],
                }
            }
        }

    def tearDown(self) -> None:
        build_rulesets.SOURCE_REGISTRY = self.previous_registry

    def test_source_cannot_expand_authority_hosts(self) -> None:
        with self.assertRaisesRegex(build_rulesets.BuildError, "expand allowed_hosts"):
            build_rulesets.source_controls(
                {
                    "type": "domain_lines",
                    "authority": "test",
                    "allowed_hosts": ["evil.example"],
                }
            )

    def test_source_cannot_disable_protective_profile_flags(self) -> None:
        with self.assertRaisesRegex(build_rulesets.BuildError, "disable no_cache_publish"):
            build_rulesets.source_controls(
                {
                    "type": "domain_lines",
                    "authority": "test",
                    "no_cache_publish": False,
                }
            )

    def test_source_can_only_tighten_limits_and_rule_types(self) -> None:
        controls = build_rulesets.source_controls(
            {
                "type": "domain_lines",
                "authority": "test",
                "max_bytes": 50,
                "freshness_ttl_hours": 12,
                "accepted_line_ratio": 0.5,
                "allowed_rule_types": ["DOMAIN"],
                "expected_parser": "domain_lines",
            }
        )
        self.assertEqual(controls["max_bytes"], 50)
        self.assertEqual(controls["freshness_ttl_hours"], 12)
        self.assertEqual(controls["accepted_line_ratio"], 0.5)
        self.assertEqual(controls["allowed_rule_types"], ["DOMAIN"])
        with self.assertRaisesRegex(build_rulesets.BuildError, "cannot relax max_bytes"):
            build_rulesets.source_controls(
                {
                    "type": "domain_lines",
                    "authority": "test",
                    "max_bytes": 101,
                }
            )


class V2FlyArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        build_rulesets.V2FLY_ARCHIVE_MEMO.clear()

    @staticmethod
    def archive_bytes(entries: list[tuple[str, bytes]]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, payload in entries:
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return buffer.getvalue()

    @staticmethod
    def controls() -> dict[str, object]:
        return {
            "allowed_hosts": ["codeload.github.com"],
            "max_bytes": 1024,
            "max_files": 100,
            "max_uncompressed_bytes": 4096,
            "freshness_ttl_hours": 24,
        }

    def test_nested_tests_data_path_cannot_replace_canonical_file(self) -> None:
        payload = self.archive_bytes(
            [
                ("repo/data/example", b"canonical"),
                ("repo/tests/data/example", b"malicious"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            build_rulesets,
            "fetch_source_bytes",
            return_value=(payload, False, "https://codeload.github.com/archive"),
        ):
            files, _used_cache, metadata = build_rulesets.load_v2fly_archive(
                {
                    "resolved_revision": "1" * 40,
                    "requested_ref": "master",
                    "archive_urls": ["https://codeload.github.com/archive"],
                },
                pathlib.Path(tmp),
                False,
                self.controls(),
            )
        self.assertEqual(files, {"example": b"canonical"})
        self.assertEqual(metadata["archive_root"], "repo")

    def test_duplicate_canonical_data_member_is_rejected(self) -> None:
        payload = self.archive_bytes(
            [
                ("repo/data/example", b"first"),
                ("repo/data/example", b"second"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            build_rulesets,
            "fetch_source_bytes",
            return_value=(payload, False, "https://codeload.github.com/archive"),
        ):
            with self.assertRaisesRegex(build_rulesets.BuildError, "duplicate canonical"):
                build_rulesets.load_v2fly_archive(
                    {
                        "resolved_revision": "2" * 40,
                        "requested_ref": "master",
                        "archive_urls": ["https://codeload.github.com/archive"],
                    },
                    pathlib.Path(tmp),
                    False,
                    self.controls(),
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

    def test_cidr_parent_shadow_is_gated(self) -> None:
        conflicts = build_rulesets.detect_rule_conflicts(
            rules_by_category={
                "direct": ["IP-CIDR,10.0.0.0/8,no-resolve"],
                "proxy": ["IP-CIDR,10.2.0.0/16,no-resolve"],
            },
            category_actions={"direct": "DIRECT", "proxy": "PROXY"},
            category_priorities={"direct": 200, "proxy": 300},
            ignored_conflict_sets=set(),
            ignored_rule_conflicts={},
        )
        cidr_conflicts = [
            item for item in conflicts if item["type"] == "parent_cidr_direct_proxy_conflict"
        ]
        self.assertEqual(len(cidr_conflicts), 1)
        self.assertTrue(cidr_conflicts[0]["gated"])

    def test_rule_scoped_waiver_remains_visible(self) -> None:
        categories = frozenset({"direct", "proxy"})
        conflicts = build_rulesets.detect_rule_conflicts(
            rules_by_category={
                "direct": ["DOMAIN,example.com"],
                "proxy": ["DOMAIN,example.com"],
            },
            category_actions={"direct": "DIRECT", "proxy": "PROXY"},
            category_priorities={"direct": 10, "proxy": 20},
            ignored_conflict_sets={},
            ignored_rule_conflicts={
                "DOMAIN,example.com": {
                    categories: {
                        "scope": "rule",
                        "reason": "tested exception",
                        "owner": "test",
                        "expires_at": "2099-01-01",
                    }
                }
            },
        )
        self.assertEqual(len(conflicts), 1)
        self.assertTrue(conflicts[0]["waived"])
        self.assertTrue(conflicts[0]["original_gated"])
        self.assertFalse(conflicts[0]["gated"])
        self.assertEqual(conflicts[0]["waiver"]["scope"], "rule")

    def test_cross_action_category_waiver_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            build_rulesets.BuildError,
            "cross-action conflicts require rule-scoped",
        ):
            build_rulesets.load_ignored_conflict_sets(
                {
                    "ignore_conflicts": [
                        {
                            "categories": ["direct", "proxy"],
                            "reason": "too broad",
                            "owner": "test",
                            "expires_at": "2099-01-01",
                        }
                    ]
                },
                {
                    "direct": {"action": "DIRECT"},
                    "proxy": {"action": "PROXY"},
                },
            )


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
