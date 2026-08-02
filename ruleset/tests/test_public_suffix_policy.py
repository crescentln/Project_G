from __future__ import annotations

import json
import pathlib
import unittest

from ruleset.scripts.public_suffix_policy import load_public_suffix_database


class PublicSuffixPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository_root = pathlib.Path(__file__).resolve().parents[2]
        config_path = (
            cls.repository_root
            / "ruleset"
            / "config"
            / "protected_domain_roots.json"
        )
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        cls.database = load_public_suffix_database(
            payload["public_suffix_list"], cls.repository_root
        )

    def test_pinned_snapshot_is_complete_and_classified(self) -> None:
        self.assertEqual(
            self.database.sha256,
            "fe6adc7fb8014f57d28d69b18d0aa3e581efb432544922e12131a5d4a87bd954",
        )
        self.assertGreater(self.database.icann_rule_count, 5_000)
        self.assertGreater(self.database.private_rule_count, 2_000)

    def test_private_suffixes_are_recognized(self) -> None:
        for domain, suffix in (
            ("tenant.duckdns.org", "duckdns.org"),
            ("project.githubusercontent.com", "githubusercontent.com"),
            ("foo.uk.com", "uk.com"),
        ):
            with self.subTest(domain=domain):
                match = self.database.match(domain)
                self.assertEqual(match.section, "private")
                self.assertEqual(match.public_suffix, suffix)

    def test_icann_registrable_domain_is_recognized(self) -> None:
        match = self.database.match("foo.blog.br")
        self.assertEqual(match.section, "icann")
        self.assertEqual(match.public_suffix, "blog.br")
        self.assertEqual(match.registrable_domain, "foo.blog.br")

    def test_wildcard_and_exception_rules_follow_psl_algorithm(self) -> None:
        wildcard = self.database.match("a.b.ck")
        self.assertEqual(wildcard.rule, "*.ck")
        self.assertEqual(wildcard.public_suffix, "b.ck")
        self.assertEqual(wildcard.registrable_domain, "a.b.ck")

        exception = self.database.match("www.ck")
        self.assertEqual(exception.rule, "!www.ck")
        self.assertEqual(exception.public_suffix, "ck")
        self.assertEqual(exception.registrable_domain, "www.ck")


if __name__ == "__main__":
    unittest.main()
