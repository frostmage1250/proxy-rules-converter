from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_rules import (  # noqa: E402
    ConversionError,
    DomainRule,
    duplicate_counts,
    is_externally_managed_output,
    parse_domain_text,
    parse_ipcidr_text,
    parse_mixed_ipcidr_text,
    render_rules,
    render_shadowrocket_ip_rules,
    rule_covers_domain,
)


class ConverterTests(unittest.TestCase):
    def test_domain_conversion_preserves_order_and_count(self) -> None:
        rules = parse_domain_text(
            "z.example\n+.example.com\na.example\n+.example.com\n", "test"
        )
        self.assertEqual(
            render_rules(rules, "shadowrocket"),
            "z.example\n.example.com\na.example\n.example.com\n",
        )

    def test_distinct_shadowrocket_projection_collision_fails(self) -> None:
        with self.assertRaises(ConversionError):
            render_rules(
                [
                    DomainRule("suffix", "example.com"),
                    DomainRule("subdomain_suffix", "example.com"),
                ],
                "shadowrocket",
            )

    def test_noncanonical_domain_fails_instead_of_being_rewritten(self) -> None:
        for value in ("Example.com", "example.com.", " example.com"):
            with self.subTest(value=value), self.assertRaises(ConversionError):
                parse_domain_text(value + "\n", "test")

    def test_unknown_domain_syntax_fails(self) -> None:
        for value in ("*.example.com", "DOMAIN,example.com"):
            with self.subTest(value=value), self.assertRaises(ConversionError):
                parse_domain_text(value + "\n", "test")

    def test_ip_conversion_preserves_order_and_count(self) -> None:
        entries, duplicates = parse_mixed_ipcidr_text(
            "2001:db8::/32\n1.1.1.0/24\n", "test"
        )
        self.assertEqual(duplicates, 0)
        self.assertEqual(
            render_shadowrocket_ip_rules(entries),
            "IP-CIDR6,2001:db8::/32\nIP-CIDR,1.1.1.0/24\n",
        )

    def test_ip_duplicates_are_reported_but_not_removed(self) -> None:
        entries, duplicates = parse_ipcidr_text(
            "1.1.1.0/24\n1.1.1.0/24\n", "test", 4
        )
        self.assertEqual(entries, ["1.1.1.0/24", "1.1.1.0/24"])
        self.assertEqual(duplicates, 1)

    def test_noncanonical_cidr_fails_instead_of_being_rewritten(self) -> None:
        with self.assertRaises(ConversionError):
            parse_ipcidr_text("1.1.1.1/24\n", "test", 4)

    def test_wrong_ip_family_fails(self) -> None:
        with self.assertRaises(ConversionError):
            parse_ipcidr_text("2001:db8::/32\n", "test", 4)

    def test_bett_scope_is_explicit(self) -> None:
        config = json.loads(
            (ROOT / "config" / "sources.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(config), {"bett"})
        self.assertNotIn("geolocation-cn", config["bett"]["shadowrocket_domains"])

    def test_only_pcdn_bilibili_file_is_static(self) -> None:
        from convert_rules import STATIC_OUTPUTS

        self.assertEqual(
            STATIC_OUTPUTS, {"dist/shadowrocket/bilibili-pcdn.list"}
        )

    def test_geolocation_outputs_are_externally_managed(self) -> None:
        self.assertTrue(
            is_externally_managed_output(
                ROOT / "dist" / "shadowrocket" / "geolocation-cn.domain-set"
            )
        )

    def test_suffix_coverage(self) -> None:
        rule = DomainRule("suffix", "example.com")
        self.assertTrue(rule_covers_domain(rule, "example.com"))
        self.assertTrue(rule_covers_domain(rule, "cdn.example.com"))
        self.assertFalse(rule_covers_domain(rule, "notexample.com"))

    def test_duplicate_counts(self) -> None:
        self.assertEqual(
            duplicate_counts(["a", "a", "b", "c", "c", "c"]),
            {"a": 2, "c": 3},
        )


if __name__ == "__main__":
    unittest.main()
