from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_rules import (  # noqa: E402
    CLAUDE_SITE_REQUIRED_TYPED_RULES,
    ConversionError,
    DomainRule,
    duplicate_counts,
    extract_claude_site_rules,
    is_externally_managed_output,
    merge_claude_rules,
    parse_domain_text,
    parse_ipcidr_text,
    parse_mixed_ipcidr_text,
    render_classical_yaml,
    render_rules,
    rule_covers_domain,
)


class ConverterTests(unittest.TestCase):
    def test_domain_conversion_preserves_order_and_count(self) -> None:
        rules = parse_domain_text(
            "z.example\n+.example.com\na.example\n+.example.com\n", "test"
        )
        self.assertEqual(
            render_rules(rules, "mihomo"),
            "z.example\n+.example.com\na.example\n+.example.com\n",
        )

    def test_noncanonical_domain_fails_instead_of_being_rewritten(self) -> None:
        for value in ("Example.com", "example.com.", " example.com"):
            with self.subTest(value=value), self.assertRaises(ConversionError):
                parse_domain_text(value + "\n", "test")

    def test_unknown_domain_syntax_fails(self) -> None:
        for value in ("*.example.com", "DOMAIN,example.com"):
            with self.subTest(value=value), self.assertRaises(ConversionError):
                parse_domain_text(value + "\n", "test")

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

    def test_bett_sources_include_ai_mrs(self) -> None:
        config = json.loads(
            (ROOT / "config" / "sources.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(config["bett"]),
            {"geosite_base", "steam_cn_download_validation", "anthropic", "ai_mrs"},
        )


    def test_claude_site_extraction_keeps_keywords_and_excludes_ntp(self) -> None:
        typed = "\n".join(sorted(CLAUDE_SITE_REQUIRED_TYPED_RULES))
        html = (
            "<html><pre><code>"
            + typed
            + "</code></pre><pre><code>"
            + "geosite:anthropic\nkeyword:datadog\nkeyword:sentry\n"
            + "keyword:sift\ngeosite:category-ntp"
            + "</code></pre></html>"
        )
        rules = extract_claude_site_rules(html, "test")
        for keyword in ("datadog", "sentry", "sift"):
            self.assertIn(f"DOMAIN-KEYWORD,{keyword}", rules)
        self.assertFalse(any("ntp" in rule.lower() for rule in rules))

    def test_claude_merge_keeps_bett_first_and_site_supplements(self) -> None:
        bett = parse_domain_text(
            "+.anthropic.com\nservd-anthropic-website.b-cdn.net\n", "bett"
        )
        site = [
            "DOMAIN-SUFFIX,anthropic.com",
            "DOMAIN,api.anthropic.com",
            "DOMAIN-SUFFIX,sentry.io",
            "IP-ASN,399358,no-resolve",
        ]
        merged = merge_claude_rules(bett, site)
        self.assertEqual(
            merged[:2],
            [
                "DOMAIN-SUFFIX,anthropic.com",
                "DOMAIN,servd-anthropic-website.b-cdn.net",
            ],
        )
        self.assertNotIn("DOMAIN,api.anthropic.com", merged)
        self.assertIn("DOMAIN-SUFFIX,sentry.io", merged)
        self.assertIn("IP-ASN,399358,no-resolve", merged)
        self.assertEqual(
            render_classical_yaml(merged).splitlines()[0], "payload:"
        )

    def test_geolocation_outputs_are_externally_managed(self) -> None:
        for name in ("geolocation-cn.list", "geolocation-cn.mrs"):
            self.assertTrue(
                is_externally_managed_output(ROOT / "dist" / "mihomo" / name)
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
