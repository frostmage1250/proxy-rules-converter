from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_rules import (  # noqa: E402
    ConversionError,
    DomainRule,
    GLOBAL_DROPPED_KEYWORDS,
    GLOBAL_EXPANDED_KEYWORDS,
    MICROSOFT_KEYWORDS,
    SUKKA_ATTRIBUTION_MARKER,
    drop_sukka_marker,
    drop_domain_fragments,
    expand_domain_keywords,
    is_droppable_domestic_wildcard,
    is_externally_managed_output,
    parse_classical_domains,
    parse_domain_text,
    parse_ipcidr_text,
    render_rules,
    rule_covers_domain,
    semantic_minimize,
)


class ConverterTests(unittest.TestCase):
    def test_parses_and_deduplicates_ipv4_cidrs(self) -> None:
        entries, duplicates = parse_ipcidr_text(
            "# comment\n1.1.8.0/24\n1.1.8.0/24\n", "test", 4
        )
        self.assertEqual(entries, ["1.1.8.0/24"])
        self.assertEqual(duplicates, 1)

    def test_parses_ipv6_cidrs(self) -> None:
        entries, duplicates = parse_ipcidr_text("2001:250::/30\n", "test", 6)
        self.assertEqual(entries, ["2001:250::/30"])
        self.assertEqual(duplicates, 0)

    def test_rejects_wrong_ip_family(self) -> None:
        with self.assertRaises(ConversionError):
            parse_ipcidr_text("2001:250::/30\n", "test", 4)

    def test_rejects_noncanonical_cidr(self) -> None:
        with self.assertRaises(ConversionError):
            parse_ipcidr_text("1.1.8.1/24\n", "test", 4)

    def test_mrs_outputs_are_owned_by_the_official_converter(self) -> None:
        self.assertTrue(
            is_externally_managed_output(ROOT / "dist" / "mihomo" / "global.mrs")
        )
        self.assertFalse(
            is_externally_managed_output(ROOT / "dist" / "mihomo" / "global.list")
        )
        self.assertFalse(
            is_externally_managed_output(ROOT / "dist" / "shadowrocket" / "global.mrs")
        )

    def test_parse_non_classical_domain_text(self) -> None:
        rules = parse_domain_text("example.com\n+.example.org\n", "test")
        self.assertEqual(
            rules,
            [DomainRule("exact", "example.com"), DomainRule("suffix", "example.org")],
        )

    def test_rejects_unknown_wildcards(self) -> None:
        with self.assertRaises(ConversionError):
            parse_domain_text("*.example.com\n", "test")

    def test_accepts_private_single_label_hostname(self) -> None:
        rules = parse_domain_text("internal\n", "test")
        self.assertEqual(rules, [DomainRule("exact", "internal")])

    def test_only_reviewed_qhimgs_wildcard_is_droppable(self) -> None:
        self.assertTrue(is_droppable_domestic_wildcard("*.qhimgs?.com"))
        self.assertFalse(is_droppable_domestic_wildcard("*.example?.com"))

    def test_semantic_minimize_removes_covered_exact_rule(self) -> None:
        rules, duplicates, redundant = semantic_minimize(
            [
                DomainRule("suffix", "example.com"),
                DomainRule("exact", "cdn.example.com"),
                DomainRule("suffix", "example.com"),
            ]
        )
        self.assertEqual(rules, [DomainRule("suffix", "example.com")])
        self.assertEqual(duplicates, 1)
        self.assertEqual(redundant, 1)

    def test_suffix_coverage(self) -> None:
        rule = DomainRule("suffix", "example.com")
        self.assertTrue(rule_covers_domain(rule, "example.com"))
        self.assertTrue(rule_covers_domain(rule, "cdn.example.com"))
        self.assertFalse(rule_covers_domain(rule, "notexample.com"))

    def test_target_rendering(self) -> None:
        rules = [DomainRule("exact", "a.example"), DomainRule("suffix", "example.com")]
        self.assertEqual(render_rules(rules, "mihomo"), "a.example\n+.example.com\n")
        self.assertEqual(
            render_rules(rules, "shadowrocket"), "a.example\n.example.com\n"
        )

    def test_classical_parser_has_explicit_skip_and_keyword_policy(self) -> None:
        rules, keywords, ignored = parse_classical_domains(
            "DOMAIN-SUFFIX,example.com\n"
            "DOMAIN-KEYWORD,microsoft\n"
            "PROCESS-NAME,Example.exe\n",
            "test",
            allowed_keywords=MICROSOFT_KEYWORDS,
            ignored_rule_types=frozenset({"PROCESS-NAME"}),
        )
        self.assertEqual(rules, [DomainRule("suffix", "example.com")])
        self.assertEqual(keywords, ["microsoft"])
        self.assertEqual(ignored, {"PROCESS-NAME": 1})

    def test_classical_parser_rejects_unreviewed_keyword(self) -> None:
        with self.assertRaises(ConversionError):
            parse_classical_domains(
                "DOMAIN-KEYWORD,unexpected\n",
                "test",
                allowed_keywords=MICROSOFT_KEYWORDS,
            )

    def test_keyword_expansion_is_finite_and_reference_backed(self) -> None:
        expanded, counts = expand_domain_keywords(
            ["microsoft", "1drv"],
            [
                DomainRule("exact", "officecdn-microsoft-com.akamaized.net"),
                DomainRule("suffix", "1drv.ms"),
                DomainRule("suffix", "example.com"),
            ],
        )
        self.assertEqual(
            set(expanded),
            {
                DomainRule("exact", "officecdn-microsoft-com.akamaized.net"),
                DomainRule("suffix", "1drv.ms"),
            },
        )
        self.assertEqual(counts, {"1drv": 1, "microsoft": 1})

    def test_sukka_attribution_marker_is_not_emitted(self) -> None:
        rules, removed = drop_sukka_marker(
            [
                DomainRule("exact", SUKKA_ATTRIBUTION_MARKER),
                DomainRule("suffix", "example.com"),
            ]
        )
        self.assertEqual(rules, [DomainRule("suffix", "example.com")])
        self.assertEqual(removed, 1)

    def test_global_keyword_policy_is_explicit_and_disjoint(self) -> None:
        self.assertEqual(
            GLOBAL_EXPANDED_KEYWORDS,
            {"google", "facebook", "whatsapp", "discord", "dropbox", "pinterest"},
        )
        self.assertEqual(
            GLOBAL_DROPPED_KEYWORDS, {"blogspot", "sci-hub", "browserleaks"}
        )
        self.assertFalse(GLOBAL_EXPANDED_KEYWORDS & GLOBAL_DROPPED_KEYWORDS)

    def test_dropped_global_fragments_do_not_return_through_branches(self) -> None:
        rules, counts = drop_domain_fragments(
            [
                DomainRule("suffix", "blogspot.com"),
                DomainRule("exact", "browserleaks.com"),
                DomainRule("suffix", "google.com"),
            ],
            GLOBAL_DROPPED_KEYWORDS,
        )
        self.assertEqual(rules, [DomainRule("suffix", "google.com")])
        self.assertEqual(counts["blogspot"], 1)
        self.assertEqual(counts["browserleaks"], 1)
        self.assertEqual(counts["sci-hub"], 0)


if __name__ == "__main__":
    unittest.main()
