from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_rules import (  # noqa: E402
    CLAUDE_SITE_REQUIRED_TYPED_RULES,
    BYPASS_JAPAN_LIST,
    ConversionError,
    DomainRule,
    duplicate_counts,
    extract_claude_site_rules,
    is_externally_managed_output,
    merge_claude_rules,
    merge_apple_rules,
    parse_sukka_apple_services,
    merge_mcdn_rules,
    parse_bypass_japan_source,
    merge_bypass_japan_rules,
    select_pron_rules,
    parse_mcdn_adguard,
    parse_domain_text,
    parse_ipcidr_text,
    parse_mixed_ipcidr_text,
    render_classical_yaml,
    render_rules,
    rule_covers_domain,
)


class ConverterTests(unittest.TestCase):
    def test_apple_supplement_excludes_push_marker_processes_and_ips(self) -> None:
        rules = parse_sukka_apple_services(
            "# generated\n"
            "DOMAIN,7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe\n"
            "DOMAIN-SUFFIX,appstore.com\n"
            "DOMAIN-SUFFIX,organicfruitapps.com\n"
            "DOMAIN-SUFFIX,push-apple.com.akadns.net\n"
            "PROCESS-NAME,apsd\n"
            "IP-CIDR,17.0.0.0/8,no-resolve\n",
            "Sukka",
            ["7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe", "push-apple.com.akadns.net"],
        )
        self.assertEqual(rules, [
            DomainRule("suffix", "appstore.com"),
            DomainRule("suffix", "organicfruitapps.com"),
        ])
        with self.assertRaises(ConversionError):
            parse_sukka_apple_services("DOMAIN-KEYWORD,apple\n", "Sukka", [])
        with self.assertRaises(ConversionError):
            parse_sukka_apple_services("DOMAIN-SUFFIX,Apple.com\n", "Sukka", [])

    def test_apple_merge_preserves_base_and_uses_semantic_coverage(self) -> None:
        primary = parse_domain_text(
            "exact.example\n+.apple.com\nexact.example\n.subdomain.example\n", "Bett"
        )
        supplement = parse_sukka_apple_services(
            "DOMAIN,api.apple.com\n"
            "DOMAIN-SUFFIX,maps.apple.com\n"
            "DOMAIN-SUFFIX,exact.example\n"
            "DOMAIN-SUFFIX,child.subdomain.example\n"
            "DOMAIN-SUFFIX,appstore.com\n"
            "DOMAIN-SUFFIX,appstore.com\n", "Sukka", []
        )
        merged = merge_apple_rules(primary, supplement)
        self.assertEqual(merged[:len(primary)], primary)
        self.assertEqual(merged[len(primary):], [
            DomainRule("suffix", "exact.example"),
            DomainRule("suffix", "appstore.com"),
        ])

    def test_domain_conversion_preserves_order_and_count(self) -> None:
        rules = parse_domain_text(
            "z.example\n+.example.com\na.example\n+.example.com\n", "test"
        )
        self.assertEqual(
            render_rules(rules, "mihomo"),
            "z.example\n+.example.com\na.example\n+.example.com\n",
        )

    def test_bypass_japan_source_has_exact_suffixes_in_order(self) -> None:
        source = BYPASS_JAPAN_LIST.read_text(encoding="utf-8")
        rules = parse_domain_text(source, str(BYPASS_JAPAN_LIST))
        self.assertEqual(rules, [
            DomainRule("suffix", "javdb.com"),
            DomainRule("suffix", "hanime1.me"),
        ])
        self.assertEqual(render_rules(rules, "mihomo"), source)

    def test_pron_excludes_regex_and_preserves_domain_scope(self) -> None:
        rules, excluded = parse_bypass_japan_source(
            "DOMAIN,cdn.example.com\n"
            "DOMAIN-REGEX,(^|\\.)javdb[0-9]{1,3}\\.com$\n"
            "DOMAIN-SUFFIX,video.fc2.com\n", "test",
        )
        self.assertEqual(excluded, 1)
        self.assertEqual(rules, [
            DomainRule("exact", "cdn.example.com"),
            DomainRule("suffix", "video.fc2.com"),
        ])

    def test_pron_selection_keeps_only_reviewed_source_domains(self) -> None:
        rules = [
            DomainRule("suffix", "javdb.com"),
            DomainRule("exact", "widgets.stripst.com"),
            DomainRule("suffix", "javdb-clone.com"),
            DomainRule("suffix", "e-hentai.org"),
            DomainRule("suffix", "collector.javdb.com"),
        ]
        selection = {"schema_version": 1, "sites": [
            {"name": "JavDB", "domains": ["javdb.com"], "cdn_domains": ["widgets.stripst.com"]},
        ], "excluded_domains": ["e-hentai.org", "exhentai.org"]}
        self.assertEqual(select_pron_rules(rules, selection), rules[:2])

    def test_pron_selection_rejects_external_or_excluded_domains(self) -> None:
        for domain in ["outside-source.example", "e-hentai.org", "img.exhentai.org"]:
            selection = {"schema_version": 1, "sites": [
                {"name": "test", "domains": [domain], "cdn_domains": []},
            ], "excluded_domains": ["e-hentai.org", "exhentai.org"]}
            with self.subTest(domain=domain), self.assertRaises(ConversionError):
                select_pron_rules([DomainRule("suffix", "javdb.com")], selection)

    def test_pron_merge_keeps_local_order_and_distinct_scopes(self) -> None:
        local = [DomainRule("suffix", "javdb.com"), DomainRule("suffix", "hanime1.me")]
        upstream = [
            DomainRule("suffix", "hanime1.me"), DomainRule("suffix", "javdb.com"),
            DomainRule("exact", "video.fc2.com"), DomainRule("suffix", "video.fc2.com"),
            DomainRule("suffix", "video.fc2.com"),
        ]
        self.assertEqual(merge_bypass_japan_rules(local, upstream), [
            *local, DomainRule("exact", "video.fc2.com"), DomainRule("suffix", "video.fc2.com"),
        ])

    def test_pron_rejects_unsupported_or_empty_domain_source(self) -> None:
        for source in ["DOMAIN-KEYWORD,example\n", "DOMAIN-REGEX,example.*\n", "DOMAIN-SUFFIX,Example.COM\n"]:
            with self.subTest(source=source), self.assertRaises(ConversionError):
                parse_bypass_japan_source(source, "test")

    def test_mcdn_adguard_merge_removes_only_identical_rules(self) -> None:
        local = parse_domain_text(
            "+.mcdn.bilivideo.com\n+.edge.mountaintoys.cn\n", "local"
        )
        upstream = parse_mcdn_adguard(
            "! comment\n||mcdn.bilivideo.com^$important\n"
            "||mountaintoys.cn^$important\n||mountaintoys.cn^$important\n", "adguard"
        )
        self.assertEqual(merge_mcdn_rules(local, upstream), [
            DomainRule("suffix", "mcdn.bilivideo.com"),
            DomainRule("suffix", "edge.mountaintoys.cn"),
            DomainRule("suffix", "mountaintoys.cn"),
        ])

    def test_mcdn_skips_only_user_excluded_wildcard(self) -> None:
        excluded = "||*pcdn*.biliapi.net^$important"
        rules = parse_mcdn_adguard(
            excluded + "\n||pcdn.yximgs.com^$important\n",
            "adguard", [excluded],
        )
        self.assertEqual(rules, [DomainRule("suffix", "pcdn.yximgs.com")])
        with self.assertRaises(ConversionError):
            parse_mcdn_adguard("||*other*.biliapi.net^$important\n", "adguard", [excluded])

    def test_mcdn_adguard_rejects_unsupported_filters(self) -> None:
        for source in (
            "@@||example.com^", "||example.com^$third-party",
            "||example.com/path", "||Example.com^", "<html>error</html>",
        ):
            with self.subTest(source=source), self.assertRaises(ConversionError):
                parse_mcdn_adguard(source + "\n", "adguard")

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
            {"geosite_base", "steam_cn_download_validation", "anthropic", "ai_mrs", "apple"},
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

    def test_egern_and_ai_outputs_are_externally_managed(self) -> None:
        for path in (
            ROOT / "dist" / "mihomo" / "ai.list",
            ROOT / "dist" / "egern" / "apns.yaml",
            ROOT / "dist" / "egern" / "geolocation-cn.yaml",
            ROOT / "reports" / "egern-source.json",
        ):
            self.assertTrue(is_externally_managed_output(path))
        self.assertFalse(
            is_externally_managed_output(ROOT / "dist" / "mihomo" / "steam-cn-download.list")
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
