from __future__ import annotations\n\nimport sys\nimport unittest\nfrom pathlib import Path\n\n\nROOT = Path(__file__).resolve().parents[1]\nsys.path.insert(0, str(ROOT / "src"))\n\nfrom convert_rules import (  # noqa: E402
    APPLE_EXPANDED_SUFFIXES,
    ConversionError,
    DomainRule,
    GLOBAL_DROPPED_KEYWORDS,
    GLOBAL_EXPANDED_KEYWORDS,
    MICROSOFT_KEYWORDS,
    SUKKA_ATTRIBUTION_MARKER,
    drop_sukka_marker,
    drop_domain_fragments,
    expand_domain_keywords,
    expand_domain_suffixes,
    is_droppable_domestic_wildcard,
    is_externally_managed_output,
    parse_classical_domains,
    parse_domain_text,
    parse_ipcidr_text,
    parse_mixed_ipcidr_text,
    render_rules,
    render_shadowrocket_ip_rules,
    rule_covers_domain,\n    semantic_minimize,\n)\n\n\nclass ConverterTests(unittest.TestCase):
    def test_steam_cn_allowlist_is_the_reviewed_metacubex_subset(self) -> None:
        entries = [
            line.strip()
            for line in (ROOT / "config" / "steam-cn-download-allowlist.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(len(entries), 11)
        self.assertEqual(len(entries), len(set(entries)))
        self.assertIn("st-bak.viv.wanwang.space", entries)
        self.assertIn("trts.baishancdnx.cn", entries)

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

    def test_parses_and_renders_mixed_shadowrocket_ip_rules(self) -> None:
        entries, duplicates = parse_mixed_ipcidr_text(
            "1.1.1.0/24\n2001:db8::/32\n1.1.1.0/24\n", "test"
        )
        self.assertEqual(entries, ["1.1.1.0/24", "2001:db8::/32"])
        self.assertEqual(duplicates, 1)
        self.assertEqual(
            render_shadowrocket_ip_rules(entries),
            "IP-CIDR,1.1.1.0/24\nIP-CIDR6,2001:db8::/32\n",
        )

    def test_bett_shadowrocket_mapping_matches_reviewed_scope(self) -> None:
        import json

        config = json.loads(
            (ROOT / "config" / "sources.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(config["bett"]["shadowrocket_ips"]),
            {
                "private-ip",
                "cn-ip",
                "telegram-ip",
                "facebook-ip",
                "twitter-ip",
                "tiktok-ip",
                "google-ip",
            },
        )
        self.assertEqual(
            config["bett"]["shadowrocket_asns"],
            {"steam-asn": "AS32590.list"},
        )
        for forbidden in ("apple-ip", "microsoft-ip", "steam-ip", "openai-ip"):
            self.assertNotIn(forbidden, config["bett"]["shadowrocket_ips"])
        self.assertNotIn("geolocation-cn", config["bett"]["shadowrocket_domains"])

    def test_self_built_geolocation_shadowrocket_output_is_external(self) -> None:
        self.assertTrue(
            is_externally_managed_output(
                ROOT / "dist" / "shadowrocket" / "geolocation-cn.domain-set"
            )
        )

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
        self.assertTrue(
            is_externally_managed_output(
                ROOT / "dist" / "mihomo" / "geolocation-cn.list"
            )
        )
        self.assertTrue(
            is_externally_managed_output(ROOT / "reports" / "geolocation-cn.json")
        )

    def test_parse_non_classical_domain_text(self) -> None:
        rules = parse_domain_text("example.com\n+.example.org\n", "test")\n        self.assertEqual(\n            rules,\n            [DomainRule("exact", "example.com"), DomainRule("suffix", "example.org")],\n        )\n\n    def test_rejects_unknown_wildcards(self) -> None:\n        with self.assertRaises(ConversionError):\n            parse_domain_text("*.example.com\n", "test")\n\n    def test_accepts_private_single_label_hostname(self) -> None:\n        rules = parse_domain_text("internal\n", "test")\n        self.assertEqual(rules, [DomainRule("exact", "internal")])\n\n    def test_only_reviewed_qhimgs_wildcard_is_droppable(self) -> None:\n        self.assertTrue(is_droppable_domestic_wildcard("*.qhimgs?.com"))\n        self.assertFalse(is_droppable_domestic_wildcard("*.example?.com"))\n\n    def test_semantic_minimize_removes_covered_exact_rule(self) -> None:
        rules, duplicates, redundant = semantic_minimize(\n            [\n                DomainRule("suffix", "example.com"),\n                DomainRule("exact", "cdn.example.com"),\n                DomainRule("suffix", "example.com"),\n            ]\n        )\n        self.assertEqual(rules, [DomainRule("suffix", "example.com")])\n        self.assertEqual(duplicates, 1)
        self.assertEqual(redundant, 1)

    def test_semantic_minimize_preserves_apex_for_subdomain_suffix(self) -> None:
        rules, duplicates, redundant = semantic_minimize(
            [
                DomainRule("subdomain_suffix", "example.com"),
                DomainRule("exact", "example.com"),
                DomainRule("exact", "www.example.com"),
                DomainRule("suffix", "cdn.example.com"),
            ]
        )
        self.assertEqual(
            rules,
            [
                DomainRule("exact", "example.com"),
                DomainRule("subdomain_suffix", "example.com"),
            ],
        )
        self.assertEqual(duplicates, 0)
        self.assertEqual(redundant, 2)
\n    def test_suffix_coverage(self) -> None:\n        rule = DomainRule("suffix", "example.com")\n        self.assertTrue(rule_covers_domain(rule, "example.com"))\n        self.assertTrue(rule_covers_domain(rule, "cdn.example.com"))\n        self.assertFalse(rule_covers_domain(rule, "notexample.com"))\n\n    def test_target_rendering(self) -> None:
        rules = [DomainRule("exact", "a.example"), DomainRule("suffix", "example.com")]\n        self.assertEqual(render_rules(rules, "mihomo"), "a.example\n+.example.com\n")\n        self.assertEqual(\n            render_rules(rules, "shadowrocket"), "a.example\n.example.com\n"
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

    def test_apple_suffix_expansion_is_finite_and_preserves_only_exact_apex(self) -> None:
        expanded, counts = expand_domain_suffixes(
            APPLE_EXPANDED_SUFFIXES,
            [
                DomainRule("suffix", "apple.com"),
                DomainRule("exact", "music.apple.com"),
                DomainRule("suffix", "iad.apple.com"),
                DomainRule("suffix", "applemusic.com"),
            ],
        )
        self.assertEqual(
            set(expanded),
            {
                DomainRule("exact", "apple.com"),
                DomainRule("exact", "music.apple.com"),
                DomainRule("suffix", "iad.apple.com"),
            },
        )
        self.assertEqual(counts, {"apple.com": 2})
        self.assertNotIn(DomainRule("suffix", "apple.com"), expanded)

    def test_apple_suffix_expansion_requires_reference_matches(self) -> None:
        with self.assertRaises(ConversionError):
            expand_domain_suffixes(
                APPLE_EXPANDED_SUFFIXES,
                [DomainRule("suffix", "applemusic.com")],
            )

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
\n\nif __name__ == "__main__":\n    unittest.main()\n