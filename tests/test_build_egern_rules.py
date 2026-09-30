from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_egern_rules import (  # noqa: E402
    BuildError,
    output_rule_count,
    merge_ordered_rules,
    merge_privaterelay_sources,
    rule_sequence,
    parse_classical_rule_list,
    parse_classical_yaml_provider,
    parse_domain_list,
    parse_ip_list,
    resolve_provider_source,
    source_rule_count,
    slug,
)

class EgernRuleConverterTests(unittest.TestCase):
    def test_privaterelay_merge_preserves_bett_and_exact_sukka_scopes(self):
        base = "+.mask-api.icloud.com\n+.mask-h2.icloud.com\n+.mask.icloud.com\n"
        source, report = merge_privaterelay_sources(
            base,
            "# generated\n7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe\n"
            "mask.icloud.com\nmask-h2.icloud.com\nmask-api.icloud.com\n"
            "mask-canary.icloud.com\nmask.apple-dns.net\ncanary.mask.apple-dns.net\n",
            ["7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe"],
        )
        self.assertTrue(source.startswith(base))
        self.assertEqual(report["bett_entries"], 3)
        self.assertEqual(report["sukka_eligible_entries"], 6)
        self.assertEqual(report["supplemented_rules"], [
            "mask-canary.icloud.com", "mask.apple-dns.net", "canary.mask.apple-dns.net",
        ])
        native = merge_ordered_rules(parse_domain_list(source))
        self.assertEqual(native, {
            "domain_suffix_set": ["mask-api.icloud.com", "mask-h2.icloud.com", "mask.icloud.com"],
            "domain_set": ["mask-canary.icloud.com", "mask.apple-dns.net", "canary.mask.apple-dns.net"],
        })
        self.assertEqual(source_rule_count(source), output_rule_count([native]))

    def test_privaterelay_merge_preserves_primary_duplicates_and_rejects_empty_sets(self):
        source, report = merge_privaterelay_sources(
            "+.mask.icloud.com\n+.mask.icloud.com\n", "mask.icloud.com\n", []
        )
        self.assertEqual(source, "+.mask.icloud.com\n+.mask.icloud.com\n")
        self.assertEqual(report["supplemented_entries"], 0)
        with self.assertRaises(BuildError):
            merge_privaterelay_sources("", "mask.icloud.com\n", [])
        with self.assertRaises(BuildError):
            merge_privaterelay_sources("+.mask.icloud.com\n", "", [])

    def test_apple_merge_resolves_to_same_run_list(self):
        result = resolve_provider_source(
            {"url": "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/mihomo/apple-merged.mrs"},
            bett_commit="bett-commit", converter_commit="converter-commit",
        )
        self.assertEqual(result["repository"], "frostmage1250/proxy-rules-converter")
        self.assertEqual(result["path"], "dist/mihomo/apple-merged.list")
        source = "push-apple.com.akadns.net\n+.appstore.com\n+.organicfruitapps.com\n"
        native = merge_ordered_rules(parse_domain_list(source))
        self.assertEqual(native, {
            "domain_set": ["push-apple.com.akadns.net"],
            "domain_suffix_set": ["appstore.com", "organicfruitapps.com"],
        })

    def test_domain_source_keeps_type_transitions_and_duplicates(self):
        result = parse_domain_list(
            "example.com\n+.example.net\nexample.com\nkeyword:video\nregexp:^api\\.\n*.local\n"
        )
        self.assertEqual(
            result,
            [
                {"domain_set": ["example.com"]},
                {"domain_suffix_set": ["example.net"]},
                {"domain_set": ["example.com"]},
                {"domain_keyword_set": ["video"]},
                {"domain_regex_set": ["^api\\."]},
                {"domain_wildcard_set": ["*.local"]},
            ],
        )

    def test_ip_source_keeps_interleaved_address_families(self):
        result = parse_ip_list("1.1.1.1/24\n2001:db8::1/32\n1.1.1.1/24\n")
        self.assertEqual(
            result,
            [
                {"ip_cidr_set": ["1.1.1.1/24"], "no_resolve": True},
                {"ip_cidr6_set": ["2001:db8::1/32"], "no_resolve": True},
                {"ip_cidr_set": ["1.1.1.1/24"], "no_resolve": True},
            ],
        )

    def test_classical_apns_source_keeps_original_rule_order(self):
        result = parse_classical_rule_list(
            "DOMAIN-SUFFIX,push.apple.com\n"
            "DOMAIN-KEYWORD,apple.com.edgekey.net\n"
            "IP-CIDR,17.249.0.0/16,no-resolve\n"
            "IP-CIDR6,2620:149:a44::/48,no-resolve\n"
            "IP-ASN,399358,no-resolve\n"
        )
        self.assertEqual(
            result,
            [
                {"domain_suffix_set": ["push.apple.com"]},
                {"domain_keyword_set": ["apple.com.edgekey.net"]},
                {"ip_cidr_set": ["17.249.0.0/16"], "no_resolve": True},
                {"ip_cidr6_set": ["2620:149:a44::/48"], "no_resolve": True},
                {"asn_set": ["399358"], "no_resolve": True},
            ],
        )

    def test_classical_yaml_provider_preserves_payload_and_requires_no_resolve(self):
        result, count = parse_classical_yaml_provider(
            "payload:\n"
            "  - DOMAIN-SUFFIX,claude.ai\n"
            "  - DOMAIN-KEYWORD,sentry\n"
            "  - IP-CIDR,160.79.104.0/21,no-resolve\n"
        )
        self.assertEqual(count, 3)
        self.assertEqual(
            result,
            [
                {"domain_suffix_set": ["claude.ai"]},
                {"domain_keyword_set": ["sentry"]},
                {"ip_cidr_set": ["160.79.104.0/21"], "no_resolve": True},
            ],
        )
        with self.assertRaises(BuildError):
            parse_classical_yaml_provider("payload:\n  - IP-ASN,399358\n")

    def test_provider_source_follows_final_url_not_bundle_path(self):
        provider = {
            "path-in-bundle": "geo/geosite/geolocation-cn.mrs",
            "url": (
                "https://raw.githubusercontent.com/frostmage1250/"
                "proxy-rules-converter/main/dist/mihomo/geolocation-cn.mrs"
            ),
        }
        result = resolve_provider_source(
            provider,
            bett_commit="bett-commit",
            converter_commit="converter-commit",
        )
        self.assertEqual(result["repository"], "frostmage1250/proxy-rules-converter")
        self.assertEqual(result["ref"], "main")
        self.assertEqual(result["commit"], "converter-commit")
        self.assertEqual(result["path"], "dist/mihomo/geolocation-cn.list")
        self.assertEqual(
            result["url"],
            "https://raw.githubusercontent.com/frostmage1250/"
            "proxy-rules-converter/converter-commit/"
            "dist/mihomo/geolocation-cn.list",
        )

    def test_converter_classical_provider_uses_pinned_yaml(self):
        provider = {
            "url": (
                "https://raw.githubusercontent.com/frostmage1250/"
                "proxy-rules-converter/main/dist/mihomo/claude.yaml"
            ),
        }
        result = resolve_provider_source(
            provider,
            bett_commit="bett-commit",
            converter_commit="converter-commit",
        )
        self.assertEqual(result["repository"], "frostmage1250/proxy-rules-converter")
        self.assertEqual(result["commit"], "converter-commit")
        self.assertEqual(result["path"], "dist/mihomo/claude.yaml")
        self.assertTrue(result["url"].endswith("/converter-commit/dist/mihomo/claude.yaml"))

    def test_bett_provider_source_uses_final_url_and_pinned_commit(self):
        provider = {
            "path-in-bundle": "ignored/by/source/resolver.mrs",
            "url": (
                "https://fastly.jsdelivr.net/gh/appshubcc/"
                "bett-rules@meta/geo/geosite/google.mrs"
            ),
        }
        result = resolve_provider_source(
            provider,
            bett_commit="bett-commit",
            converter_commit="converter-commit",
        )
        self.assertEqual(result["repository"], "appshubcc/bett-rules")
        self.assertEqual(result["ref"], "meta")
        self.assertEqual(result["commit"], "bett-commit")
        self.assertEqual(result["path"], "geo/geosite/google.list")

    def test_bypass_japan_native_yaml_follows_canonical_source(self):
        source = (ROOT / "config" / "bypass-japan.list").read_text(encoding="utf-8")
        native = merge_ordered_rules(parse_domain_list(source))
        self.assertEqual(native, {"domain_suffix_set": ["javdb.com", "hanime1.me"]})
        self.assertEqual(source_rule_count(source), output_rule_count([native]))

    def test_converter_bypass_japan_mrs_uses_same_run_text_projection(self):
        provider = {
            "url": (
                "https://raw.githubusercontent.com/frostmage1250/"
                "proxy-rules-converter/main/dist/mihomo/bypass-japan.mrs"
            )
        }
        result = resolve_provider_source(
            provider, bett_commit="bett-commit", converter_commit="main"
        )
        self.assertEqual(result["repository"], "frostmage1250/proxy-rules-converter")
        self.assertEqual(result["path"], "dist/mihomo/bypass-japan.list")

    def test_mcdn_provider_keeps_reviewed_suffix_scope_across_formats(self):
        provider = {
            "url": "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/mihomo/mcdn-block.mrs"
        }
        source_info = resolve_provider_source(
            provider, bett_commit="bett-commit", converter_commit="converter-commit"
        )
        self.assertEqual(source_info["repository"], "frostmage1250/proxy-rules-converter")
        self.assertEqual(source_info["commit"], "converter-commit")
        self.assertEqual(source_info["path"], "dist/mihomo/mcdn-block.list")
        self.assertEqual(slug("mcdn屏蔽"), "mcdn-block")
        source = (ROOT / "config" / "mcdn-block.list").read_text(encoding="utf-8")
        native = merge_ordered_rules(parse_domain_list(source))
        self.assertEqual(native, {"domain_suffix_set": [
            "mcdn.bilivideo.com", "mcdn.bilivideo.cn",
            "edge.mountaintoys.cn", "h2.smtcdns.net",
        ]})
        self.assertEqual(source_rule_count(source), output_rule_count([native]))

    def test_converter_ai_mrs_uses_same_run_text_projection(self):
        provider = {
            "url": "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/mihomo/ai.mrs"
        }
        result = resolve_provider_source(
            provider, bett_commit="bett-commit", converter_commit="main"
        )
        self.assertEqual(result["path"], "dist/mihomo/ai.list")

    def test_rule_conversion_preserves_duplicates_spelling_count_and_order(self):
        domain_source = "example.com\n+.example.net\n+.example.net\nexample.com\n"
        domain_rules = parse_domain_list(domain_source)
        self.assertEqual(
            domain_rules,
            [
                {"domain_set": ["example.com"]},
                {"domain_suffix_set": ["example.net", "example.net"]},
                {"domain_set": ["example.com"]},
            ],
        )
        self.assertEqual(source_rule_count(domain_source), output_rule_count(domain_rules))

        ip_source = "1.1.1.1/24\n2001:db8::1/32\n1.1.1.1/24\n"
        ip_rules = parse_ip_list(ip_source)
        self.assertEqual(source_rule_count(ip_source), output_rule_count(ip_rules))
        self.assertEqual(ip_rules[0], ip_rules[2])

    def test_native_yaml_keeps_one_provider_and_per_type_duplicates(self):
        source = parse_domain_list(
            "a.example\n+.example.org\na.example\n+.example.org\n"
        )
        native = merge_ordered_rules(source)
        self.assertEqual(
            native,
            {
                "domain_set": ["a.example", "a.example"],
                "domain_suffix_set": ["example.org", "example.org"],
            },
        )
        self.assertEqual(output_rule_count([native]), source_rule_count(
            "a.example\n+.example.org\na.example\n+.example.org\n"
        ))
        self.assertEqual(
            rule_sequence(native),
            [
                ("domain_set", "a.example"),
                ("domain_set", "a.example"),
                ("domain_suffix_set", "example.org"),
                ("domain_suffix_set", "example.org"),
            ],
        )
        ip_native = merge_ordered_rules(parse_ip_list(
            "1.1.1.1/24\n2001:db8::1/32\n1.1.1.1/24\n"
        ))
        self.assertEqual(ip_native["ip_cidr_set"], ["1.1.1.1/24", "1.1.1.1/24"])
        self.assertTrue(ip_native["no_resolve"])

    def test_exact_geolocation_host_maps_to_domain_set(self):
        result = parse_domain_list("upos-icdn-cqg101.solseed.cn\n")
        self.assertEqual(result, [{"domain_set": ["upos-icdn-cqg101.solseed.cn"]}])


if __name__ == "__main__":
    unittest.main()
