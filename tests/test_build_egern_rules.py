from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_egern_rules import (  # noqa: E402
    BuildError,
    output_rule_count,
    parse_classical_rule_list,
    parse_classical_yaml_provider,
    parse_domain_list,
    parse_ip_list,
    resolve_provider_source,
    source_rule_count,
)

class EgernRuleConverterTests(unittest.TestCase):
    def test_domain_source_becomes_native_egern_fields(self):
        result = parse_domain_list(
            "example.com\n+.example.net\nkeyword:video\nregexp:^api\\.\n*.local\n"
        )
        self.assertEqual(result["domain_set"], ["example.com"])
        self.assertEqual(result["domain_suffix_set"], ["example.net"])
        self.assertEqual(result["domain_keyword_set"], ["video"])
        self.assertEqual(result["domain_regex_set"], ["^api\\."])
        self.assertEqual(result["domain_wildcard_set"], ["*.local"])

    def test_ip_source_splits_v4_and_v6_and_sets_no_resolve(self):
        result = parse_ip_list("1.1.1.1/24\n2001:db8::1/32\n")
        self.assertTrue(result["no_resolve"])
        self.assertEqual(result["ip_cidr_set"], ["1.1.1.1/24"])
        self.assertEqual(result["ip_cidr6_set"], ["2001:db8::1/32"])

    def test_classical_apns_source_becomes_one_native_mixed_rule_set(self):
        result = parse_classical_rule_list(
            "DOMAIN-SUFFIX,push.apple.com\n"
            "DOMAIN-KEYWORD,apple.com.edgekey.net\n"
            "IP-CIDR,17.249.0.0/16,no-resolve\n"
            "IP-CIDR6,2620:149:a44::/48,no-resolve\n"
            "IP-ASN,399358,no-resolve\n"
        )
        self.assertEqual(result["domain_suffix_set"], ["push.apple.com"])
        self.assertEqual(
            result["domain_keyword_set"], ["apple.com.edgekey.net"]
        )
        self.assertEqual(result["ip_cidr_set"], ["17.249.0.0/16"])
        self.assertEqual(result["ip_cidr6_set"], ["2620:149:a44::/48"])
        self.assertEqual(result["asn_set"], ["399358"])
        self.assertTrue(result["no_resolve"])

    def test_classical_yaml_provider_preserves_payload_and_requires_no_resolve(self):
        result, count = parse_classical_yaml_provider(
            "payload:\n"
            "  - DOMAIN-SUFFIX,claude.ai\n"
            "  - DOMAIN-KEYWORD,sentry\n"
            "  - IP-CIDR,160.79.104.0/21,no-resolve\n"
            "  - IP-CIDR6,2607:6bc0::/32,no-resolve\n"
            "  - IP-ASN,399358,no-resolve\n"
        )
        self.assertEqual(count, 5)
        self.assertEqual(result["domain_suffix_set"], ["claude.ai"])
        self.assertEqual(result["domain_keyword_set"], ["sentry"])
        self.assertEqual(result["ip_cidr_set"], ["160.79.104.0/21"])
        self.assertEqual(result["ip_cidr6_set"], ["2607:6bc0::/32"])
        self.assertEqual(result["asn_set"], ["399358"])
        self.assertTrue(result["no_resolve"])
        with self.assertRaises(BuildError):
            parse_classical_yaml_provider(
                "payload:\n  - IP-ASN,399358\n"
            )

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

    def test_rule_conversion_preserves_duplicates_spelling_and_count(self):
        domain_source = "example.com\n+.example.net\n+.example.net\n"
        domain_rule = parse_domain_list(domain_source)
        self.assertEqual(
            domain_rule["domain_suffix_set"],
            ["example.net", "example.net"],
        )
        self.assertEqual(source_rule_count(domain_source), output_rule_count(domain_rule))

        ip_source = "1.1.1.1/24\n1.1.1.1/24\n"
        ip_rule = parse_ip_list(ip_source)
        self.assertEqual(ip_rule["ip_cidr_set"], ["1.1.1.1/24", "1.1.1.1/24"])
        self.assertEqual(source_rule_count(ip_source), output_rule_count(ip_rule))

    def test_exact_geolocation_host_maps_to_domain_set(self):
        result = parse_domain_list("upos-icdn-cqg101.solseed.cn\n")
        self.assertEqual(result["domain_set"], ["upos-icdn-cqg101.solseed.cn"])
        self.assertNotIn("domain_suffix_set", result)


if __name__ == "__main__":
    unittest.main()
