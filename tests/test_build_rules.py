import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from build_rules import BuildError, convert, resolve  # noqa: E402


class ConvertTest(unittest.TestCase):
    def test_type_mapping(self):
        rules, skipped = convert(
            "\n".join([
                "# comment", "// comment", "; comment", "",
                "DOMAIN,a.com", "DOMAIN-SUFFIX,b.com", "DOMAIN-KEYWORD,key",
                "DOMAIN-WILDCARD,*.c.com", "DOMAIN-REGEX,^d\\.com$",
                "  IP-CIDR , 1.2.3.0/24 ", "IP-CIDR6,2001:db8::/32", "IP-ASN,13335",
            ]),
            "t",
        )
        self.assertEqual(rules, {
            "domain_set": ["a.com"],
            "domain_suffix_set": ["b.com"],
            "domain_keyword_set": ["key"],
            "domain_wildcard_set": ["*.c.com"],
            "domain_regex_set": ["^d\\.com$"],
            "ip_cidr_set": ["1.2.3.0/24"],
            "ip_cidr6_set": ["2001:db8::/32"],
            "asn_set": ["13335"],
        })
        self.assertEqual(skipped, {})

    def test_regex_keeps_commas(self):
        rules, _ = convert("DOMAIN-REGEX,^a[0-9]{1,3}\\.com$", "t")
        self.assertEqual(rules["domain_regex_set"], ["^a[0-9]{1,3}\\.com$"])

    def test_ipv6_written_as_ip_cidr(self):
        rules, _ = convert("IP-CIDR,1.0.1.0/24\nIP-CIDR,2400:3200::/32", "t")
        self.assertEqual(rules, {"ip_cidr_set": ["1.0.1.0/24"], "ip_cidr6_set": ["2400:3200::/32"]})

    def test_skip_types(self):
        rules, skipped = convert(
            "DOMAIN-SUFFIX,a.com\nDOMAIN-REGEX,^b$\nDOMAIN-KEYWORD,c\nDOMAIN-REGEX,^d$",
            "t", {"DOMAIN-REGEX", "DOMAIN-KEYWORD"},
        )
        self.assertEqual(rules, {"domain_suffix_set": ["a.com"]})
        self.assertEqual(skipped, {"DOMAIN-REGEX": 2, "DOMAIN-KEYWORD": 1})

    def test_process_name_skipped(self):
        rules, skipped = convert("DOMAIN,a.com\nPROCESS-NAME,claude.exe", "t")
        self.assertEqual(rules, {"domain_set": ["a.com"]})
        self.assertEqual(skipped, {"PROCESS-NAME": 1})

    def test_no_resolve_all(self):
        rules, _ = convert(
            "DOMAIN,a.com\nIP-CIDR,1.2.3.0/24,no-resolve\nIP-CIDR6,::1/128,no-resolve\nIP-ASN,1,no-resolve", "t"
        )
        self.assertIs(rules["no_resolve"], True)
        self.assertEqual(list(rules)[-1], "no_resolve")

    def test_no_resolve_none(self):
        rules, _ = convert("IP-CIDR,1.2.3.0/24\nIP-ASN,1", "t")
        self.assertNotIn("no_resolve", rules)

    def test_no_resolve_mixed_fails(self):
        with self.assertRaisesRegex(BuildError, "no-resolve"):
            convert("IP-CIDR,1.2.3.0/24,no-resolve\nIP-CIDR,5.6.7.0/24", "t")

    def test_unknown_type_fails_with_location(self):
        with self.assertRaisesRegex(BuildError, r"rules\.list:2: .*GEOIP"):
            convert("DOMAIN,a.com\nGEOIP,CN", "rules.list")

    def test_invalid_values_fail(self):
        for line in ("DOMAIN,", "IP-CIDR,not-an-ip", "IP-CIDR6,1.2.3.0/24", "IP-ASN,abc", "DOMAIN,a.com,no-resolve"):
            with self.subTest(line=line), self.assertRaises(BuildError):
                convert(line, "t")

    def test_dedup_keeps_first_order(self):
        rules, _ = convert("DOMAIN,b.com\nDOMAIN,a.com\nDOMAIN,b.com\nDOMAIN-SUFFIX,b.com", "t")
        self.assertEqual(rules, {"domain_set": ["b.com", "a.com"], "domain_suffix_set": ["b.com"]})

    def test_empty_result_fails(self):
        with self.assertRaises(BuildError):
            convert("# only comments\nPROCESS-NAME,a.exe", "t")


class ResolveTest(unittest.TestCase):
    SOURCES = {"bett": {"base": "https://example.com/geo/", "skip_types": ["DOMAIN-REGEX"]}}

    def test_prefix_quotes_path_and_inherits_skip_types(self):
        url, skip = resolve("bett:geosite/classical/geolocation-!cn.list", self.SOURCES)
        self.assertEqual(url, "https://example.com/geo/geosite/classical/geolocation-%21cn.list")
        self.assertEqual(skip, {"DOMAIN-REGEX"})
        url, _ = resolve("bett:geosite/classical/apple@cn.list", self.SOURCES)
        self.assertTrue(url.endswith("/apple%40cn.list"))

    def test_full_url_and_override(self):
        self.assertEqual(resolve("https://x.org/a.list", self.SOURCES), ("https://x.org/a.list", set()))
        _, skip = resolve({"source": "bett:a.list", "skip_types": []}, self.SOURCES)
        self.assertEqual(skip, set())

    def test_unknown_prefix_fails(self):
        with self.assertRaises(BuildError):
            resolve("nope:a.list", self.SOURCES)


if __name__ == "__main__":
    unittest.main()
