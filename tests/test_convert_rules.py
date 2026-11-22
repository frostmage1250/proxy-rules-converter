from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import convert_rules  # noqa: E402
from convert_rules import (  # noqa: E402
    CLAUDE_PROCESS_RULE,
    CLAUDE_SUPPLEMENT,
    PRON_SITES,
    ConversionError,
    DomainRule,
    build,
    build_claude_rules,
    duplicate_counts,
    is_externally_managed_output,
    merge_mcdn_rules,
    parse_claude_supplement,
    parse_domain_text,
    parse_ipcidr_text,
    parse_mcdn_adguard,
    parse_porn_source,
    render_classical_rules,
    render_classical_text,
    render_rules,
    select_pron_rules,
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

    def test_pron_excludes_regex_and_preserves_domain_scope(self) -> None:
        rules, excluded = parse_porn_source(
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

    def test_pron_selection_config_has_former_local_sites(self) -> None:
        selection = json.loads(PRON_SITES.read_text(encoding="utf-8"))
        domains = {
            domain
            for site in selection["sites"]
            for domain in site["domains"] + site["cdn_domains"]
        }
        self.assertTrue({"javdb.com", "hanime1.me"}.issubset(domains))
        self.assertFalse((ROOT / "config" / "porn.list").exists())

    def test_pron_rejects_unsupported_or_empty_domain_source(self) -> None:
        for source in ["DOMAIN-KEYWORD,example\n", "DOMAIN-REGEX,example.*\n", "DOMAIN-SUFFIX,Example.COM\n"]:
            with self.subTest(source=source), self.assertRaises(ConversionError):
                parse_porn_source(source, "test")

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

    def test_bett_sources_have_no_ai_or_site_scraping(self) -> None:
        config = json.loads(
            (ROOT / "config" / "sources.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(config["bett"]), {"geosite_base", "anthropic"})
        self.assertNotIn("claude_site", config)

    def test_claude_supplement_file_is_valid(self) -> None:
        rules = parse_claude_supplement(
            CLAUDE_SUPPLEMENT.read_text(encoding="utf-8"), str(CLAUDE_SUPPLEMENT)
        )
        self.assertTrue(rules)
        self.assertNotIn(CLAUDE_PROCESS_RULE, rules)

    def test_claude_supplement_accepts_allowed_types_and_comments(self) -> None:
        text = (
            "# comment\n\n"
            "DOMAIN,a.example\nDOMAIN-SUFFIX,b.example\nDOMAIN-KEYWORD,telemetry\n"
            "IP-CIDR,192.0.2.0/24,no-resolve\nIP-CIDR6,2001:db8::/32\n"
            "IP-ASN,64496,no-resolve\n"
        )
        self.assertEqual(len(parse_claude_supplement(text, "test")), 6)

    def test_claude_supplement_rejects_other_rules(self) -> None:
        for line in (
            "PROCESS-NAME,claude.exe",
            "DOMAIN-REGEX,^claude",
            "DOMAIN-WILDCARD,*.claude.ai",
            "DOMAIN,Claude.ai",
            "DOMAIN-SUFFIX,claude.ai,no-resolve",
            "IP-CIDR,192.0.2.1/24,no-resolve",
            "IP-CIDR,2001:db8::/32",
            "IP-CIDR6,192.0.2.0/24",
            "IP-ASN,AS64496",
            "IP-CIDR,192.0.2.0/24,no-resolve,extra",
            "+.claude.ai",
        ):
            with self.subTest(line=line), self.assertRaises(ConversionError):
                parse_claude_supplement(line + "\n", "test")

    def test_claude_rules_bett_first_dedup_and_process_last(self) -> None:
        bett = parse_domain_text(
            "servd-anthropic-website.b-cdn.net\n+.anthropic.com\n+.claude.ai\n", "bett"
        )
        supplement = [
            "DOMAIN-SUFFIX,anthropic.com",
            "DOMAIN,api.anthropic.com",
            "DOMAIN-KEYWORD,datadog",
            "DOMAIN-KEYWORD,datadog",
            "IP-ASN,399358,no-resolve",
        ]
        self.assertEqual(
            build_claude_rules(bett, supplement),
            [
                "DOMAIN,servd-anthropic-website.b-cdn.net",
                "DOMAIN-SUFFIX,anthropic.com",
                "DOMAIN-SUFFIX,claude.ai",
                "DOMAIN,api.anthropic.com",
                "DOMAIN-KEYWORD,datadog",
                "IP-ASN,399358,no-resolve",
                CLAUDE_PROCESS_RULE,
            ],
        )

    def test_claude_bett_subdomain_only_rule_fails(self) -> None:
        with self.assertRaises(ConversionError):
            build_claude_rules(parse_domain_text(".anthropic.com\n", "bett"), [])

    def test_classical_rendering_has_no_payload(self) -> None:
        text = render_classical_rules(
            [DomainRule("suffix", "a.example"), DomainRule("exact", "b.example")]
        )
        self.assertEqual(text, "DOMAIN-SUFFIX,a.example\nDOMAIN,b.example\n")
        with self.assertRaises(ConversionError):
            render_classical_text([])

    def test_build_produces_exact_output_set(self) -> None:
        selection = json.loads(PRON_SITES.read_text(encoding="utf-8"))
        porn_lines = ["DOMAIN-REGEX,^ignored$", "DOMAIN-SUFFIX,not-selected.example"]
        for site in selection["sites"]:
            for domain in site["domains"] + site["cdn_domains"]:
                porn_lines.append(f"DOMAIN-SUFFIX,{domain}")
        anthropic = "+.anthropic.com\nservd-anthropic-website.b-cdn.net\n"
        adguard = "! test\n||mcdn.bilivideo.com^$important\n||pcdn.example.com^\n"
        with tempfile.TemporaryDirectory() as temp_name:
            porn_path = Path(temp_name) / "category-porn.list"
            mcdn_path = Path(temp_name) / "adguard.txt"
            porn_path.write_text("\n".join(porn_lines) + "\n", encoding="utf-8")
            mcdn_path.write_text(adguard, encoding="utf-8")
            with mock.patch.object(convert_rules, "fetch_text", return_value=anthropic):
                outputs, intermediates = build(
                    ROOT / "config" / "sources.json", mcdn_path, porn_path
                )
        self.assertEqual(
            set(outputs),
            {
                "dist/mihomo/claude.list",
                "dist/classical/mcdn-block.list",
                "dist/classical/porn.list",
                "reports/summary.json",
                "reports/update-report.md",
            },
        )
        self.assertEqual(set(intermediates), {"mcdn-block.list", "porn.list"})

        claude = outputs["dist/mihomo/claude.list"].splitlines()
        self.assertEqual(claude[0], "DOMAIN-SUFFIX,anthropic.com")
        self.assertEqual(claude[-1], CLAUDE_PROCESS_RULE)
        self.assertEqual(len(claude), len(set(claude)))
        self.assertNotIn("payload:", outputs["dist/mihomo/claude.list"])

        porn = outputs["dist/classical/porn.list"].splitlines()
        self.assertNotIn("DOMAIN-SUFFIX,not-selected.example", porn)
        self.assertEqual(
            [line.replace("DOMAIN-SUFFIX,", "+.", 1) for line in porn],
            intermediates["porn.list"].splitlines(),
        )

        mcdn = outputs["dist/classical/mcdn-block.list"].splitlines()
        self.assertEqual(mcdn[0], "DOMAIN-SUFFIX,mcdn.bilivideo.com")
        self.assertEqual(mcdn[-1], "DOMAIN-SUFFIX,pcdn.example.com")
        self.assertEqual(len(mcdn), 5)

    def test_workflow_built_outputs_are_externally_managed(self) -> None:
        for path in (
            ROOT / "dist" / "mihomo" / "geolocation-cn.mrs",
            ROOT / "dist" / "mihomo" / "porn.mrs",
            ROOT / "dist" / "classical" / "geolocation-cn.list",
        ):
            with self.subTest(path=path):
                self.assertTrue(is_externally_managed_output(path))
        for path in (
            ROOT / "dist" / "mihomo" / "claude.list",
            ROOT / "dist" / "mihomo" / "porn.list",
            ROOT / "dist" / "classical" / "porn.list",
            ROOT / "dist" / "classical" / "mcdn-block.list",
        ):
            with self.subTest(path=path):
                self.assertFalse(is_externally_managed_output(path))

    def test_duplicate_counts(self) -> None:
        self.assertEqual(
            duplicate_counts(["a", "a", "b", "c", "c", "c"]),
            {"a": 2, "c": 3},
        )


if __name__ == "__main__":
    unittest.main()
