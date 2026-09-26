from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_ai_mrs import AI_SUPPLEMENTS, covers, merge_ai_rules  # noqa: E402
from convert_rules import DomainRule, parse_domain_text, render_rules  # noqa: E402


class AITests(unittest.TestCase):
    def test_mrs_dump_is_preserved_and_three_rules_are_added(self) -> None:
        upstream = parse_domain_text("z.example\n+.openai.com\nz.example\n", "mrs-dump")
        merged, added = merge_ai_rules(upstream)
        self.assertEqual(merged[: len(upstream)], upstream)
        self.assertEqual(added, list(AI_SUPPLEMENTS))
        self.assertEqual(
            render_rules(merged, "mihomo").splitlines()[-3:],
            ["+.webpubsub.azure.com", "client-api.arkoselabs.com", "openai-api.arkoselabs.com"],
        )

    def test_existing_upstream_coverage_prevents_redundant_additions(self) -> None:
        upstream = parse_domain_text("+.webpubsub.azure.com\n+.arkoselabs.com\n", "mrs-dump")
        self.assertEqual(merge_ai_rules(upstream), (upstream, []))

    def test_suffix_and_exact_coverage_remain_distinct(self) -> None:
        self.assertTrue(covers(DomainRule("suffix", "webpubsub.azure.com"), [AI_SUPPLEMENTS[0]]))
        self.assertTrue(covers(DomainRule("exact", "client-api.arkoselabs.com"), [AI_SUPPLEMENTS[1]]))
        self.assertFalse(covers(DomainRule("suffix", "client-api.arkoselabs.com"), [AI_SUPPLEMENTS[1]]))


if __name__ == "__main__":
    unittest.main()
