from __future__ import annotations

import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_mrs import discover_rule_sets, materialize_ipcidr_rule_sets  # noqa: E402


class MrsConverterTests(unittest.TestCase):
    def test_discovers_only_list_files_in_stable_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            rule_dir = Path(temp_name)
            (rule_dir / "z.list").write_text("+.z.example\n", encoding="utf-8")
            (rule_dir / "a.list").write_text("a.example\n", encoding="utf-8")
            (rule_dir / "geolocation-cn.list").write_text(
                "+.qq.com\n", encoding="utf-8"
            )
            (rule_dir / "old.mrs").write_bytes(b"old")
            (rule_dir / "notes.txt").write_text("ignored\n", encoding="utf-8")

            pairs = discover_rule_sets(rule_dir)

        self.assertEqual(
            [
                (rule_set.source.name, rule_set.destination.name, rule_set.behavior)
                for rule_set in pairs
            ],
            [("a.list", "a.mrs", "domain"), ("z.list", "z.mrs", "domain")],
        )

    def test_china_ip_sets_use_ipcidr_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            temp_dir = Path(temp_name)
            rule_dir = temp_dir / "rules"
            rule_dir.mkdir()
            sources = temp_dir / "sources.json"
            sources.write_text(
                '{"sukka":{"china_ip":"v4","china_ip_ipv6":"v6"}}',
                encoding="utf-8",
            )

            with patch(
                "convert_mrs.fetch_text",
                side_effect=lambda url: (
                    "1.1.8.0/24\n" if url == "v4" else "2001:250::/30\n"
                ),
            ):
                rule_sets = materialize_ipcidr_rule_sets(
                    temp_dir, rule_dir, sources
                )

        self.assertEqual([item.behavior for item in rule_sets], ["ipcidr", "ipcidr"])
        self.assertEqual(
            [item.destination.name for item in rule_sets],
            ["china-ip.mrs", "china-ip-ipv6.mrs"],
        )


if __name__ == "__main__":
    unittest.main()
