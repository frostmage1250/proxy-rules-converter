from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_rules import ConversionError  # noqa: E402
from domain_to_classical import domain_text_to_classical, main  # noqa: E402


class DomainToClassicalTests(unittest.TestCase):
    def test_suffix_and_exact_keep_order(self) -> None:
        self.assertEqual(
            domain_text_to_classical(
                "+.example.cn\nwww.example.com\n+.a.example\n", "test"
            ),
            [
                "DOMAIN-SUFFIX,example.cn",
                "DOMAIN,www.example.com",
                "DOMAIN-SUFFIX,a.example",
            ],
        )

    def test_exact_covered_by_same_suffix_is_dropped(self) -> None:
        self.assertEqual(
            domain_text_to_classical(
                "example.cn\n+.example.cn\nwww.example.cn\nother.cn\n", "test"
            ),
            [
                "DOMAIN-SUFFIX,example.cn",
                "DOMAIN,www.example.cn",
                "DOMAIN,other.cn",
            ],
        )

    def test_unsupported_syntax_fails(self) -> None:
        for line in (
            ".example.com",
            "*.example.com",
            "*",
            "+.*.example.com",
            "DOMAIN,example.com",
            "Example.com",
            "example.com.",
            " example.com",
            "+example.com",
        ):
            with self.subTest(line=line), self.assertRaises(ConversionError):
                domain_text_to_classical(line + "\n", "test")

    def test_empty_or_html_input_fails(self) -> None:
        for text in ("", "# only a comment\n", "<html>error</html>\n"):
            with self.subTest(text=text), self.assertRaises(ConversionError):
                domain_text_to_classical(text, "test")

    def test_cli_writes_classical_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            source = Path(temp_name) / "decoded.txt"
            output = Path(temp_name) / "out" / "geolocation-cn.list"
            source.write_text("+.example.cn\nexample.com\n", encoding="utf-8")
            self.assertEqual(main([str(source), str(output)]), 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "DOMAIN-SUFFIX,example.cn\nDOMAIN,example.com\n",
            )
            source.write_text(".example.cn\n", encoding="utf-8")
            self.assertEqual(main([str(source), str(output)]), 2)

    def test_mihomo_mrs_round_trip(self) -> None:
        mihomo = os.environ.get("MIHOMO_BIN") or shutil.which("mihomo")
        if not mihomo:
            self.skipTest("Mihomo executable not available")
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            # Mihomo may reorder entries when decoding; compare as a sorted list.
            (root / "in.list").write_text("+.example.cn\nexample.com\n", encoding="utf-8")
            for args in (
                ["domain", "text", "in.list", "rules.mrs"],
                ["domain", "mrs", "rules.mrs", "decoded.txt"],
            ):
                subprocess.run(
                    [mihomo, "convert-ruleset", *args], cwd=root, check=True,
                    capture_output=True,
                )
            rules = domain_text_to_classical(
                (root / "decoded.txt").read_text(encoding="utf-8"), "decoded"
            )
        self.assertEqual(
            sorted(rules), ["DOMAIN,example.com", "DOMAIN-SUFFIX,example.cn"]
        )


if __name__ == "__main__":
    unittest.main()
