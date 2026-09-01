from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_rules import ConversionError  # noqa: E402
from convert_v2fly_geolocation_cn import convert  # noqa: E402


class V2FlyGeolocationCnConverterTests(unittest.TestCase):
    def test_preserves_v2fly_domain_and_full_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            export = root / "export.txt"
            regex = root / "regex.txt"
            export.write_text(
                "domain:z.example\n"
                "full:only.example\n"
                "domain:a.example:@cn\n"
                "regexp:^x\\.cn$:@cn\n",
                encoding="utf-8",
            )
            regex.write_text("regexp:^x\\.cn$\n", encoding="utf-8")
            result = convert(export, regex)

        self.assertEqual(result, "+.z.example\nonly.example\n+.a.example\n")

    def test_regex_change_stops_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            export = root / "export.txt"
            regex = root / "regex.txt"
            export.write_text("regexp:^new\\.cn$\n", encoding="utf-8")
            regex.write_text("regexp:^old\\.cn$\n", encoding="utf-8")
            with self.assertRaises(ConversionError):
                convert(export, regex)


if __name__ == "__main__":
    unittest.main()
