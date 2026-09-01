from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_geolocation_cn_shadowrocket import convert  # noqa: E402


class GeolocationCnShadowrocketTests(unittest.TestCase):
    def test_converts_mihomo_suffix_and_exact_rules_without_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            source = Path(temp_name) / "geolocation-cn.list"
            source.write_text(
                "+.example.com\nonly.example.net\n", encoding="utf-8"
            )
            result = convert(source)

        self.assertEqual(result, ".example.com\nonly.example.net\n")
        self.assertEqual(len(result.splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
