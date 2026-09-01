from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from validate_geolocation_cn import (  # noqa: E402
    ValidationError,
    parse_v2fly_export,
    validate,
)


class GeolocationCnValidationTests(unittest.TestCase):
    def test_parses_attributes_without_losing_regex_colons(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            source = Path(temp_name) / "export.txt"
            source.write_text(
                "domain:example.com:@cn\nregexp:^foo:[0-9]+\\.cn$:@cn\n",
                encoding="utf-8",
            )
            entries = parse_v2fly_export(source)

        self.assertEqual(entries[0].attrs, ("cn",))
        self.assertEqual(entries[1].value, r"^foo:[0-9]+\.cn$")

    def test_validates_exact_meta_projection_and_sentinels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            export = root / "export.txt"
            domain_list = root / "rules.list"
            mrs = root / "rules.mrs"
            expected_regex = root / "regex.txt"
            export.write_text(
                "domain:example.com\nfull:only.example.net\nregexp:^x\\.cn$:@cn\n",
                encoding="utf-8",
            )
            domain_list.write_text(
                "+.example.com\nonly.example.net\n", encoding="utf-8"
            )
            mrs.write_bytes(b"x" * 1024)
            expected_regex.write_text("regexp:^x\\.cn$\n", encoding="utf-8")

            report = validate(
                export,
                domain_list,
                mrs,
                expected_regex,
                minimum_domain_rules=2,
                positive_hosts=("www.example.com", "only.example.net"),
                negative_hosts=("example.org",),
            )

        self.assertEqual(report["mrs_compatible_entries"], 2)

    def test_rejects_forbidden_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            export = root / "export.txt"
            export.write_text("domain:example.com:@ads\n", encoding="utf-8")
            empty = root / "empty"
            empty.write_text("", encoding="utf-8")
            mrs = root / "rules.mrs"
            mrs.write_bytes(b"x" * 1024)

            with self.assertRaisesRegex(ValidationError, "@ads/@!cn"):
                validate(
                    export,
                    empty,
                    mrs,
                    empty,
                    minimum_domain_rules=1,
                    positive_hosts=(),
                    negative_hosts=(),
                )


if __name__ == "__main__":
    unittest.main()
