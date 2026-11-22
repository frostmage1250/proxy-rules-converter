from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from convert_mrs import convert_all, discover_rule_sets  # noqa: E402


def find_mihomo() -> str | None:
    return os.environ.get("MIHOMO_BIN") or shutil.which("mihomo")


class MrsConverterTests(unittest.TestCase):
    def test_discovers_only_list_files_in_stable_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            source_dir = Path(temp_name) / "build"
            output_dir = Path(temp_name) / "dist"
            source_dir.mkdir()
            (source_dir / "z.list").write_text("+.z.example\n", encoding="utf-8")
            (source_dir / "a.list").write_text("a.example\n", encoding="utf-8")
            (source_dir / "old.mrs").write_bytes(b"old")
            (source_dir / "notes.txt").write_text("ignored\n", encoding="utf-8")

            pairs = discover_rule_sets(source_dir, output_dir)

        self.assertEqual(
            [
                (rule_set.source.name, rule_set.destination, rule_set.behavior)
                for rule_set in pairs
            ],
            [
                ("a.list", output_dir / "a.mrs", "domain"),
                ("z.list", output_dir / "z.mrs", "domain"),
            ],
        )

    def test_compiles_into_output_dir_and_keeps_geolocation(self) -> None:
        mihomo = find_mihomo()
        if not mihomo:
            self.skipTest("Mihomo executable not available")
        with tempfile.TemporaryDirectory() as temp_name:
            source_dir = Path(temp_name) / "build"
            output_dir = Path(temp_name) / "dist"
            source_dir.mkdir()
            output_dir.mkdir()
            (source_dir / "a.list").write_text("+.a.example\nb.example\n", encoding="utf-8")
            (output_dir / "geolocation-cn.mrs").write_bytes(b"external")
            (output_dir / "stale.mrs").write_bytes(b"stale")

            changed, stale = convert_all(Path(mihomo), source_dir, output_dir, False)

            self.assertEqual(changed, ["a.mrs"])
            self.assertEqual(stale, ["stale.mrs"])
            self.assertEqual(
                sorted(path.name for path in output_dir.iterdir()),
                ["a.mrs", "geolocation-cn.mrs"],
            )


if __name__ == "__main__":
    unittest.main()
