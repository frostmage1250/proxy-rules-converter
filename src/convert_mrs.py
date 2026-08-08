#!/usr/bin/env python3
"""Compile generated Mihomo domain text providers to deterministic MRS files.

This wrapper deliberately delegates the binary format to Mihomo's official
``convert-ruleset`` command. The readable ``.list`` files remain the source of truth.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULE_DIR = ROOT / "dist" / "mihomo"


class MrsConversionError(RuntimeError):
    """Raised when Mihomo cannot compile a rule provider."""


def discover_rule_sets(rule_dir: Path) -> list[tuple[Path, Path]]:
    """Map every Mihomo text provider to its same-named MRS output."""

    return [(source, source.with_suffix(".mrs")) for source in sorted(rule_dir.glob("*.list"))]


def resolve_mihomo(explicit: Path | None) -> Path:
    candidate = str(explicit) if explicit else os.environ.get("MIHOMO_BIN")
    resolved = candidate or shutil.which("mihomo")
    if not resolved:
        raise MrsConversionError(
            "Mihomo executable not found; pass --mihomo, set MIHOMO_BIN, or add mihomo to PATH"
        )
    path = Path(resolved).resolve()
    if not path.is_file():
        raise MrsConversionError(f"Mihomo executable does not exist: {path}")
    return path


def compile_rule_set(mihomo: Path, source: Path, destination: Path) -> None:
    result = subprocess.run(
        [
            str(mihomo),
            "convert-ruleset",
            "domain",
            "text",
            str(source),
            str(destination),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        raise MrsConversionError(
            f"Mihomo failed to compile {source.name}: {details or 'unknown error'}"
        )
    if not destination.is_file() or destination.stat().st_size == 0:
        raise MrsConversionError(f"Mihomo did not create a valid output for {source.name}")


def convert_all(mihomo: Path, rule_dir: Path, check: bool) -> tuple[list[str], list[str]]:
    pairs = discover_rule_sets(rule_dir)
    if not pairs:
        raise MrsConversionError(f"No .list rule providers found in {rule_dir}")

    expected = {destination for _, destination in pairs}
    stale = sorted(path.name for path in rule_dir.glob("*.mrs") if path not in expected)
    changed: list[str] = []

    with tempfile.TemporaryDirectory(prefix="mrs-", dir=rule_dir) as temp_name:
        temp_dir = Path(temp_name)
        for source, destination in pairs:
            candidate = temp_dir / destination.name
            compile_rule_set(mihomo, source, candidate)
            old = destination.read_bytes() if destination.exists() else None
            if old != candidate.read_bytes():
                changed.append(destination.name)
                if not check:
                    os.replace(candidate, destination)

    if not check:
        for name in stale:
            (rule_dir / name).unlink()
    return changed, stale


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", type=Path, help="Path to the official Mihomo executable")
    parser.add_argument("--rule-dir", type=Path, default=DEFAULT_RULE_DIR)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when MRS files differ; do not write them.",
    )
    args = parser.parse_args(argv)

    try:
        mihomo = resolve_mihomo(args.mihomo)
        changed, stale = convert_all(mihomo, args.rule_dir.resolve(), args.check)
        if args.check and (changed or stale):
            print("Generated MRS files are out of date:", file=sys.stderr)
            for name in changed:
                print(f"  changed: {name}", file=sys.stderr)
            for name in stale:
                print(f"  stale: {name}", file=sys.stderr)
            return 1
        verb = "checked" if args.check else "generated"
        print(
            f"MRS files {verb}: {len(discover_rule_sets(args.rule_dir))}; "
            f"changed {len(changed)}, removed {len(stale)} stale files."
        )
        return 0
    except (MrsConversionError, OSError) as exc:
        print(f"MRS conversion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
