#!/usr/bin/env python3
"""Compile generated Mihomo text providers to deterministic MRS files.

This wrapper deliberately delegates the binary format to Mihomo's official
``convert-ruleset`` command. The readable ``.list`` files remain the source of truth.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from convert_rules import ConversionError, fetch_text, parse_ipcidr_text


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULE_DIR = ROOT / "dist" / "mihomo"
DEFAULT_SOURCES = ROOT / "config" / "sources.json"
IPCIDR_RULE_SETS = (
    ("china_ip", "china-ip", 4),
    ("china_ip_ipv6", "china-ip-ipv6", 6),
)


class MrsConversionError(RuntimeError):
    """Raised when Mihomo cannot compile a rule provider."""


@dataclass(frozen=True)
class RuleSet:
    source: Path
    destination: Path
    behavior: str


def discover_rule_sets(rule_dir: Path) -> list[RuleSet]:
    """Map every Mihomo text provider to its same-named MRS output."""

    return [
        RuleSet(
            source=source,
            destination=source.with_suffix(".mrs"),
            behavior="domain",
        )
        for source in sorted(rule_dir.glob("*.list"))
    ]


def materialize_ipcidr_rule_sets(
    temp_dir: Path, rule_dir: Path, sources_path: Path
) -> list[RuleSet]:
    """Download validated IP sources into temporary files for direct MRS compilation."""

    config = json.loads(sources_path.read_text(encoding="utf-8"))
    result: list[RuleSet] = []
    for source_key, output_name, ip_version in IPCIDR_RULE_SETS:
        url = config["sukka"][source_key]
        entries, _ = parse_ipcidr_text(fetch_text(url), url, ip_version)
        source = temp_dir / f"{output_name}.source.txt"
        source.write_text("\n".join(entries) + "\n", encoding="utf-8", newline="\n")
        result.append(
            RuleSet(source, rule_dir / f"{output_name}.mrs", "ipcidr")
        )
    return result


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


def compile_rule_set(mihomo: Path, rule_set: RuleSet, destination: Path) -> None:
    result = subprocess.run(
        [
            str(mihomo),
            "convert-ruleset",
            rule_set.behavior,
            "text",
            str(rule_set.source),
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
            f"Mihomo failed to compile {rule_set.source.name}: {details or 'unknown error'}"
        )
    if not destination.is_file() or destination.stat().st_size == 0:
        raise MrsConversionError(
            f"Mihomo did not create a valid output for {rule_set.source.name}"
        )


def convert_all(
    mihomo: Path, rule_dir: Path, check: bool, sources_path: Path = DEFAULT_SOURCES
) -> tuple[list[str], list[str]]:
    domain_rule_sets = discover_rule_sets(rule_dir)
    if not domain_rule_sets:
        raise MrsConversionError(f"No .list rule providers found in {rule_dir}")
    changed: list[str] = []

    with tempfile.TemporaryDirectory(prefix="mrs-", dir=rule_dir) as temp_name:
        temp_dir = Path(temp_name)
        rule_sets = [
            *domain_rule_sets,
            *materialize_ipcidr_rule_sets(temp_dir, rule_dir, sources_path),
        ]
        expected = {rule_set.destination for rule_set in rule_sets}
        stale = sorted(
            path.name for path in rule_dir.glob("*.mrs") if path not in expected
        )
        for rule_set in rule_sets:
            candidate = temp_dir / rule_set.destination.name
            compile_rule_set(mihomo, rule_set, candidate)
            old = (
                rule_set.destination.read_bytes()
                if rule_set.destination.exists()
                else None
            )
            if old != candidate.read_bytes():
                changed.append(rule_set.destination.name)
                if not check:
                    os.replace(candidate, rule_set.destination)

    if not check:
        for name in stale:
            (rule_dir / name).unlink()
    return changed, stale


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", type=Path, help="Path to the official Mihomo executable")
    parser.add_argument("--rule-dir", type=Path, default=DEFAULT_RULE_DIR)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when MRS files differ; do not write them.",
    )
    args = parser.parse_args(argv)

    try:
        mihomo = resolve_mihomo(args.mihomo)
        changed, stale = convert_all(
            mihomo, args.rule_dir.resolve(), args.check, args.sources.resolve()
        )
        if args.check and (changed or stale):
            print("Generated MRS files are out of date:", file=sys.stderr)
            for name in changed:
                print(f"  changed: {name}", file=sys.stderr)
            for name in stale:
                print(f"  stale: {name}", file=sys.stderr)
            return 1
        verb = "checked" if args.check else "generated"
        print(
            f"MRS files {verb}: "
            f"{len(discover_rule_sets(args.rule_dir)) + len(IPCIDR_RULE_SETS)}; "
            f"changed {len(changed)}, removed {len(stale)} stale files."
        )
        return 0
    except (ConversionError, MrsConversionError, OSError) as exc:
        print(f"MRS conversion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
