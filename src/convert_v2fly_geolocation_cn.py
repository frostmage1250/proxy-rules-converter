#!/usr/bin/env python3
"""Render the canonical Mihomo geolocation-cn list directly from V2Fly export."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from convert_rules import (
    ConversionError,
    DomainRule,
    atomic_write,
    render_rules,
    validate_canonical_domain,
)
from validate_geolocation_cn import (
    DEFAULT_EXPECTED_REGEX,
    ValidationError,
    parse_v2fly_export,
)


def load_expected_regex(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def convert(export_path: Path, expected_regex_path: Path) -> str:
    entries = parse_v2fly_export(export_path)
    forbidden = [entry for entry in entries if {"ads", "!cn"} & set(entry.attrs)]
    if forbidden:
        raise ConversionError(
            f"V2Fly export retained {len(forbidden)} forbidden @ads/@!cn entries"
        )

    actual_regex = {
        f"regexp:{entry.value}" for entry in entries if entry.rule_type == "regexp"
    }
    expected_regex = load_expected_regex(expected_regex_path)
    if actual_regex != expected_regex:
        raise ConversionError(
            "Reviewed V2Fly regex set changed; "
            f"missing={sorted(expected_regex - actual_regex)}, "
            f"added={sorted(actual_regex - expected_regex)}"
        )

    rules: list[DomainRule] = []
    for entry in entries:
        if entry.rule_type == "regexp":
            continue
        if entry.rule_type == "keyword":
            raise ConversionError(
                "V2Fly export contains a keyword rule that domain MRS cannot preserve: "
                + entry.value
            )
        validate_canonical_domain(entry.value, str(export_path), entry.value)
        kind = "suffix" if entry.rule_type == "domain" else "exact"
        rules.append(DomainRule(kind, entry.value))

    rendered = render_rules(rules, "mihomo")
    if len(rendered.splitlines()) != len(rules):
        raise ConversionError("V2Fly to Mihomo conversion changed the rule count")
    return rendered


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v2fly-export", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-regex", type=Path, default=DEFAULT_EXPECTED_REGEX)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        expected = convert(
            args.v2fly_export.resolve(), args.expected_regex.resolve()
        )
        current = (
            args.output.read_text(encoding="utf-8") if args.output.exists() else None
        )
        if args.check:
            if current != expected:
                raise ConversionError(f"Generated file is stale: {args.output}")
            return 0
        if current != expected:
            atomic_write(args.output, expected)
        return 0
    except (ConversionError, OSError, ValidationError) as exc:
        print(f"V2Fly geolocation-cn conversion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
