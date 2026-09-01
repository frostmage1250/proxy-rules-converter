#!/usr/bin/env python3
"""Convert the self-built Mihomo geolocation-cn list to Shadowrocket DOMAIN-SET."""

from __future__ import annotations

import argparse
from pathlib import Path

from convert_rules import (
    ConversionError,
    ROOT,
    atomic_write,
    parse_domain_text,
    render_rules,
)


DEFAULT_INPUT = ROOT / "dist" / "mihomo" / "geolocation-cn.list"
DEFAULT_OUTPUT = ROOT / "dist" / "shadowrocket" / "geolocation-cn.domain-set"


def convert(source: Path) -> str:
    rules = parse_domain_text(source.read_text(encoding="utf-8"), str(source))
    rendered = render_rules(rules, "shadowrocket")
    if len(rendered.splitlines()) != len(rules):
        raise ConversionError("Shadowrocket conversion changed the rule count")
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the existing DOMAIN-SET differs; do not write it.",
    )
    args = parser.parse_args()

    expected = convert(args.input)
    current = args.output.read_text(encoding="utf-8") if args.output.exists() else None
    if args.check:
        if current != expected:
            raise ConversionError(f"Generated file is stale: {args.output}")
        return 0

    if current != expected:
        atomic_write(args.output, expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
