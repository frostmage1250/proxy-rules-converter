#!/usr/bin/env python3
"""Convert Mihomo domain text (e.g. a decoded .mrs) to classical rules.

``+.example.com`` becomes ``DOMAIN-SUFFIX,example.com`` and ``example.com``
becomes ``DOMAIN,example.com``. Any other syntax (``.example.com``,
wildcards, typed rules) fails instead of being approximated.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from convert_rules import (
    ConversionError,
    atomic_write,
    render_classical_text,
    rule_lines,
    validate_canonical_domain,
)


def domain_text_to_classical(text: str, source: str) -> list[str]:
    """Return one classical rule per domain line, preserving order.

    Mihomo stores ``+.x`` as both ``x`` and ``+.x``, so a decoded .mrs lists
    both. ``DOMAIN,x`` is dropped when ``DOMAIN-SUFFIX,x`` exists because the
    suffix rule already matches ``x``; nothing else is removed.
    """

    parsed: list[tuple[str, str]] = []
    for line in rule_lines(text, source):
        if line.startswith("+."):
            parsed.append(("DOMAIN-SUFFIX", validate_canonical_domain(line[2:], source, line)))
        elif line.startswith(".") or any(char in line for char in "*?,+"):
            raise ConversionError(f"Unsupported domain syntax in {source}: {line}")
        else:
            parsed.append(("DOMAIN", validate_canonical_domain(line, source, line)))
    suffixes = {value for kind, value in parsed if kind == "DOMAIN-SUFFIX"}
    return [
        f"{kind},{value}"
        for kind, value in parsed
        if kind == "DOMAIN-SUFFIX" or value not in suffixes
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Mihomo domain text")
    parser.add_argument("output", type=Path, help="Classical rule list to write")
    args = parser.parse_args(argv)
    try:
        text = args.input.read_text(encoding="utf-8-sig")
        rules = domain_text_to_classical(text, str(args.input))
        atomic_write(args.output.resolve(), render_classical_text(rules))
    except (ConversionError, OSError) as exc:
        print(f"Classical conversion failed: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {len(rules)} classical rules to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
