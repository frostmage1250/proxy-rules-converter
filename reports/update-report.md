# Generated rule report

- Conversion policy: syntax only; no semantic minimization or sorting.
- Providers preserve source rule order and count, except explicitly deduplicated MCDN rules.
- Upstream exact duplicates are preserved; unsupported syntax and required normalization fail the build.

## Steam China download

- Canonical allowlist rules: 11.
- Bett coverage validation passed.
- Mihomo output preserves allowlist order and count.

## Bypass Japan

- Reviewed suffix rules: 2.
- Mihomo list and MRS, plus Egern native YAML, use the same two suffixes.

## MCDN block

- Local rules: 4; accepted AdGuard rules: 33.
- Identical duplicates removed: 2.
- Shared suffix rules: 35.
- The user-excluded *pcdn*.biliapi.net wildcard is omitted.
- mcdn屏蔽: Mihomo domain MRS and Egern native YAML share the merged suffixes.

## Claude

- Bett Anthropic rules: 8 (primary source).
- Claude site rules: 23.
- Merged classical rules: 23.
- Authentication, telemetry, risk-control keywords, IPv4, IPv6, and AS399358 are retained.
- NTP rules are explicitly excluded.
