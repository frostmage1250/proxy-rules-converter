# Generated rule report

- Conversion policy: syntax only; no semantic minimization or sorting.
- Every generated provider preserves source rule order and count.
- Upstream exact duplicates are preserved; unsupported syntax and required normalization fail the build.

## Steam China download

- Canonical allowlist rules: 11.
- Bett coverage validation passed.
- Mihomo output preserves allowlist order and count.

## Bypass Japan

- Reviewed suffix rules: 2.
- Mihomo list and MRS, plus Egern native YAML, use the same two suffixes.

## MCDN block

- Reviewed suffix rules: 4.
- mcdn屏蔽: Mihomo domain MRS and Egern native YAML share the four reviewed suffixes.

## Claude

- Bett Anthropic rules: 8 (primary source).
- Claude site rules: 23.
- Merged classical rules: 23.
- Authentication, telemetry, risk-control keywords, IPv4, IPv6, and AS399358 are retained.
- NTP rules are explicitly excluded.
