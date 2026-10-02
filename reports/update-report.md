# Generated rule report

- Conversion policy: syntax only; no semantic minimization or sorting.
- Providers preserve source rule order and count, except explicitly merged providers.
- Upstream exact duplicates are preserved; unsupported syntax and required normalization fail the build.

## Steam China download

- Canonical allowlist rules: 11.
- Bett coverage validation passed.
- Mihomo output preserves allowlist order and count.

## pron

- Local rules: 2; category-porn domain rules: 6520.
- Selected websites: 26; selected domain rules: 76.
- Unselected domain rules excluded: 6444.
- Source scope: category-porn only; no external CDN additions; E-Hentai and ExHentai excluded.
- Regex rules excluded: 140.
- Identical duplicates removed: 2.
- Shared domain rules: 76.
- Mihomo list and MRS, plus Egern native YAML, use the same merged non-regex rules.

## MCDN block

- Local rules: 4; accepted AdGuard rules: 33.
- Identical duplicates removed: 2.
- Shared suffix rules: 35.
- The user-excluded *pcdn*.biliapi.net wildcard is omitted.
- mcdn屏蔽: Mihomo domain MRS and Egern native YAML share the merged suffixes.

## Apple merge

- Bett Apple rules retained: 1792.
- Eligible Sukka domains: 15; uncovered scopes added: 2.
- Bett entry order, spelling, and duplicates are preserved.
- Sukka APNs push suffix, generator marker, process rules, and IP rules are excluded.
- Mihomo MRS and Egern native YAML share the apple-merged domain source.

## Claude

- Bett Anthropic rules: 8 (primary source).
- Claude site rules: 23.
- Merged classical rules: 23.
- Authentication, telemetry, risk-control keywords, IPv4, IPv6, and AS399358 are retained.
- NTP rules are explicitly excluded.
