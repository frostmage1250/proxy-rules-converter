# Mihomo rule converter

This repository publishes reviewed Steam China download rules, an extended
Bett AI MRS provider, a merged `Claude` classical provider, and a
`geolocation-cn` set built from V2Fly domain data for Mihomo.

## Conversion policy

- Preserve every source rule, its order, and the total rule count.
- Do not semantically minimize, deduplicate, sort, replace, or silently ignore rules.
- Preserve upstream exact duplicates in their original positions.
- Stop the build when an unsupported rule, required normalization, or source
  disappearance is detected.

## Steam China download

`config/steam-cn-download-allowlist.txt` is the canonical reviewed 11-rule source.
Every build verifies that Bett's
`category-game-platforms-download@cn.list` still covers all 11 entries, then emits
the allowlist unchanged and in its original order as a Mihomo text provider.
The official Mihomo converter compiles its MRS file.


## AI

`dist/mihomo/ai.mrs` is built directly from Bett's
`category-ai-!cn.mrs`. Mihomo decodes the upstream MRS to temporary text;
the generator adds `+.webpubsub.azure.com`,
`client-api.arkoselabs.com`, and `openai-api.arkoselabs.com` when they are
not already covered, then recompiles with Mihomo. The validated final MRS is
also decoded to `dist/mihomo/ai.list` for Egern conversion. `reports/ai.json`
records the source and generated file hashes.

## Claude

\`dist/mihomo/claude.yaml\` is a Mihomo classical provider. Bett's
\`anthropic.list\` is the primary source; the typed rules and keyword fallbacks
published by \`https://ip.net.coffee/claude/site.html\` supply missing
authentication, CDN, telemetry, risk-control, customer-support, IPv4, IPv6,
and AS399358 coverage. Bett rules are emitted first, and site rules already
covered by a Bett suffix are not duplicated.

The extractor requires the reviewed complete site rule block and all three
\`datadog\`, \`sentry\`, and \`sift\` keyword fallbacks. Any disappearance or
unsupported syntax stops the build. NTP is explicitly excluded from the
Claude provider.

## MCDN block

The four local suffixes in `config/mcdn-block.list` are merged with
[xianhongtao/AdGuard-AntiPCDN-Rules](https://github.com/xianhongtao/AdGuard-AntiPCDN-Rules/blob/main/adguard.txt).
The user-excluded `||*pcdn*.biliapi.net^$important` wildcard is skipped;
all other supported AdGuard hostname blocks become suffix rules, including
their apex and subdomains. Unsupported syntax fails the build.

MCDN is an explicit exception to duplicate preservation: only identical rules
are removed, keeping their first occurrence and local rules first. Covered
narrower suffixes are retained; no semantic minimization is performed.

The workflow publishes `dist/mihomo/mcdn-block.mrs` (domain behavior) and
`dist/egern/mcdn-block.yaml` (native `domain_suffix_set`), plus the readable
`dist/mihomo/mcdn-block.list`. All three share the same merged suffixes.
The AdGuard source is fetched once per workflow run; generation and the final
deterministic check use that snapshot. The report records its URL, hash,
excluded rules, input counts, removed duplicates, and final rule count.
Final validation decodes the MRS and compares it and Egern YAML against the
merged source. Existing consumer URLs and REJECT routing remain unchanged.

## V2Fly geolocation-cn

This is the approved exception to the Bett rule-data source. The workflow
builds `geolocation-cn-clean` with V2Fly's official generator. The local
`config/v2fly/geolocation-cn-clean` wrapper adds the `ugcimg.cn` suffix
(including the apex and all subdomains) and the exact host
`dypnsapi-dualstack.aliyuncs.com` and `upos-icdn-cqg101.solseed.cn`.
Domain rule sets do not include ports; both additions match exact hosts.

The current three regular-expression rules cannot be represented by domain
MRS and are explicitly pinned in `config/v2fly/geolocation-cn-regex.txt`.
Any change to that reviewed set stops the workflow. MetaCubeX is used only
to compile the MRS format. The Mihomo text list is checked against the
V2Fly export for identical order and count.

## Published files

```text
dist/mihomo/
├─ ai.list
├─ ai.mrs
├─ claude.yaml
├─ mcdn-block.list
├─ mcdn-block.mrs
├─ geolocation-cn.list
├─ geolocation-cn.mrs
├─ steam-cn-download.list
└─ steam-cn-download.mrs
```

`reports/geolocation-cn.json` records the V2Fly source, converter commit,
entry counts, sentinels, and output hashes. `reports/summary.json` and
`reports/update-report.md` cover the Steam allowlist validation.

## Automation

`.github/workflows/update-rules.yml` runs every six hours and on relevant
source changes. It fetches fresh upstream files, runs validation, regenerates
the providers, checks determinism, and commits changed generated files.

## Egern-native rule sets

The same workflow extracts the rule-provider model from the pinned Mihomo script,
converts every referenced provider to one Egern-native YAML file, and publishes
`dist/egern/<provider>.yaml`. It also converts the pinned
`ttyyss2233/Tool/shadowrocket/rules/apns.list` to `dist/egern/apns.yaml`.
No source entry is removed or deduplicated. Egern native YAML stores each rule
type in its own list, so rules of different types are grouped by field; within
each field, original order and duplicates are preserved. A rule set matches
when any entry matches.

`reports/egern-source.json` records the Mihomo, Bett, and APNs commits,
source URLs and hashes, source and output counts, a source-order digest,
a native-field-order digest, and the output file hash for each provider.
Generated geolocation-cn, AI, and Claude sources are read from this workflow's
own Mihomo outputs after validation; Egern conversion uses text sources rather
than decoding MRS binaries. The Egern profile repository consumes this report
and only publishes its profile. Import the current Egern profile to pick up
the one-file references.
