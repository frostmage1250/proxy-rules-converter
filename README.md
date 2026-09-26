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
not already covered, then recompiles with Mihomo. No AI text provider is
published. `reports/ai.json` records the source and generated file hashes.

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

## V2Fly geolocation-cn

This is the approved exception to the Bett rule-data source. The workflow
builds `geolocation-cn-clean` with V2Fly's official generator. The local
`config/v2fly/geolocation-cn-clean` wrapper also contains the reviewed exact
host `qq.ugcimg.cn`; domain rule sets do not include ports, so this rule
covers the requested `qq.ugcimg.cn:443` connection.

The current three regular-expression rules cannot be represented by domain
MRS and are explicitly pinned in `config/v2fly/geolocation-cn-regex.txt`.
Any change to that reviewed set stops the workflow. MetaCubeX is used only
to compile the MRS format. The Mihomo text list is checked against the
V2Fly export for identical order and count.

## Published files

```text
dist/mihomo/
├─ ai.mrs
├─ claude.yaml
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
