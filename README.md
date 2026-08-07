# Mihomo and Shadowrocket rule converter

This repository generates compact native domain providers for the paired Mihomo and
Shadowrocket configurations. It downloads public upstream data, validates every rule
type, removes duplicates and covered entries, and commits only changed generated files.

## Policy

### Shared Apple direct set

- Combine Sukka `apple_cdn` and the domain portion of `apple_services`.
- Remove semantic overlap and emit one `apple-direct` provider, reducing client rule
  lookups while preserving both sources' domain coverage.
- Ignore the eight process rules and `17.0.0.0/8` from Apple Services.
- Do not use Sukka Apple CN, MetaCubeX Apple@CN, or the full MetaCubeX Apple set.
- Shadowrocket APNS remains an external classical rule and is not generated here.

### Mihomo Microsoft split

- Convert Sukka `microsoft_cdn` to `microsoft-cdn.list` for direct connections.
- Convert the 80 explicit Sukka Microsoft suffixes to `microsoft.list` for proxying.
- Replace only Sukka's three reviewed keywords (`1drv`, `hotmail`, and `microsoft`)
  with the finite matching entries found in MetaCubeX `microsoft.list`.
- The CDN rule must appear before the Microsoft proxy rule because the two providers
  intentionally overlap.
- Do not use MetaCubeX Microsoft@CN.
- Do not generate any Microsoft provider for Shadowrocket.

### Domestic and Steam

- Convert Sukka `domestic` classical text to native domain text for both clients.
- Drop the reviewed nonessential `DOMAIN-WILDCARD,*.qhimgs?.com` entry; any new
  wildcard fails the build pending review.
- Build Steam input only from Sukka `game-download` and MetaCubeX
  `category-game-platforms-download.list`.
- Emit only reviewed Mainland China Steam download endpoints that are not already
  covered by Domestic. International endpoints and other game platforms are excluded.

### Other Shadowrocket providers

- Convert only MetaCubeX non-classical `.list` domain data to native DOMAIN-SET text.
- Keep APNS and all IP rules as external classical RULE-SET resources.
- Do not generate qBittorrent process rules or a Shadowrocket Steam provider.

## Outputs

```text
dist/
├─ mihomo/
│  ├─ apple-direct.list
│  ├─ domestic.list
│  ├─ microsoft-cdn.list
│  ├─ microsoft.list
│  └─ steam-cn-download.list
└─ shadowrocket/
   ├─ apple-direct.domain-set
   ├─ domestic.domain-set
   ├─ private.domain-set
   ├─ telegram.domain-set
   ├─ youtube.domain-set
   ├─ threads.domain-set
   ├─ instagram.domain-set
   ├─ facebook.domain-set
   ├─ twitter.domain-set
   ├─ twitch.domain-set
   ├─ tiktok.domain-set
   ├─ ai.domain-set
   └─ gfw.domain-set
```

Mihomo files use the `.list` filename extension with provider `format: text`.
Shadowrocket files use native DOMAIN-SET syntax. `reports/summary.json` records source
URLs and hashes, counts, ignored rules, deduplication, keyword expansion, and ordering
requirements.

## Run locally

Python 3.11 or newer is sufficient; no third-party packages are needed.

```bash
python -m unittest discover -s tests -v
python src/convert_rules.py
python src/convert_rules.py --check
```

## GitHub Actions schedule

The **Update generated rules** workflow supports manual runs and runs daily at
18:23 UTC, which is 02:23 the following day in Asia/Shanghai. It commits only when
`dist/` or `reports/` actually changes. The repository is independent rather than a
GitHub fork; upstream attribution and licensing are documented in `NOTICE.md`.

## Mihomo configuration

```yaml
rule-providers:
  apple_direct:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: text
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/apple-direct.list"
    path: ./ruleset/apple-direct.list

  microsoft_cdn:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: text
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/microsoft-cdn.list"
    path: ./ruleset/microsoft-cdn.list

  microsoft:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: text
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/microsoft.list"
    path: ./ruleset/microsoft.list
```

The relevant rule order is:

```yaml
rules:
  - "RULE-SET,apple_direct,Direct"
  - "RULE-SET,microsoft_cdn,Direct"
  - "RULE-SET,microsoft,MESL"
```

Keep `microsoft_cdn` immediately before `microsoft`.

## Shadowrocket configuration

```ini
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/apple-direct.domain-set,DIRECT
```

No Microsoft rule from this repository should be added to Shadowrocket.

## Update source decisions

- Upstream URLs: `config/sources.json`
- Reviewed Steam China candidates: `config/steam-cn-download-allowlist.txt`

The Steam allowlist is a classification decision, not an independent domain source.
An entry is emitted only while one of the two permitted game-download sources covers
it and Domestic does not.
