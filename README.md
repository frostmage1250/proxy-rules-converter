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

### Mihomo Global replacement

- Replace the old Shadowrocket GFW provider with a Mihomo-only Global provider built
  from Sukka `global`.
- Convert Sukka `DOMAIN` and `DOMAIN-SUFFIX` entries to native Mihomo domain text.
- Replace the six reviewed keywords (`google`, `facebook`, `whatsapp`, `discord`,
  `dropbox`, and `pinterest`) with the complete corresponding MetaCubeX `.list`
  branches, rather than approximate wildcard matching.
- Drop `blogspot`, `sci-hub`, and `browserleaks` completely. This exclusion is also
  applied to the expanded branches, so Blogspot entries from `google.list` cannot be
  reintroduced indirectly.
- Do not generate a Shadowrocket Global or GFW provider.

### Other Shadowrocket providers

- Convert only MetaCubeX non-classical `.list` domain data to native DOMAIN-SET text.
- Keep APNS and all IP rules as external classical RULE-SET resources.
- Do not generate qBittorrent process rules or a Shadowrocket Steam provider.
- Keep `bilibili-direct.list` and `bilibili-pcdn.list` as hand-maintained static
  Shadowrocket DOMAIN-SET files; the converter neither creates nor rewrites them.

## Outputs

```text
dist/
├─ mihomo/
│  ├─ apple-direct.list
│  ├─ apple-direct.mrs
│  ├─ domestic.list
│  ├─ domestic.mrs
│  ├─ global.list
│  ├─ global.mrs
│  ├─ microsoft-cdn.list
│  ├─ microsoft-cdn.mrs
│  ├─ microsoft.list
│  ├─ microsoft.mrs
│  ├─ steam-cn-download.list
│  └─ steam-cn-download.mrs
└─ shadowrocket/
   ├─ apple-direct.domain-set
   ├─ bilibili-direct.list
   ├─ bilibili-pcdn.list
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
   └─ ai.domain-set
```

Each Mihomo provider is published twice: a readable `.list` source with
`format: text`, and a compact `.mrs` binary compiled by Mihomo's official
`convert-ruleset` command. The workflow pins the official Mihomo release and verifies
its SHA-256 digest before conversion.
Shadowrocket files use native DOMAIN-SET syntax. `reports/summary.json` records source
URLs and hashes, counts, ignored rules, deduplication, keyword expansion, and ordering
requirements.

## Run locally

Python 3.11 or newer is sufficient for the text converter; no third-party Python
packages are needed. MRS generation additionally requires the official `mihomo`
executable in `PATH`, through `MIHOMO_BIN`, or with `--mihomo`.

```bash
python -m unittest discover -s tests -v
python src/convert_rules.py
python src/convert_mrs.py
python src/convert_rules.py --check
python src/convert_mrs.py --check
```

The MRS wrapper runs the official command for every `dist/mihomo/*.list` file:

```text
mihomo convert-ruleset domain text input.list output.mrs
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
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/apple-direct.mrs"
    path: ./ruleset/apple-direct.mrs

  microsoft_cdn:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/microsoft-cdn.mrs"
    path: ./ruleset/microsoft-cdn.mrs

  microsoft:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/microsoft.mrs"
    path: ./ruleset/microsoft.mrs

  global:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/global.mrs"
    path: ./ruleset/global.mrs
```

The relevant rule order is:

```yaml
rules:
  - "RULE-SET,apple_direct,Direct"
  - "RULE-SET,microsoft_cdn,Direct"
  - "RULE-SET,microsoft,MESL"
  - "RULE-SET,global,MESL"
```

Keep `microsoft_cdn` immediately before `microsoft`.

## Shadowrocket configuration

```ini
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/apple-direct.domain-set,DIRECT
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/bilibili-direct.list,DIRECT
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/bilibili-pcdn.list,REJECT
```

No Microsoft, Global, or GFW rule from this repository should be added to Shadowrocket.
The two Bilibili files above are static reviewed inputs and are not generated by the
converter.

## Update source decisions

- Upstream URLs: `config/sources.json`
- Reviewed Steam China candidates: `config/steam-cn-download-allowlist.txt`

The Steam allowlist is a classification decision, not an independent domain source.
An entry is emitted only while one of the two permitted game-download sources covers
it and Domestic does not.
