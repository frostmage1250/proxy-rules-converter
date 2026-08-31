# Mihomo and Shadowrocket rule converter

This repository generates compact native domain providers for the paired Mihomo and
Shadowrocket configurations. It downloads public upstream data, validates every rule
type, removes duplicates and covered entries, and commits only changed generated files.

## Policy

### Apple direct and services split

- Combine Sukka `apple_cdn` and `apple_cn`, minimize their internal overlap, and emit
  `apple-direct` for direct connections.
- Build `apple-services` primarily from Sukka `apple_services`: convert its 15 reviewed
  explicit suffixes directly, but replace the broad `apple.com` suffix with the finite
  matching descendants from MetaCubeX `apple.list` plus the exact `apple.com` apex.
- Never restore the broad `+.apple.com` rule, import the full MetaCubeX Apple set, or
  import MetaCubeX Apple@CN. In particular, `apps.apple.com` is not added specially.
- Keep overlap between `apple-direct` and `apple-services`; direct must be evaluated
  first because the providers intentionally use different policies.
- Ignore the eight process rules and `17.0.0.0/8` from Apple Services.
- Emit both Apple providers for Mihomo and Shadowrocket. Shadowrocket APNS remains an
  external classical rule and is not generated here.

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
- Build Steam input only from MetaCubeX
  `category-game-platforms-download@cn.list`.
- Emit its reviewed Steam-only subset as a self-contained direct provider. Domestic
  overlap is retained because this provider must be evaluated before the complete
  MetaCubeX `steam.mrs` proxy provider.
- Required order: `steam-cn-download` (DIRECT), then MetaCubeX `steam` (proxy).
  Other game platforms from the upstream `@cn` category are excluded.

### Global replacement

- Replace the old Shadowrocket GFW provider with a Mihomo-only Global provider built
  from Sukka `global`.
- Convert Sukka `DOMAIN` and `DOMAIN-SUFFIX` entries to native Mihomo domain text.
- Replace the six reviewed keywords (`google`, `facebook`, `whatsapp`, `discord`,
  `dropbox`, and `pinterest`) with the complete corresponding MetaCubeX `.list`
  branches, rather than approximate wildcard matching.
- Drop `blogspot`, `sci-hub`, and `browserleaks` completely. This exclusion is also
  applied to the expanded branches, so Blogspot entries from `google.list` cannot be
  reintroduced indirectly.
- Render the same canonical result as Mihomo domain text and as a Shadowrocket
  DOMAIN-SET; only the client-specific suffix syntax differs.

### Mihomo China IP providers

- Fetch Sukka's `china_ip.txt` and `china_ip_ipv6.txt` directly on every build.
- Validate every entry as a canonical IPv4 or IPv6 network and reject mixed families.
- Download into temporary text files and publish only `.mrs` files compiled with
  Mihomo's official `ipcidr` converter behavior.
- Do not generate corresponding Shadowrocket IP providers.

### Bett-rules Shadowrocket providers

- Fetch the reviewed service and geolocation inputs from the authoritative
  `appshubcc/bett-rules@meta` raw GitHub branch and convert its non-classical
  `geo/geosite/*.list` files to native Shadowrocket DOMAIN-SET text.
- Generate classical Shadowrocket IP rule sets only for Private, China, Google,
  Telegram, Facebook, Twitter, and TikTok, plus Steam ASN AS32590. Apple,
  Microsoft, OpenAI, and Steam GeoIP are intentionally excluded.
- Emit the reviewed 11-domain Steam-China subset as
  `steam-cn-download.domain-set`; it must precede the complete Steam provider.
- Keep APNS external. Do not generate qBittorrent process rules.
- Keep `bilibili-direct.list` and `bilibili-pcdn.list` as hand-maintained static
  Shadowrocket files; the converter neither creates nor rewrites them.

## Outputs

```text
dist/
├─ mihomo/
│  ├─ apple-direct.list
│  ├─ apple-direct.mrs
│  ├─ apple-services.list
│  ├─ apple-services.mrs
│  ├─ china-ip.mrs
│  ├─ china-ip-ipv6.mrs
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
   ├─ *.domain-set        # Bett geosite conversions and Steam-China subset
   ├─ *-ip.list           # Reviewed Bett GeoIP classical rules
   ├─ steam-asn.list      # Bett AS32590 classical rules
   ├─ bilibili-direct.list
   └─ bilibili-pcdn.list
```

Each Mihomo domain provider is published twice: a readable `.list` source with
`format: text`, and a compact `.mrs` binary. The two China IP providers publish only
their compact `.mrs` binaries; their downloaded text is temporary. All binaries are
compiled by Mihomo's official `convert-ruleset` command. On every run, the workflow resolves the latest stable
official Mihomo release through GitHub's `releases/latest` API, selects the compatible
Linux AMD64 build, and verifies the asset's published SHA-256 digest before conversion.
Pre-releases such as Alpha are intentionally excluded.
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

The MRS wrapper runs the official command for every `dist/mihomo/*.list` file,
selecting the behavior assigned to that provider:

```text
mihomo convert-ruleset domain text input.list output.mrs
mihomo convert-ruleset ipcidr text input.list output.mrs
```

## GitHub Actions schedule

The **Update generated rules** workflow supports manual runs and runs daily at
18:23 UTC, which is 02:23 the following day in Asia/Shanghai. It commits only when
`dist/` or `reports/` actually changes. The repository is independent rather than a
GitHub fork; upstream attribution and licensing are documented in `NOTICE.md`.

There is no separate upstream download timer or cache: every workflow run fetches all
configured upstream rule sets immediately before conversion. The scheduled upstream
refresh interval and conversion interval are therefore both one day. Mihomo client
examples below also use `interval: 86400`, so published providers are checked daily.

Dependabot checks only the GitHub Actions development dependencies once per day. A
three-day cooldown keeps newly published versions out of update PRs until they have had
time to stabilize; application rule sources and generated providers are not part of
this dependency-update configuration.

## Mihomo configuration

```yaml
rule-providers:
  china_ip:
    type: http
    interval: 86400
    proxy: MESL
    behavior: ipcidr
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/china-ip.mrs"
    path: ./ruleset/china-ip.mrs

  china_ip_ipv6:
    type: http
    interval: 86400
    proxy: MESL
    behavior: ipcidr
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/china-ip-ipv6.mrs"
    path: ./ruleset/china-ip-ipv6.mrs

  apple_direct:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/apple-direct.mrs"
    path: ./ruleset/apple-direct.mrs

  apple_services:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: mrs
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/apple-services.mrs"
    path: ./ruleset/apple-services.mrs

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
  - "RULE-SET,apple_services,MESL"
  - "RULE-SET,microsoft_cdn,Direct"
  - "RULE-SET,microsoft,MESL"
  - "RULE-SET,global,MESL"
```

Keep `apple_direct` immediately before `apple_services`, and keep `microsoft_cdn`
immediately before `microsoft`.

## Shadowrocket configuration

```ini
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/apple-cn.domain-set,DIRECT
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/apple.domain-set,PROXY
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/google.domain-set,Google
RULE-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/google-ip.list,Google,no-resolve
```

The two Bilibili files are static reviewed inputs and are not generated by the
converter. APNS remains an external rule and must stay first in the client config.

## Update source decisions

- Upstream URLs: `config/sources.json`
- Reviewed Steam China candidates: `config/steam-cn-download-allowlist.txt`

The Steam allowlist is a classification decision, not an independent domain source.
An entry is emitted only while MetaCubeX `category-game-platforms-download@cn`
covers it. Domestic overlap is intentionally retained so the direct subset remains
self-contained ahead of the complete Steam proxy rule.
