# Mihomo and Shadowrocket rule converter

This repository is a ready-to-run external conversion pipeline for the paired
Mihomo and Shadowrocket configurations. It uses public upstream rule data only.

## Implemented policy

### Mihomo

- Existing MetaCubeX MRS providers remain upstream-native and are not regenerated here.
- Sukka `domestic` classical text is converted to Mihomo `behavior: domain`, `format: text`.
- The generated Mihomo files use the `.list` filename extension, while `format` remains
  `text`: Mihomo supports `yaml`, `text`, and `mrs` as format values, not `list`.
- Steam input is limited to Sukka `game-download` and MetaCubeX
  `category-game-platforms-download.list`.
- Only reviewed Mainland China Steam download endpoints are considered.
- Anything already covered by the converted Sukka domestic set is removed from the
  standalone Steam output.
- International Steam download endpoints and other game platforms are not emitted.

### Shadowrocket

- MetaCubeX non-classical `.list` files are converted to native DOMAIN-SET text.
- The converted Sukka domestic data is rendered separately as a DOMAIN-SET.
- APNS and all IP rule sets remain external classical RULE-SET resources.
- No qBittorrent process rule and no standalone Steam rule are generated for Shadowrocket.

## Outputs

```text
dist/
├─ mihomo/
│  ├─ domestic.list
│  └─ steam-cn-download.list
└─ shadowrocket/
   ├─ domestic.domain-set
   ├─ private.domain-set
   ├─ apple-cn.domain-set
   ├─ microsoft-cn.domain-set
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

`reports/summary.json` contains source hashes, input/output counts, deduplication
statistics, Steam domestic-coverage decisions, and missing reviewed candidates.

## Domestic wildcard handling

Sukka currently contains one `DOMAIN-WILDCARD,*.qhimgs?.com` entry. Mihomo domain
providers do not support the routing rule `?` wildcard. This is a nonessential Qihoo
360 image-CDN pattern, so the converter deliberately drops it and records that decision
in the audit report. Any new DOMAIN-WILDCARD causes a hard failure until it is reviewed.

## Run locally

Python 3.11 or newer is sufficient; no third-party packages are needed.

```bash
python -m unittest discover -s tests -v
python src/convert_rules.py
```

To verify that committed outputs are current without writing them:

```bash
python src/convert_rules.py --check
```

## Publish with GitHub Actions

1. Create a public GitHub repository.
2. Upload this directory to its default branch.
3. Open **Actions** and manually run **Update generated rules** once.
4. Ensure repository Actions workflow permissions allow `contents: write`.
5. The workflow then runs every day at 02:23 Asia/Shanghai and commits only real changes.

No personal access token is needed; the workflow uses the repository-scoped
`GITHUB_TOKEN` with only `contents: write` permission.

## Mihomo configuration

The examples use the proposed repository
`frostmage1250/proxy-rules-converter`:

```yaml
rule-providers:
  steam_cn_download:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: text
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/steam-cn-download.list"
    path: ./ruleset/steam-cn-download.list

  domestic:
    type: http
    interval: 86400
    proxy: MESL
    behavior: domain
    format: text
    url: "https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/mihomo/domestic.list"
    path: ./ruleset/domestic.list
```

Keep the Steam rule before domestic:

```yaml
rules:
  - "RULE-SET,steam_cn_download,Direct"
  # ...
  - "RULE-SET,domestic,Direct"
```

If `steam-cn-download.list` becomes empty, remove its provider and rule from Mihomo.

## Shadowrocket configuration

Replace each classical MetaCubeX geosite rule with the corresponding generated
DOMAIN-SET. For example:

```ini
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/private.domain-set,DIRECT
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/youtube.domain-set,媒体
DOMAIN-SET,https://fastly.jsdelivr.net/gh/frostmage1250/proxy-rules-converter@main/dist/shadowrocket/domestic.domain-set,DIRECT
```

Keep APNS, Telegram/private IP, China IPv4, and China IPv6 as RULE-SET entries.

## Update sources or Steam review decisions

- Public source URLs: `config/sources.json`
- Reviewed China Steam download endpoints: `config/steam-cn-download-allowlist.txt`

The Steam allowlist is a classification decision, not an additional data source.
An allowlisted hostname is emitted only when one of the two permitted game-download
sources still covers it and the converted domestic set does not already cover it.

See [NOTICE.md](NOTICE.md) before publishing generated data.
