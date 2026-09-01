# Mihomo and Shadowrocket rule converter

This repository publishes reviewed Bett rules for Mihomo and Shadowrocket, plus the
separately documented V2Fly `geolocation-cn` fallback.

## Conversion policy

- Perform only syntax changes required by the target client.
- Preserve every source rule, its order, and the total rule count.
- Do not semantically minimize, deduplicate, sort, replace, or silently ignore rules.
- Preserve upstream exact duplicates in their original positions without special
  handling or approval.
- Stop the build when an unsupported rule, normalization requirement, source
  disappearance, or target-format collision is detected, then request a maintainer
  decision.

## Sources and outputs

### Bett to Shadowrocket

The converter downloads the configured `appshubcc/bett-rules@meta` geosite, GeoIP,
and ASN lists. It converts:

- Mihomo `+.` domain suffix syntax to Shadowrocket `.` syntax.
- IPv4 CIDRs to `IP-CIDR,<network>`.
- IPv6 CIDRs to `IP-CIDR6,<network>`.

No other rule transformation is permitted. The output line at position N always
corresponds to source rule N.

### Steam China download

`config/steam-cn-download-allowlist.txt` is the canonical reviewed 11-rule source.
Every build verifies that Bett
`category-game-platforms-download@cn.list` still covers all 11 entries, then emits the
allowlist unchanged and in its original order for Mihomo and Shadowrocket.

### V2Fly geolocation-cn

This is the explicitly approved exception to the Bett-only rule-data policy.
The workflow builds `geolocation-cn-clean` with V2Fly's official generator and
MetaCubeX's official converter. The current three regular-expression rules cannot be
represented by domain MRS and are explicitly pinned in
`config/v2fly/geolocation-cn-regex.txt`; any change to that reviewed set stops the
workflow. The generated Mihomo list is converted to Shadowrocket without changing its
rule count or order.

### Static file

`dist/shadowrocket/bilibili-pcdn.list` is the only hand-maintained static provider.
The converter never rewrites it.

## Published files

```text
dist/
├─ mihomo/
│  ├─ geolocation-cn.list
│  ├─ geolocation-cn.mrs
│  ├─ steam-cn-download.list
│  └─ steam-cn-download.mrs
└─ shadowrocket/
   ├─ *.domain-set          # Bett geosite sets, geolocation-cn, Steam-China
   ├─ *-ip.list             # Bett GeoIP sets
   ├─ steam-asn.list        # Bett AS32590 CIDRs
   └─ bilibili-pcdn.list    # static reviewed provider
```

Mihomo MRS files are produced by official converters. `steam-cn-download.mrs` is
compiled with Mihomo's `convert-ruleset` command. `geolocation-cn.mrs` is produced by
MetaCubeX's official converter from the V2Fly build.

## Run locally

Python 3.11 or newer is sufficient for text conversion. MRS generation additionally
requires an official Mihomo executable in `PATH`, through `MIHOMO_BIN`, or with
`--mihomo`.

```bash
python -m unittest discover -s tests -v
python src/convert_rules.py
python src/convert_mrs.py
python src/convert_rules.py --check
python src/convert_mrs.py --check
python src/convert_geolocation_cn_shadowrocket.py --check
```

## Automation

`.github/workflows/update-rules.yml` runs daily and on relevant source changes. It
fetches fresh upstream files, runs all validation, regenerates the providers, checks
determinism, and commits only changed files under `dist/` and `reports/`.

Source mappings are in `config/sources.json`.

