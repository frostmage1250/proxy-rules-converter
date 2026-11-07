# Rule converter

The repository has two publishing branches:

- `main`: custom Mihomo providers under `dist/mihomo/`.
- [`egern`](https://github.com/frostmage1250/proxy-rules-converter/tree/egern): independently reads the latest Mihomo script and publishes all referenced providers as native YAML under `rules/`, plus APNs and Private Relay.

The Egern profile generator independently reads the script again and references the Egern branch. No shared configuration model is transferred. Historical `main/dist/egern/*.yaml` remain frozen compatibility URLs for existing profiles.

## Custom Mihomo providers

- **AI**: official Mihomo decodes Bett `category-ai-!cn.mrs`; three reviewed Azure/Arkose supplement rules are added if uncovered, then the MRS is compiled.
- **Claude**: Bett Anthropic rules first, supplemented by the reviewed site rules and datadog/sentry/sift keyword fallbacks. NTP remains excluded.
- **MCDN**: the four local suffixes in `config/mcdn-block.list` merge with AdGuard-AntiPCDN. The explicitly excluded wildcard is skipped. Only identical duplicates are removed.
- **porn**: `config/pron-sites.json` selects reviewed domain rules from Bett category-porn, excluding regex and E-Hentai/ExHentai. The two suffixes in `config/porn.list` remain first. Only identical duplicates are removed.
- **geolocation-cn**: each build fetches the latest V2Fly source, expands `geolocation-cn` with the official V2Fly generator and excludes entries tagged `@ads`, then MetaCubeX/meta-rules-converter compiles the resulting DAT to domain MRS. No supplemental domains or custom text-list conversion are used.

Ordinary Apple, Podcasts, Steam CN and other service providers belong to the Mihomo script's upstream definitions. Their Egern format conversion belongs exclusively to the Egern branch.

## Main branch workflow

The main workflow fetches sources, generates each custom provider once, validates during generation and commits `dist/` and `reports/`. Unit tests run on source pushes. Egern conversion, repeated native-artifact validation, repeated downloads and post-push file comparisons have been removed from this workflow.

The small `update-egern.yml` workflow also exists on this default branch because GitHub schedules originate here. Its job checks out `egern` and runs that branch's converter; its implementation and rule outputs remain on `egern`.

## Published Mihomo files

```text
dist/mihomo/
  ai.list
  ai.mrs
  claude.yaml
  geolocation-cn.mrs
  mcdn-block.list
  mcdn-block.mrs
  porn.list
  porn.mrs
```
